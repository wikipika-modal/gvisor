// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !pagesize_64k

package pgalloc

import (
	"bytes"
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func newSaveTestMemoryFile(t *testing.T, diskBacked bool) *MemoryFile {
	t.Helper()
	var file *os.File
	if diskBacked {
		var err error
		if file, err = os.CreateTemp(t.TempDir(), "pgalloc-save-test"); err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
	} else {
		fd, err := memutil.CreateMemFD("pgalloc-save-test", 0)
		if err != nil {
			t.Fatalf("CreateMemFD: %v", err)
		}
		file = os.NewFile(uintptr(fd), "pgalloc-save-test")
	}
	f, err := NewMemoryFile(file, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionDisabled,
		DisableMemoryAccounting: true,
		DiskBackedFile:          diskBacked,
	})
	if err != nil {
		file.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(f.Destroy)
	return f
}

func allocateSaveTestPages(t *testing.T, f *MemoryFile) memmap.FileRange {
	t.Helper()
	fr, err := f.Allocate(16*uint64(hostarch.PageSize), AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	return fr
}

func pwritePage(t *testing.T, f *MemoryFile, fr memmap.FileRange, page int, b byte) {
	t.Helper()
	buf := make([]byte, hostarch.PageSize)
	buf[17] = b
	if _, err := unix.Pwrite(f.FD(), buf, int64(fr.Start)+int64(page*int(hostarch.PageSize))); err != nil {
		t.Fatalf("Pwrite page %d: %v", page, err)
	}
}

func TestHostFileDataSeeker(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 2, 1)
	pwritePage(t, f, fr, 3, 1)
	pwritePage(t, f, fr, 9, 1)
	pwritePage(t, f, fr, 12, 0)
	page := func(n uint64) uint64 { return fr.Start + n*uint64(hostarch.PageSize) }
	d := f.newHostFileDataSeeker()
	for _, call := range []struct {
		off  uint64
		want memmap.FileRange
	}{
		{off: page(0), want: memmap.FileRange{page(2), page(4)}},
		{off: page(3), want: memmap.FileRange{page(3), page(4)}},
		{off: page(4), want: memmap.FileRange{page(9), page(10)}},
		{off: page(10), want: memmap.FileRange{page(12), page(13)}},
		{off: page(13), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
		{off: page(15), want: memmap.FileRange{f.TotalSize(), f.TotalSize()}},
	} {
		got, err := d.dataAtOrAfter(call.off)
		if err != nil || got != call.want {
			t.Errorf("dataAtOrAfter(%#x): got (%v, %v), want (%v, nil)", call.off, got, err, call.want)
		}
	}
}

func TestSaveToPreservesContents(t *testing.T) {
	for _, tc := range []struct {
		name          string
		diskBacked    bool
		exclude       bool
		wantCommitted uint64
	}{
		{name: "memfd", wantCommitted: 2 * uint64(hostarch.PageSize)},
		{name: "memfd excluding committed zero pages", exclude: true, wantCommitted: uint64(hostarch.PageSize)},
		{name: "disk-backed", diskBacked: true, wantCommitted: 2 * uint64(hostarch.PageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSaveTestMemoryFile(t, tc.diskBacked)
			fr := allocateSaveTestPages(t, f)
			pwritePage(t, f, fr, 2, 1)
			pwritePage(t, f, fr, 13, 2)
			if err := f.SaveTo(context.Background(), io.Discard, &SaveOpts{}); err != nil {
				t.Fatalf("first SaveTo: %v", err)
			}
			pwritePage(t, f, fr, 9, 0)
			pwritePage(t, f, fr, 13, 0)
			want := make([]byte, fr.Length())
			want[2*hostarch.PageSize+17] = 1

			var checkpoint bytes.Buffer
			if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: tc.exclude}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}
			if got := f.knownCommittedBytes; got != tc.wantCommitted {
				t.Errorf("knownCommittedBytes: got %d, want %d", got, tc.wantCommitted)
			}

			restored := newSaveTestMemoryFile(t, tc.diskBacked)
			if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			t.Cleanup(func() { restored.DecRef(fr) })
			restored.forEachMappingSlice(fr, func(bs []byte) {
				if !bytes.Equal(bs, want) {
					t.Error("restored contents differ from saved contents")
				}
			})
		})
	}
}

type lazyReader struct {
	stateio.AsyncReader
	lazy      bool
	prefetch  []memmap.FileRange
	bytes     atomic.Uint64
	last      uint64
	readahead atomic.Uint64
}

func (r *lazyReader) Lazy() bool { return r.lazy }

func (r *lazyReader) Prefetch() []memmap.FileRange { return r.prefetch }

func (r *lazyReader) AddRead(id int, off int64, dstFile stateio.DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	r.last = uint64(len(dstMap))
	r.bytes.Add(r.last)
	r.AsyncReader.AddRead(id, off, dstFile, dstFR, dstMap)
}

func (r *lazyReader) AddReadv(id int, off int64, total uint64, dstFile stateio.DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	r.last = total
	r.bytes.Add(total)
	r.AsyncReader.AddReadv(id, off, total, dstFile, dstFRs, dstMaps)
}

func (r *lazyReader) MarkLastReadReadahead() { r.readahead.Add(r.last) }

// saveToPagesFile saves f with its pages in a separate pages file.
func saveToPagesFile(t *testing.T, f *MemoryFile, exclude bool) (metadata, pages *bytes.Buffer) {
	t.Helper()
	metadata, pages = new(bytes.Buffer), new(bytes.Buffer)
	saved := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(pages, 1<<20, 16, 4), func(err error) { saved <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	if err := f.SaveTo(context.Background(), metadata, &SaveOpts{PagesFile: apfs, ExcludeCommittedZeroPages: exclude}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()
	if err := <-saved; err != nil {
		t.Fatalf("async page save: %v", err)
	}
	return metadata, pages
}

// loadPagesFile restores a MemoryFile saved by saveToPagesFile, loading
// lazily if lazy is true, with the reader suggesting prefetch. The returned
// channel receives the end of async loading.
func loadPagesFile(t *testing.T, metadata, pages *bytes.Buffer, fr memmap.FileRange, lazy bool, prefetch ...memmap.FileRange) (*MemoryFile, *lazyReader, chan error) {
	t.Helper()
	r := &lazyReader{AsyncReader: stateio.NewIOReader(bytes.NewReader(pages.Bytes()), 1<<20, 16, 4), lazy: lazy, prefetch: prefetch}
	loaded := make(chan error, 1)
	apfl, err := StartAsyncPagesFileLoad(r, func(err error) { loaded <- err }, nil)
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	f := newSaveTestMemoryFile(t, false)
	if err := f.LoadFrom(context.Background(), metadata, &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()
	t.Cleanup(func() { f.DecRef(fr) })
	return f, r, loaded
}

// lazyTestPages is one contiguous range of lazyTestBigPages non-zero pages
// (byte 17 of each is 1), four lazyMinBytes windows long, a hole, and one more
// page (byte 17 is 2).
const lazyTestBigPages = 4 * lazyMinBytes / hostarch.PageSize

func newLazyTestMemoryFile(t *testing.T) (*MemoryFile, memmap.FileRange, []byte) {
	t.Helper()
	f := newSaveTestMemoryFile(t, false)
	fr, err := f.Allocate((lazyTestBigPages+2)*hostarch.PageSize, AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	want := make([]byte, fr.Length())
	for i := uint64(0); i < lazyTestBigPages; i++ {
		want[i*hostarch.PageSize+17] = 1
	}
	want[(lazyTestBigPages+1)*hostarch.PageSize+17] = 2
	if _, err := unix.Pwrite(f.FD(), want[:lazyTestBigPages*hostarch.PageSize], int64(fr.Start)); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	pwritePage(t, f, fr, lazyTestBigPages+1, 2)
	return f, fr, want
}

func testPage(fr memmap.FileRange, i uint64) memmap.FileRange {
	start := fr.Start + i*hostarch.PageSize
	return memmap.FileRange{start, start + hostarch.PageSize}
}

func TestLazyLoadReadsOnlyAwaitedPages(t *testing.T) {
	f, fr, want := newLazyTestMemoryFile(t)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, loaded := loadPagesFile(t, metadata, pages, fr, true)

	bs, err := restored.MapInternal(testPage(fr, 5), hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := bs.Head().ToSlice()[17]; got != 1 {
		t.Errorf("page 5: got %d, want 1", got)
	}
	// The small range is loaded in the background; the large one only in the
	// window around the awaited page.
	if got, want := waitForReads(r, lazyMinBytes+hostarch.PageSize), uint64(lazyMinBytes+hostarch.PageSize); got != want {
		t.Errorf("read %d bytes, want %d (the awaited page's window and the small range)", got, want)
	}
	if !restored.IsAsyncLoading() {
		t.Fatal("the large range was loaded without being awaited")
	}

	if err := restored.AwaitLoadAll(); err != nil {
		t.Fatalf("AwaitLoadAll: %v", err)
	}
	if err := <-loaded; err != nil {
		t.Fatalf("async page load: %v", err)
	}
	if got, total := r.bytes.Load(), uint64((lazyTestBigPages+1)*hostarch.PageSize); got != total {
		t.Errorf("read %d bytes in total, want %d", got, total)
	}
	restored.forEachMappingSlice(fr, func(bs []byte) {
		if !bytes.Equal(bs, want) {
			t.Error("restored contents differ from saved contents")
		}
	})
}

// waitForReads waits until r has read at least n bytes, then a little longer
// for any reads beyond n, and returns how many bytes r has read.
func waitForReads(r *lazyReader, n uint64) uint64 {
	deadline := time.Now().Add(10 * time.Second)
	for r.bytes.Load() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return r.bytes.Load()
}

func TestLazyLoadPrefetchesSuggestedRanges(t *testing.T) {
	f, fr, want := newLazyTestMemoryFile(t)
	metadata, pages := saveToPagesFile(t, f, false)
	// The large range comes first in the pages file. Suggest pages 10 and 11
	// of it, and part of page 12.
	suggested := memmap.FileRange{10 * hostarch.PageSize, 12*hostarch.PageSize + 1}
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true, suggested)

	// Pages 10 to 12 and the small range are loaded without being awaited.
	const prefetched = 4 * hostarch.PageSize
	if got := waitForReads(r, prefetched); got != prefetched {
		t.Errorf("read %d bytes, want %d (three suggested pages and the small range)", got, prefetched)
	}
	if !restored.IsAsyncLoading() {
		t.Fatal("the large range was loaded without being awaited")
	}
	pfr := memmap.FileRange{testPage(fr, 10).Start, testPage(fr, 12).End}
	if _, err := restored.MapInternal(pfr, hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	restored.forEachMappingSlice(pfr, func(bs []byte) {
		if !bytes.Equal(bs, want[10*hostarch.PageSize:13*hostarch.PageSize]) {
			t.Error("prefetched contents differ from saved contents")
		}
	})
	if got := r.bytes.Load(); got != prefetched {
		t.Errorf("awaiting prefetched pages read %d more bytes", got-prefetched)
	}
}

// newLazyWindowsMemoryFile returns a MemoryFile with windows lazyMinBytes
// windows of non-zero pages.
func newLazyWindowsMemoryFile(t *testing.T, windows uint64) (*MemoryFile, memmap.FileRange, []byte) {
	t.Helper()
	f := newSaveTestMemoryFile(t, false)
	fr, err := f.Allocate(windows*lazyMinBytes, AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	if fr.Start%lazyMinBytes != 0 {
		t.Skipf("allocated %v, not aligned to %d", fr, lazyMinBytes)
	}
	want := make([]byte, fr.Length())
	for i := uint64(0); i < fr.Length()/hostarch.PageSize; i++ {
		want[i*hostarch.PageSize+17] = byte(i%251 + 1)
	}
	if _, err := unix.Pwrite(f.FD(), want, int64(fr.Start)); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	return f, fr, want
}

func lazyWindow(fr memmap.FileRange, i uint64) memmap.FileRange {
	start := fr.Start + i*lazyMinBytes
	return memmap.FileRange{start, start + lazyMinBytes}
}

func checkLoaded(t *testing.T, f *MemoryFile, fr memmap.FileRange, want []byte) {
	t.Helper()
	if err := f.AwaitLoadAll(); err != nil {
		t.Fatalf("AwaitLoadAll: %v", err)
	}
	f.forEachMappingSlice(fr, func(bs []byte) {
		if !bytes.Equal(bs, want) {
			t.Error("restored contents differ from saved contents")
		}
	})
}

// neverEager keeps lazy loading from turning eager for the rest of the test.
func neverEager(t *testing.T) {
	old := lazyEagerPercent
	lazyEagerPercent = 101
	t.Cleanup(func() { lazyEagerPercent = old })
}

func TestLazyLoadReadsAheadOfAdjacentAwaits(t *testing.T) {
	neverEager(t)
	for _, reverse := range []bool{false, true} {
		f, fr, want := newLazyWindowsMemoryFile(t, 4)
		metadata, pages := saveToPagesFile(t, f, false)
		restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
		first, second := lazyWindow(fr, 0), lazyWindow(fr, 1)
		if reverse {
			first, second = lazyWindow(fr, 3), lazyWindow(fr, 2)
		}
		for _, w := range []memmap.FileRange{first, second} {
			if _, err := restored.MapInternal(w, hostarch.Read); err != nil {
				t.Fatalf("MapInternal: %v", err)
			}
		}
		// The window beyond the second one is loaded without being awaited, as
		// readahead.
		if got := waitForReads(r, 3*lazyMinBytes); got != 3*lazyMinBytes {
			t.Errorf("reverse=%v: read %d bytes, want %d", reverse, got, 3*lazyMinBytes)
		}
		if got := r.readahead.Load(); got != lazyReadaheadMinBytes {
			t.Errorf("reverse=%v: read %d bytes as readahead, want %d", reverse, got, lazyReadaheadMinBytes)
		}
		checkLoaded(t, restored, fr, want)
	}
}

func TestLazyLoadReadsAheadOfAwaitsAfterLoadedWindows(t *testing.T) {
	neverEager(t)
	f, fr, want := newLazyWindowsMemoryFile(t, 4)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	hugePage := func(i uint64) memmap.FileRange {
		w := lazyWindow(fr, i)
		return memmap.FileRange{w.Start, w.Start + hostarch.HugePageSize}
	}
	if _, err := restored.MapInternal(hugePage(0), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	// The rest of window 0 is loaded before anything in it is awaited, so the
	// next await is the first in window 1, which continues window 0. Window 2
	// is read ahead beyond the rest of window 1.
	waitForReads(r, lazyMinBytes)
	if _, err := restored.MapInternal(hugePage(1), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := waitForReads(r, 3*lazyMinBytes); got != 3*lazyMinBytes {
		t.Errorf("read %d bytes, want %d", got, 3*lazyMinBytes)
	}
	checkLoaded(t, restored, fr, want)
}

func TestLazyLoadReadsWindowAroundSmallAwaits(t *testing.T) {
	f, fr, want := newLazyWindowsMemoryFile(t, 4)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	page := testPage(lazyWindow(fr, 1), 5)
	if _, err := restored.MapInternal(page, hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	// The rest of the awaited page's window is loaded, as a fault would load
	// it, but not the other windows.
	if got := waitForReads(r, lazyMinBytes); got != lazyMinBytes {
		t.Errorf("read %d bytes, want %d", got, uint64(lazyMinBytes))
	}
	checkLoaded(t, restored, fr, want)
}

func TestLazyLoadTurnsEagerAfterAwaitingInHalfTheWindows(t *testing.T) {
	f, fr, want := newLazyWindowsMemoryFile(t, 4)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	if _, err := restored.MapInternal(testPage(lazyWindow(fr, 0), 5), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := waitForReads(r, lazyMinBytes); got != lazyMinBytes {
		t.Errorf("read %d bytes after awaiting in a quarter of the windows, want %d", got, uint64(lazyMinBytes))
	}
	if !restored.IsLazyLoading() {
		t.Error("not loading lazily after awaiting in a quarter of the windows")
	}
	// Windows 0 and 2 aren't adjacent, so this doesn't read ahead.
	if _, err := restored.MapInternal(testPage(lazyWindow(fr, 2), 5), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if restored.IsLazyLoading() {
		t.Error("still loading lazily after awaiting in half of the windows")
	}
	if got := waitForReads(r, 4*lazyMinBytes); got != 4*lazyMinBytes {
		t.Errorf("read %d bytes after awaiting in half of the windows, want %d", got, 4*lazyMinBytes)
	}
	checkLoaded(t, restored, fr, want)
}

func TestLazyLoadCountsOnlyLazyPagesInTouchedWindows(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr, err := f.Allocate(4*lazyMinBytes, AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	if fr.Start%lazyMinBytes != 0 {
		t.Skipf("allocated %v, not aligned to %d", fr, lazyMinBytes)
	}
	// Two lazy ranges, each starting a page before the end of a window, with
	// zero pages around them.
	want := make([]byte, fr.Length())
	for _, start := range []uint64{lazyMinBytes - hostarch.PageSize, 3*lazyMinBytes - hostarch.PageSize} {
		for off := start; off < start+lazyMinBytes; off += hostarch.PageSize {
			want[off+17] = 1
		}
	}
	if _, err := unix.Pwrite(f.FD(), want, int64(fr.Start)); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	metadata, pages := saveToPagesFile(t, f, true)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	// Window 0 holds only the first page of the first range.
	if _, err := restored.MapInternal(testPage(fr, lazyMinBytes/hostarch.PageSize-1), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := waitForReads(r, hostarch.PageSize); got != hostarch.PageSize {
		t.Errorf("read %d bytes, want %d", got, hostarch.PageSize)
	}
	checkLoaded(t, restored, fr, want)
}

func TestLazyLoadReadaheadDoesNotTurnEager(t *testing.T) {
	f, fr, want := newLazyWindowsMemoryFile(t, 8)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	for _, i := range []uint64{0, 1} {
		if _, err := restored.MapInternal(lazyWindow(fr, i), hostarch.Read); err != nil {
			t.Fatalf("MapInternal: %v", err)
		}
	}
	waitForReads(r, 3*lazyMinBytes)
	// Window 2 was read ahead, so this reads windows 3 and 4 ahead. Pages have
	// been awaited only in windows 0 and 1.
	if _, err := restored.MapInternal(testPage(lazyWindow(fr, 2), 5), hostarch.Read); err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := waitForReads(r, 5*lazyMinBytes); got != 5*lazyMinBytes {
		t.Errorf("read %d bytes, want %d", got, 5*lazyMinBytes)
	}
	checkLoaded(t, restored, fr, want)
}

// gatedReaderAt blocks reads at the offsets in gates until their channels are
// closed, sending each offset to started first.
type gatedReaderAt struct {
	io.ReaderAt
	gates   map[int64]chan struct{}
	started chan int64
}

func (r *gatedReaderAt) ReadAt(dst []byte, off int64) (int, error) {
	if gate, ok := r.gates[off]; ok {
		r.started <- off
		<-gate
	}
	return r.ReaderAt.ReadAt(dst, off)
}

// promoteReader sends the offsets of the reads it is asked to promote to
// promoted.
type promoteReader struct {
	stateio.AsyncReader
	offs     map[int]int64
	promoted chan int64
}

func (r *promoteReader) AddRead(id int, off int64, dstFile stateio.DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	r.offs[id] = off
	r.AsyncReader.AddRead(id, off, dstFile, dstFR, dstMap)
}

func (r *promoteReader) AddReadv(id int, off int64, total uint64, dstFile stateio.DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	r.offs[id] = off
	r.AsyncReader.AddReadv(id, off, total, dstFile, dstFRs, dstMaps)
}

func (r *promoteReader) PromoteRead(id int) { r.promoted <- r.offs[id] }

func TestLoadPromotesAwaitedBackgroundReads(t *testing.T) {
	f, fr, want := newLazyWindowsMemoryFile(t, 1)
	metadata, pages := saveToPagesFile(t, f, false)
	// The pages file holds fr's pages in order, read 1 MiB at a time.
	const awaited, other = 8 << 20, 16 << 20
	src := &gatedReaderAt{
		ReaderAt: bytes.NewReader(pages.Bytes()),
		gates:    map[int64]chan struct{}{awaited: make(chan struct{}), other: make(chan struct{})},
		started:  make(chan int64, 2),
	}
	r := &promoteReader{
		AsyncReader: stateio.NewIOReader(src, 1<<20, 16, 4),
		offs:        make(map[int]int64),
		promoted:    make(chan int64, 4),
	}
	apfl, err := StartAsyncPagesFileLoad(r, nil, nil)
	if err != nil {
		t.Fatalf("StartAsyncPagesFileLoad: %v", err)
	}
	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), metadata, &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	apfl.MemoryFilesDone()
	t.Cleanup(func() { restored.DecRef(fr) })
	<-src.started
	<-src.started

	mapped := make(chan error, 1)
	go func() {
		_, err := restored.MapInternal(testPage(fr, awaited/hostarch.PageSize+1), hostarch.Read)
		mapped <- err
	}()
	for {
		apfl.mu.Lock()
		waiters := apfl.numWaiters
		apfl.mu.Unlock()
		if waiters != 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// The loader sees the waiter once another read completes.
	close(src.gates[other])
	select {
	case off := <-r.promoted:
		if off != awaited {
			t.Errorf("promoted the read at %d, want %d", off, awaited)
		}
	case <-time.After(10 * time.Second):
		t.Error("the awaited background read wasn't promoted")
	}
	close(src.gates[awaited])
	if err := <-mapped; err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	checkLoaded(t, restored, fr, want)
}

func TestDecommitDuringLazyLoad(t *testing.T) {
	f, fr, want := newLazyWindowsMemoryFile(t, 1)
	metadata, pages := saveToPagesFile(t, f, false)
	restored, r, _ := loadPagesFile(t, metadata, pages, fr, true)
	page := testPage(fr, 5)
	restored.Decommit(page)
	if got := waitForReads(r, hostarch.PageSize); got != hostarch.PageSize {
		t.Errorf("read %d bytes, want only the decommitted page", got)
	}
	bs, err := restored.MapInternal(page, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if got := bs.Head().ToSlice()[17]; got != 0 {
		t.Errorf("decommitted page: got %d, want 0", got)
	}
	clear(want[5*hostarch.PageSize : 6*hostarch.PageSize])
	checkLoaded(t, restored, fr, want)
}

func TestSaveAfterLazyLoad(t *testing.T) {
	for _, exclude := range []bool{false, true} {
		f, fr, want := newLazyTestMemoryFile(t)
		metadata, pages := saveToPagesFile(t, f, false)
		restored, _, loaded := loadPagesFile(t, metadata, pages, fr, true)
		if _, err := restored.MapInternal(testPage(fr, 5), hostarch.Read); err != nil {
			t.Fatalf("MapInternal: %v", err)
		}

		// Saving loads the rest of the large range.
		metadata, pages = saveToPagesFile(t, restored, exclude)
		if err := <-loaded; err != nil {
			t.Fatalf("async page load: %v", err)
		}
		again, _, loaded := loadPagesFile(t, metadata, pages, fr, false)
		if err := <-loaded; err != nil {
			t.Fatalf("async page load: %v", err)
		}
		again.forEachMappingSlice(fr, func(bs []byte) {
			if !bytes.Equal(bs, want) {
				t.Errorf("exclude=%v: contents saved after a lazy load differ", exclude)
			}
		})
	}
}

func TestSaveToExcludesZeroPagesScannedInParallel(t *testing.T) {
	const pages = 4 * zeroPageScanMinPages
	f := newSaveTestMemoryFile(t, false)
	fr, err := f.Allocate(pages*hostarch.PageSize, AllocOpts{Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	t.Cleanup(func() { f.DecRef(fr) })
	want := make([]byte, fr.Length())
	for i := uint64(0); i < pages; i += 3 {
		want[i*hostarch.PageSize+17] = byte(i%255 + 1)
	}
	if _, err := unix.Pwrite(f.FD(), want, int64(fr.Start)); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}

	var checkpoint bytes.Buffer
	if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: true}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	if got, want := f.knownCommittedBytes, uint64((pages+2)/3*hostarch.PageSize); got != want {
		t.Errorf("knownCommittedBytes: got %d, want %d", got, want)
	}

	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	t.Cleanup(func() { restored.DecRef(fr) })
	var got []byte
	restored.forEachMappingSlice(fr, func(bs []byte) { got = append(got, bs...) })
	if !bytes.Equal(got, want) {
		t.Error("restored contents differ from saved contents")
	}
}

func TestSaveToTrustsPrescannedNonZeroPages(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 1, 1)
	pwritePage(t, f, fr, 2, 2)
	pwritePage(t, f, fr, 4, 0)
	prescan := f.PrescanZeroPages(true)
	// Page 2 became zero and page 4 non-zero since prescanning.
	pwritePage(t, f, fr, 2, 0)
	pwritePage(t, f, fr, 4, 4)
	want := make([]byte, fr.Length())
	want[1*hostarch.PageSize+17] = 1
	want[4*hostarch.PageSize+17] = 4

	var checkpoint bytes.Buffer
	if err := f.SaveTo(context.Background(), &checkpoint, &SaveOpts{ExcludeCommittedZeroPages: true, Prescan: prescan}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	// Page 2 is saved since prescanning found it non-zero; page 4 since
	// SaveTo checked it.
	if got, want := f.knownCommittedBytes, 3*uint64(hostarch.PageSize); got != want {
		t.Errorf("knownCommittedBytes: got %d, want %d", got, want)
	}

	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), &checkpoint, &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	t.Cleanup(func() { restored.DecRef(fr) })
	var got []byte
	restored.forEachMappingSlice(fr, func(bs []byte) { got = append(got, bs...) })
	if !bytes.Equal(got, want) {
		t.Error("restored contents differ from contents at SaveTo")
	}
}
