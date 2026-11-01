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
	lazy  bool
	bytes atomic.Uint64
}

func (r *lazyReader) Lazy() bool { return r.lazy }

func (r *lazyReader) AddRead(id int, off int64, dstFile stateio.DestinationFile, dstFR memmap.FileRange, dstMap []byte) {
	r.bytes.Add(uint64(len(dstMap)))
	r.AsyncReader.AddRead(id, off, dstFile, dstFR, dstMap)
}

func (r *lazyReader) AddReadv(id int, off int64, total uint64, dstFile stateio.DestinationFile, dstFRs []memmap.FileRange, dstMaps []unix.Iovec) {
	r.bytes.Add(total)
	r.AsyncReader.AddReadv(id, off, total, dstFile, dstFRs, dstMaps)
}

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
// lazily if lazy is true. The returned channel receives the end of async
// loading.
func loadPagesFile(t *testing.T, metadata, pages *bytes.Buffer, fr memmap.FileRange, lazy bool) (*MemoryFile, *lazyReader, chan error) {
	t.Helper()
	r := &lazyReader{AsyncReader: stateio.NewIOReader(bytes.NewReader(pages.Bytes()), 1<<20, 16, 4), lazy: lazy}
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
// (byte 17 of each is 1), a hole, and one more page (byte 17 is 2).
const lazyTestBigPages = lazyMinBytes / hostarch.PageSize

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
	// The small range is loaded in the background; the large one only where
	// awaited.
	deadline := time.Now().Add(10 * time.Second)
	for r.bytes.Load() < 2*hostarch.PageSize && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := r.bytes.Load(); got != 2*hostarch.PageSize {
		t.Errorf("read %d bytes, want %d (one awaited page and the small range)", got, 2*hostarch.PageSize)
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
