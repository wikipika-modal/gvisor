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
	"sync"
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

// gatedPageReader holds each read until the test releases the eager loader.
type gatedPageReader struct {
	io.ReaderAt
	gate <-chan struct{}
}

func (r *gatedPageReader) ReadAt(p []byte, off int64) (int, error) {
	<-r.gate
	return r.ReaderAt.ReadAt(p, off)
}

func TestDecommitDuringAsyncLoad(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	fr := allocateSaveTestPages(t, f)
	pwritePage(t, f, fr, 5, 42)
	var metadata, pages bytes.Buffer
	saved := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(stateio.NewIOWriter(&pages, 1<<20, 16, 4), func(err error) { saved <- err })
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SaveTo(context.Background(), &metadata, &SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatal(err)
	}
	apfs.MemoryFilesDone()
	if err := <-saved; err != nil {
		t.Fatal(err)
	}

	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	loaded := make(chan error, 1)
	reader := &gatedPageReader{bytes.NewReader(pages.Bytes()), gate}
	apfl, err := StartAsyncPagesFileLoad(stateio.NewIOReader(reader, 1<<20, 16, 4), func(err error) { loaded <- err }, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored := newSaveTestMemoryFile(t, false)
	if err := restored.LoadFrom(context.Background(), &metadata, &LoadOpts{PagesFile: apfl}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restored.DecRef(fr) })
	apfl.MemoryFilesDone()
	page := memmap.FileRange{fr.Start + 5*hostarch.PageSize, fr.Start + 6*hostarch.PageSize}
	decommitted := make(chan struct{})
	go func() { restored.Decommit(page); close(decommitted) }()
	select {
	case <-decommitted:
		t.Error("Decommit returned before the pending page load")
	case <-time.After(50 * time.Millisecond):
	}
	release.Do(func() { close(gate) })
	if err := <-loaded; err != nil {
		t.Fatal(err)
	}
	<-decommitted
	bs, err := restored.MapInternal(page, hostarch.Read)
	if err != nil {
		t.Fatal(err)
	}
	if got := bs.Head().ToSlice()[17]; got != 0 {
		t.Errorf("decommitted byte: got %d, want 0", got)
	}
}
