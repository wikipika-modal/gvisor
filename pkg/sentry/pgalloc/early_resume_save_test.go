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
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

// heldWriter completes priority writes at once, and other writes only after
// release(). It copies each write's source when completing it, as an external
// server would.
type heldWriter struct {
	stateio.NoRegisterClientFD

	mu        sync.Mutex
	cond      sync.Cond
	released  bool
	pending   []heldWrite
	file      []byte
	priority  int
	finalized bool
}

type heldWrite struct {
	id       int
	off      uint64
	priority bool
	srcs     []unix.Iovec
}

func newHeldWriter() *heldWriter {
	w := &heldWriter{}
	w.cond.L = &w.mu
	return w
}

func (w *heldWriter) release() {
	w.mu.Lock()
	w.released = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

func (w *heldWriter) Close() error          { return nil }
func (w *heldWriter) MaxWriteBytes() uint64 { return uint64(hostarch.PageSize) }
func (w *heldWriter) MaxRanges() int        { return 4 }
func (w *heldWriter) MaxParallel() int      { return 8 }
func (w *heldWriter) Reserve(uint64)        {}

func (w *heldWriter) AddWrite(int, stateio.SourceFile, memmap.FileRange, []byte) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritev(int, uint64, stateio.SourceFile, []memmap.FileRange, []unix.Iovec) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritevAt(id int, off uint64, priority bool, total uint64, _ stateio.SourceFile, _ []memmap.FileRange, srcs []unix.Iovec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if priority {
		w.priority++
	}
	w.pending = append(w.pending, heldWrite{id, off, priority, append([]unix.Iovec(nil), srcs...)})
	w.cond.Broadcast()
}

// Wait returns early while it holds writes, as PositionedWriter allows.
func (w *heldWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		var rest []heldWrite
		for _, hw := range w.pending {
			if !hw.priority && !w.released {
				rest = append(rest, hw)
				continue
			}
			off := hw.off
			for _, iov := range hw.srcs {
				src := stateio.SliceFromIovec(iov)
				if end := off + uint64(len(src)); end > uint64(len(w.file)) {
					w.file = append(w.file, make([]byte, end-uint64(len(w.file)))...)
				}
				copy(w.file[off:], src)
				off += uint64(len(src))
			}
			cs = append(cs, stateio.Completion{ID: hw.id, N: off - hw.off})
			minCompletions--
		}
		w.pending = rest
		if minCompletions <= 0 {
			return cs, nil
		}
		if len(rest) != 0 {
			w.mu.Unlock()
			time.Sleep(time.Millisecond)
			w.mu.Lock()
			return cs, nil
		}
		w.cond.Wait()
	}
}

func (w *heldWriter) Finalize() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.finalized = true
	return nil
}

func TestEarlyResumeSaveWaitsForWrittenPages(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	const pages = 16
	fr := allocateSaveTestPages(t, f)
	for i := 0; i < pages; i++ {
		pwritePage(t, f, fr, i, byte(i+1))
	}
	want := make([]byte, fr.Length())
	f.forEachMappingSlice(fr, func(bs []byte) { copy(want, bs) })

	w := newHeldWriter()
	done := make(chan error, 1)
	apfs, err := StartAsyncPagesFileSave(w, func(err error) { done <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	if err := apfs.EnableEarlyResume(); err != nil {
		t.Fatalf("EnableEarlyResume: %v", err)
	}
	var meta bytes.Buffer
	if err := f.SaveTo(context.Background(), &meta, &SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()
	if !f.IsEarlyResumeSaving() {
		t.Fatalf("IsEarlyResumeSaving: got false after SaveTo")
	}

	page := func(i int) memmap.FileRange {
		start := fr.Start + uint64(i)*uint64(hostarch.PageSize)
		return memmap.FileRange{start, start + uint64(hostarch.PageSize)}
	}
	if _, err := f.MapInternal(page(3), hostarch.Read); err != nil {
		t.Fatalf("MapInternal(Read): %v", err)
	}
	if !f.HasUnsaved(page(12)) {
		t.Fatalf("page 12 saved while writes are held")
	}
	ims, err := f.MapInternal(page(12), hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal(Write): %v", err)
	}
	if f.HasUnsaved(page(12)) {
		t.Fatalf("page 12 unsaved after MapInternal(Write)")
	}
	ims.Head().ToSlice()[17] = 0xff
	f.Decommit(page(13))

	w.release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("saving failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("saving did not finish")
	}
	if f.IsEarlyResumeSaving() {
		t.Errorf("IsEarlyResumeSaving: got true after saving finished")
	}
	if !w.finalized {
		t.Errorf("pages file not finalized")
	}
	if w.priority == 0 {
		t.Errorf("no priority writes")
	}
	if !bytes.Equal(w.file, want) {
		t.Errorf("pages file differs from memory at save time")
	}
}

func TestEarlyResumeRefusedWithoutPositionedWrites(t *testing.T) {
	apfs, err := StartAsyncPagesFileSave(struct{ stateio.AsyncWriter }{newHeldWriter()}, nil)
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	defer apfs.MemoryFilesDone()
	if err := apfs.EnableEarlyResume(); !errors.Is(err, ErrEarlyResumeUnsupported) {
		t.Fatalf("EnableEarlyResume: got %v, want ErrEarlyResumeUnsupported", err)
	}
	if apfs.earlyResume {
		t.Fatalf("early resume enabled after refusal")
	}
}
