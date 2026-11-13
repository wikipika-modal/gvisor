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
// release() or, if holds is true, when a repeat of them arrives. It copies each
// write's source when completing it, as an external server would.
type heldWriter struct {
	stateio.NoRegisterClientFD

	mu        sync.Mutex
	cond      sync.Cond
	holds     bool
	released  bool
	pending   []heldWrite
	file      []byte
	priority  int
	repeats   int
	finalized bool
}

type heldWrite struct {
	id    int
	off   uint64
	flags stateio.WriteFlags
	srcs  []unix.Iovec
}

func (hw *heldWrite) end() uint64 {
	end := hw.off
	for _, iov := range hw.srcs {
		end += iov.Len
	}
	return end
}

func newHeldWriter(holds bool) *heldWriter {
	w := &heldWriter{holds: holds}
	w.cond.L = &w.mu
	return w
}

func (w *heldWriter) release() {
	w.mu.Lock()
	w.released = true
	w.mu.Unlock()
	w.cond.Broadcast()
}

// holding returns true if a write at off is held.
func (w *heldWriter) holding(off uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, hw := range w.pending {
		if hw.off == off {
			return true
		}
	}
	return false
}

func (w *heldWriter) Close() error          { return nil }
func (w *heldWriter) MaxWriteBytes() uint64 { return uint64(hostarch.PageSize) }
func (w *heldWriter) MaxRanges() int        { return 4 }
func (w *heldWriter) MaxParallel() int      { return 8 }
func (w *heldWriter) Reserve(uint64)        {}
func (w *heldWriter) HoldsWrites() bool     { return w.holds }

func (w *heldWriter) AddWrite(int, stateio.SourceFile, memmap.FileRange, []byte) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritev(int, uint64, stateio.SourceFile, []memmap.FileRange, []unix.Iovec) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritevAt(id int, off uint64, flags stateio.WriteFlags, total uint64, _ stateio.SourceFile, _ []memmap.FileRange, srcs []unix.Iovec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if flags&stateio.WriteRepeat != 0 && !w.holds {
		panic("repeated write to a pages file that doesn't hold writes")
	}
	if flags&stateio.WritePriority != 0 {
		w.priority++
	}
	if flags&stateio.WriteRepeat != 0 {
		w.repeats++
	}
	w.pending = append(w.pending, heldWrite{id, off, flags, append([]unix.Iovec(nil), srcs...)})
	w.cond.Broadcast()
}

// repeated returns true if a pending repeat overlaps hw.
//
// Preconditions: w.mu must be locked.
func (w *heldWriter) repeated(hw *heldWrite) bool {
	for i := range w.pending {
		r := &w.pending[i]
		if r.flags&stateio.WriteRepeat != 0 && r.off < hw.end() && hw.off < r.end() {
			return true
		}
	}
	return false
}

// Wait returns early while it holds writes, as PositionedWriter allows.
func (w *heldWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for {
		var rest []heldWrite
		for i := range w.pending {
			hw := &w.pending[i]
			if hw.flags&stateio.WritePriority == 0 && !w.released && !w.repeated(hw) {
				rest = append(rest, *hw)
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

// startEarlyResumeSave fills 16 pages of f and starts saving them to w. It
// returns the pages, their contents, and a channel that receives the result of
// saving.
func startEarlyResumeSave(t *testing.T, f *MemoryFile, w *heldWriter) (memmap.FileRange, []byte, chan error) {
	t.Helper()
	fr := allocateSaveTestPages(t, f)
	for i := 0; i < 16; i++ {
		pwritePage(t, f, fr, i, byte(i+1))
	}
	want := make([]byte, fr.Length())
	f.forEachMappingSlice(fr, func(bs []byte) { copy(want, bs) })

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
	return fr, want, done
}

// finishEarlyResumeSave releases w's writes, waits for saving to finish, and
// checks that w holds want.
func finishEarlyResumeSave(t *testing.T, f *MemoryFile, w *heldWriter, want []byte, done chan error) {
	t.Helper()
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
	if !bytes.Equal(w.file, want) {
		t.Errorf("pages file differs from memory at save time")
	}
}

func TestEarlyResumeSaveWaitsForWrittenPages(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	w := newHeldWriter(false)
	fr, want, done := startEarlyResumeSave(t, f, w)

	if _, err := f.MapInternal(testPage(fr, 3), hostarch.Read); err != nil {
		t.Fatalf("MapInternal(Read): %v", err)
	}
	if !f.HasUnsaved(testPage(fr, 12)) {
		t.Fatalf("page 12 saved while writes are held")
	}
	ims, err := f.MapInternal(testPage(fr, 12), hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal(Write): %v", err)
	}
	if f.HasUnsaved(testPage(fr, 12)) {
		t.Fatalf("page 12 unsaved after MapInternal(Write)")
	}
	ims.Head().ToSlice()[17] = 0xff
	f.Decommit(testPage(fr, 13))

	finishEarlyResumeSave(t, f, w, want, done)
	if w.priority == 0 {
		t.Errorf("no priority writes")
	}
}

func TestEarlyResumeSaveRepeatsHeldWrites(t *testing.T) {
	f := newSaveTestMemoryFile(t, false)
	w := newHeldWriter(true)
	fr, want, done := startEarlyResumeSave(t, f, w)

	for !w.holding(3 * uint64(hostarch.PageSize)) {
		time.Sleep(time.Millisecond)
	}
	ims, err := f.MapInternal(testPage(fr, 3), hostarch.Write)
	if err != nil {
		t.Fatalf("MapInternal(Write): %v", err)
	}
	ims.Head().ToSlice()[17] = 0xff
	if w.repeats == 0 {
		t.Errorf("no repeated writes")
	}

	finishEarlyResumeSave(t, f, w, want, done)
}

func TestEarlyResumeRefusedWithoutPositionedWrites(t *testing.T) {
	apfs, err := StartAsyncPagesFileSave(struct{ stateio.AsyncWriter }{newHeldWriter(false)}, nil)
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
