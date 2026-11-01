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

package kernel

import (
	"bytes"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// holdFor is how long heldWriter holds writes that aren't priority writes.
const holdFor = 200 * time.Millisecond

// heldWriter completes priority writes at once and other writes after holdFor,
// copying each write's source when completing it, and records what it saved
// by MemoryFile offset.
type heldWriter struct {
	stateio.NoRegisterClientFD

	mu      sync.Mutex
	pending []heldWrite
	saved   map[uint64][]byte
}

type heldWrite struct {
	id       int
	priority bool
	added    time.Time
	frs      []memmap.FileRange
	srcs     []unix.Iovec
}

func (w *heldWriter) Close() error          { return nil }
func (w *heldWriter) MaxWriteBytes() uint64 { return hostarch.PageSize }
func (w *heldWriter) MaxRanges() int        { return 2 }
func (w *heldWriter) MaxParallel() int      { return 8 }
func (w *heldWriter) Reserve(uint64)        {}
func (w *heldWriter) Finalize() error       { return nil }
func (w *heldWriter) HoldsWrites() bool     { return false }

func (w *heldWriter) AddWrite(int, stateio.SourceFile, memmap.FileRange, []byte) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritev(int, uint64, stateio.SourceFile, []memmap.FileRange, []unix.Iovec) {
	panic("appending write during early-resume save")
}

func (w *heldWriter) AddWritevAt(id int, _ uint64, flags stateio.WriteFlags, _ uint64, _ stateio.SourceFile, frs []memmap.FileRange, srcs []unix.Iovec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, heldWrite{id, flags&stateio.WritePriority != 0, time.Now(), append([]memmap.FileRange(nil), frs...), append([]unix.Iovec(nil), srcs...)})
}

// Wait returns early while it holds writes, as stateio.PositionedWriter
// allows.
func (w *heldWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var rest []heldWrite
	for _, hw := range w.pending {
		if !hw.priority && time.Since(hw.added) < holdFor {
			rest = append(rest, hw)
			continue
		}
		var n uint64
		for i, fr := range hw.frs {
			w.saved[fr.Start] = bytes.Clone(stateio.SliceFromIovec(hw.srcs[i]))
			n += fr.Length()
		}
		cs = append(cs, stateio.Completion{ID: hw.id, N: n})
	}
	w.pending = rest
	if len(cs) == 0 && minCompletions > 0 {
		w.mu.Unlock()
		time.Sleep(time.Millisecond)
		w.mu.Lock()
	}
	return cs, nil
}

func TestVDSOParamPageWaitsForEarlyResumeSave(t *testing.T) {
	ctx := contexttest.Context(t)
	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	params := NewVDSOParamPage(mf, fr)
	write := func(base int64) {
		if err := params.Write(func() vdsoParams {
			return vdsoParams{monotonicReady: 1, monotonicBaseCycles: base}
		}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	write(1)
	bs, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	want := bytes.Clone(bs.Head().ToSlice())

	w := &heldWriter{saved: make(map[uint64][]byte)}
	done := make(chan error, 1)
	apfs, err := pgalloc.StartAsyncPagesFileSave(w, func(err error) { done <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	if err := apfs.EnableEarlyResume(); err != nil {
		t.Fatalf("EnableEarlyResume: %v", err)
	}
	if err := mf.SaveTo(ctx, io.Discard, &pgalloc.SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()

	write(2)
	if err := <-done; err != nil {
		t.Fatalf("saving failed: %v", err)
	}
	if got := w.saved[fr.Start]; !bytes.Equal(got, want) {
		t.Errorf("saved param page differs from the page when saving began")
	}
}
