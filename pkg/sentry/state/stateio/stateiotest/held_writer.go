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

// Package stateiotest provides stateio implementations for tests.
package stateiotest

import (
	"bytes"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sync"
)

// HeldWriter is a stateio.PositionedWriter for early-resume saves. It
// completes priority writes at once and other writes once they have been held
// for a while, copying each write's source when completing it, and records
// what it saved by source file offset.
type HeldWriter struct {
	stateio.NoRegisterClientFD

	mu       sync.Mutex
	hold     time.Duration
	pending  []heldWrite
	saved    map[uint64][]byte
	priority int
}

type heldWrite struct {
	id       int
	priority bool
	added    time.Time
	frs      []memmap.FileRange
	srcs     []unix.Iovec
}

// NewHeldWriter returns a HeldWriter that holds writes other than priority
// writes for hold.
func NewHeldWriter(hold time.Duration) *HeldWriter {
	return &HeldWriter{hold: hold, saved: make(map[uint64][]byte)}
}

// Release completes held writes at the next Wait, and stops holding writes.
func (w *HeldWriter) Release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hold = 0
}

// Saved returns the page saved from source file offset off, or nil.
func (w *HeldWriter) Saved(off uint64) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.saved[off]
}

// PriorityWrites returns the number of priority writes added so far.
func (w *HeldWriter) PriorityWrites() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.priority
}

// Close implements stateio.AsyncWriter.Close.
func (w *HeldWriter) Close() error { return nil }

// MaxWriteBytes implements stateio.AsyncWriter.MaxWriteBytes.
func (w *HeldWriter) MaxWriteBytes() uint64 { return hostarch.PageSize }

// MaxRanges implements stateio.AsyncWriter.MaxRanges.
func (w *HeldWriter) MaxRanges() int { return 2 }

// MaxParallel implements stateio.AsyncWriter.MaxParallel.
func (w *HeldWriter) MaxParallel() int { return 8 }

// Reserve implements stateio.AsyncWriter.Reserve.
func (w *HeldWriter) Reserve(uint64) {}

// Finalize implements stateio.AsyncWriter.Finalize.
func (w *HeldWriter) Finalize() error { return nil }

// PriorityUnit implements stateio.PositionedWriter.PriorityUnit.
func (w *HeldWriter) PriorityUnit() uint64 { return 0 }

// AddWrite implements stateio.AsyncWriter.AddWrite.
func (w *HeldWriter) AddWrite(int, stateio.SourceFile, memmap.FileRange, []byte) {
	panic("appending write during early-resume save")
}

// AddWritev implements stateio.AsyncWriter.AddWritev.
func (w *HeldWriter) AddWritev(int, uint64, stateio.SourceFile, []memmap.FileRange, []unix.Iovec) {
	panic("appending write during early-resume save")
}

// AddWritevAt implements stateio.PositionedWriter.AddWritevAt.
func (w *HeldWriter) AddWritevAt(id int, _ uint64, priority bool, _ uint64, _ stateio.SourceFile, frs []memmap.FileRange, srcs []unix.Iovec) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if priority {
		w.priority++
	}
	w.pending = append(w.pending, heldWrite{id, priority, time.Now(), append([]memmap.FileRange(nil), frs...), append([]unix.Iovec(nil), srcs...)})
}

// Wait implements stateio.AsyncWriter.Wait.
func (w *HeldWriter) Wait(cs []stateio.Completion, minCompletions int) ([]stateio.Completion, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	minLen := len(cs) + minCompletions
	for {
		var rest []heldWrite
		for _, hw := range w.pending {
			if !hw.priority && time.Since(hw.added) < w.hold {
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
		if len(cs) >= minLen {
			return cs, nil
		}
		w.mu.Unlock()
		time.Sleep(time.Millisecond)
		w.mu.Lock()
	}
}
