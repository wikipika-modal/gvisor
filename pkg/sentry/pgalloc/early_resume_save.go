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

package pgalloc

import (
	"errors"
	"fmt"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

// Early-resume saving lets the application run while its pages are still
// being written to the pages file. Every MemoryFile range that has not yet
// been written is write-protected: application mappings of it are read-only
// (see the mm package), and internal writers call MemoryFile.awaitSaved(),
// which moves the range to the front of the write queue and blocks until it
// has been written. Writes carry explicit pages file offsets, since priority
// writes complete out of order.

// earlyResumePriorityUnit is the alignment to which ranges awaited by writers
// are expanded when they are moved to the front of the write queue, so that
// sequential writers wait less often.
const earlyResumePriorityUnit = 2 << 20

// apsUnsavedInfo is the value type of asyncMemoryFileSave.unsaved.
type apsUnsavedInfo struct {
	// off is the offset into the pages file at which the segment's first
	// byte is saved.
	off uint64

	// priority is true if a writer is blocked on the segment.
	priority bool

	// inflight is true if a write of the segment has been enqueued.
	inflight bool

	// prioritySent is true if a priority write of the segment has been
	// enqueued.
	prioritySent bool
}

type apsUnsavedSetFunctions struct{}

func (apsUnsavedSetFunctions) MinKey() uint64 {
	return 0
}

func (apsUnsavedSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

func (apsUnsavedSetFunctions) ClearValue(*apsUnsavedInfo) {
}

func (apsUnsavedSetFunctions) Merge(fr1 memmap.FileRange, us1 apsUnsavedInfo, fr2 memmap.FileRange, us2 apsUnsavedInfo) (apsUnsavedInfo, bool) {
	if us1.off+fr1.Length() != us2.off || us1.priority != us2.priority || us1.inflight != us2.inflight || us1.prioritySent != us2.prioritySent {
		return apsUnsavedInfo{}, false
	}
	return us1, true
}

func (apsUnsavedSetFunctions) Split(fr memmap.FileRange, us apsUnsavedInfo, splitAt uint64) (apsUnsavedInfo, apsUnsavedInfo) {
	us2 := us
	us2.off += splitAt - fr.Start
	return us, us2
}

// ErrEarlyResumeUnsupported is returned by EnableEarlyResume if the pages file
// can't be written at explicit offsets.
var ErrEarlyResumeUnsupported = errors.New("early-resume saving unsupported")

// EnableEarlyResume makes apfs save pages after MemoryFile.SaveTo() returns,
// while the MemoryFiles saved to apfs may be written to. It must be called
// before any call to MemoryFile.SaveTo() with apfs. If it returns an error
// wrapping ErrEarlyResumeUnsupported, apfs is unchanged and may be used for an
// ordinary save.
func (apfs *AsyncPagesFileSave) EnableEarlyResume() error {
	pw, ok := apfs.aw.(stateio.PositionedWriter)
	if !ok {
		return fmt.Errorf("%w: pages file %T does not support positioned writes", ErrEarlyResumeUnsupported, apfs.aw)
	}
	maxRanges := apfs.aw.MaxRanges()
	if maxRanges < 2 {
		return fmt.Errorf("%w: pages file MaxRanges() (%d) is below 2", ErrEarlyResumeUnsupported, maxRanges)
	}
	apfs.pw = pw
	apfs.earlyResume = true
	apfs.repeats = pw.HoldsWrites()
	apfs.prioReserve = min(4, apfs.qavail/4)
	apfs.savedCh = make(chan struct{})
	for i := range apfs.ops {
		op := &apfs.ops[i]
		op.frs = op.frs[: 0 : maxRanges-1]
		op.iovecs = op.iovecs[: 0 : maxRanges-1]
	}
	return nil
}

// registerEarlyResume makes amfs's MemoryFile wait for saving before writes.
func (amfs *asyncMemoryFileSave) registerEarlyResume() error {
	apfs := amfs.pf
	if !amfs.f.earlyResumeSave.CompareAndSwap(nil, amfs) {
		return fmt.Errorf("MemoryFile(%p) is already being saved", amfs.f)
	}
	apfs.mu.Lock()
	apfs.erFiles = append(apfs.erFiles, amfs)
	apfs.mu.Unlock()
	return nil
}

// Preconditions: apfs.mu must be locked.
func (amfs *asyncMemoryFileSave) addUnsavedLocked(fr memmap.FileRange, off uint64) {
	amfs.unsaved.InsertRange(fr, apsUnsavedInfo{off: off})
}

// enqueueEarlyResumeLocked enqueues priority writes, repeating writes that the
// pages file may hold, then writes in pages file order.
//
// Preconditions: apfs.mu must be locked.
func (apfs *AsyncPagesFileSave) enqueueEarlyResumeLocked() {
	for apfs.canEnqueue() && !apfs.priority.Empty() {
		pr := apfs.priority.PeekFrontPtr()
		useg := pr.amfs.unsaved.LowerBoundSegment(pr.Start)
		for useg.Ok() && useg.Start() < pr.End && (!useg.ValuePtr().priority || useg.ValuePtr().prioritySent) {
			useg = useg.NextSegment()
		}
		if !useg.Ok() || useg.Start() >= pr.End {
			apfs.priority.RemoveFront()
			continue
		}
		if apfs.curOp != nil {
			apfs.enqueueCurOp()
			if !apfs.canEnqueue() {
				return
			}
		}
		flags := stateio.WritePriority
		if useg.ValuePtr().inflight {
			flags |= stateio.WriteRepeat
		}
		n := apfs.enqueueUnsaved(pr.amfs, useg, useg.Range().Intersect(pr.FileRange), flags)
		apfs.enqueueCurOp()
		pr.Start = max(pr.Start, useg.Start()) + n
	}
	for apfs.qavail > apfs.prioReserve && apfs.erCursorFile < len(apfs.erFiles) {
		amfs := apfs.erFiles[apfs.erCursorFile]
		useg := amfs.unsaved.LowerBoundSegment(apfs.erCursor)
		for useg.Ok() && (useg.ValuePtr().priority || useg.ValuePtr().inflight) {
			useg = useg.NextSegment()
		}
		if !useg.Ok() {
			// MemoryFiles are scanned one at a time, so only a later
			// MemoryFile's registration means that this one is complete.
			if apfs.erCursorFile+1 == len(apfs.erFiles) {
				return
			}
			apfs.erCursorFile++
			apfs.erCursor = 0
			continue
		}
		fr := useg.Range()
		n := apfs.enqueueUnsaved(amfs, useg, fr, 0)
		if n == 0 {
			apfs.enqueueCurOp()
			continue
		}
		apfs.erCursor = fr.Start + n
	}
}

// enqueueUnsaved adds as much of fr as possible to apfs.curOp, a write with the
// given flags, marks it inflight, and returns the number of bytes added. If
// apfs.curOp can't be extended, enqueueUnsaved returns 0 without changing it.
//
// Preconditions:
// - apfs.mu must be locked.
// - apfs.canEnqueue() == true.
// - useg.Range().IsSupersetOf(fr).
// - fr.Length() > 0.
func (apfs *AsyncPagesFileSave) enqueueUnsaved(amfs *asyncMemoryFileSave, useg apsUnsavedIterator, fr memmap.FileRange, flags stateio.WriteFlags) uint64 {
	off := useg.ValuePtr().off + (fr.Start - useg.Start())
	if op := apfs.curOp; op != nil && op.total != 0 && (op.amfs != amfs || op.flags != flags || op.off+op.total != off) {
		return 0
	}
	if apfs.curOp == nil {
		id, err := apfs.opsBusy.FirstZero(0)
		if err != nil {
			panic(fmt.Sprintf("all ops busy with qavail=%d: %v", apfs.qavail, err))
		}
		apfs.opsBusy.Add(id)
		op := &apfs.ops[id]
		op.total = 0
		op.frs = op.frs[:0]
		op.iovecs = op.iovecs[:0]
		apfs.curOp = op
		apfs.curOpID = id
	}
	op := apfs.curOp
	if op.total == 0 {
		op.off = off
		op.flags = flags
	}
	n := apfs.combine(apsRange{amfs: amfs, FileRange: fr})
	if n == 0 {
		return 0
	}
	useg = amfs.unsaved.Isolate(useg, memmap.FileRange{fr.Start, fr.Start + n})
	useg.ValuePtr().inflight = true
	useg.ValuePtr().prioritySent = flags&stateio.WritePriority != 0
	return n
}

// enqueueEarlyResumeOp enqueues apfs.curOp.
func (apfs *AsyncPagesFileSave) enqueueEarlyResumeOp(op *apsOp) {
	if op.flags&stateio.WritePriority != 0 {
		apfs.prioOps++
		apfs.prioBytes += op.total
	}
	if op.flags&stateio.WriteRepeat != 0 {
		apfs.repeatOps++
	}
	apfs.pw.AddWritevAt(int(apfs.curOpID), op.off, op.flags, op.total, op.amfs.sf, op.frs, op.iovecs)
}

// savedLocked records that op has been written.
//
// Preconditions: apfs.mu must be locked.
func (apfs *AsyncPagesFileSave) savedLocked(op *apsOp) {
	for _, fr := range op.frs {
		op.amfs.unsaved.RemoveRange(fr)
	}
}

// wakeSaveWaitersLocked wakes callers of awaitSaved().
//
// Preconditions: apfs.mu must be locked.
func (apfs *AsyncPagesFileSave) wakeSaveWaitersLocked() {
	close(apfs.savedCh)
	apfs.savedCh = make(chan struct{})
}

// endEarlyResume stops write-protecting MemoryFiles saved to apfs, whether or
// not saving succeeded.
func (apfs *AsyncPagesFileSave) endEarlyResume() {
	apfs.mu.Lock()
	defer apfs.mu.Unlock()
	apfs.erDone = true
	for _, amfs := range apfs.erFiles {
		amfs.f.earlyResumeSave.CompareAndSwap(amfs, nil)
	}
	apfs.wakeSaveWaitersLocked()
	log.Infof("Early-resume page saving: %d priority writes (%d bytes, %d repeats); %d waits for %s",
		apfs.prioOps, apfs.prioBytes, apfs.repeatOps, apfs.erWaits, apfs.erWaitDur)
}

// IsEarlyResumeSaving returns true if pages of f may still be unsaved after an
// early-resume save, in which case writes to f's pages must be preceded by
// AwaitSaved() and application mappings of UnsavedRanges() must be read-only.
func (f *MemoryFile) IsEarlyResumeSaving() bool {
	return f.earlyResumeSave.Load() != nil
}

// AwaitSaved blocks until all pages in fr have been saved, if f is being saved
// by an early-resume save.
func (f *MemoryFile) AwaitSaved(fr memmap.FileRange) {
	if amfs := f.earlyResumeSave.Load(); amfs != nil {
		amfs.awaitSaved(fr)
	}
}

// HasUnsaved returns true if any page in fr has not yet been saved by an
// early-resume save.
func (f *MemoryFile) HasUnsaved(fr memmap.FileRange) bool {
	amfs := f.earlyResumeSave.Load()
	if amfs == nil {
		return false
	}
	apfs := amfs.pf
	apfs.mu.Lock()
	defer apfs.mu.Unlock()
	return !apfs.erDone && !amfs.unsaved.IsEmptyRange(fr)
}

// UnsavedRanges appends the subranges of fr that have not yet been saved by an
// early-resume save to frs, and returns the updated slice.
func (f *MemoryFile) UnsavedRanges(fr memmap.FileRange, frs []memmap.FileRange) []memmap.FileRange {
	amfs := f.earlyResumeSave.Load()
	if amfs == nil {
		return frs
	}
	apfs := amfs.pf
	apfs.mu.Lock()
	defer apfs.mu.Unlock()
	if apfs.erDone {
		return frs
	}
	for useg := amfs.unsaved.LowerBoundSegment(fr.Start); useg.Ok() && useg.Start() < fr.End; useg = useg.NextSegment() {
		ufr := useg.Range().Intersect(fr)
		if n := len(frs); n != 0 && frs[n-1].End == ufr.Start {
			frs[n-1].End = ufr.End
		} else {
			frs = append(frs, ufr)
		}
	}
	return frs
}

func (amfs *asyncMemoryFileSave) awaitSaved(fr memmap.FileRange) {
	fr.Start = hostarch.PageRoundDown(fr.Start)
	fr.End = hostarch.MustPageRoundUp(fr.End)
	pfr := memmap.FileRange{
		Start: fr.Start &^ (earlyResumePriorityUnit - 1),
		End:   (fr.End + earlyResumePriorityUnit - 1) &^ (earlyResumePriorityUnit - 1),
	}
	apfs := amfs.pf
	apfs.mu.Lock()
	if apfs.erDone || amfs.unsaved.IsEmptyRange(fr) {
		apfs.mu.Unlock()
		return
	}
	timeStart := gohacks.Nanotime()
	apfs.erWaits++
	for {
		requested := false
		amfs.unsaved.MutateRange(pfr, func(useg apsUnsavedIterator) bool {
			us := useg.ValuePtr()
			if !us.priority && (!us.inflight || apfs.repeats) {
				us.priority = true
				requested = true
			}
			return true
		})
		if requested {
			apfs.priority.PushBack(apsRange{amfs: amfs, FileRange: pfr})
		}
		savedCh := apfs.savedCh
		apfs.mu.Unlock()
		if requested {
			apfs.stStatus.Notify(apsSTPending)
		}
		<-savedCh
		apfs.mu.Lock()
		if apfs.erDone || amfs.unsaved.IsEmptyRange(fr) {
			break
		}
	}
	apfs.erWaitDur += time.Duration(gohacks.Nanotime() - timeStart)
	apfs.mu.Unlock()
}
