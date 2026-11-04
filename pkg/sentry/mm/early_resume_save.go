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

package mm

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

// earlyResumeMapUnit replaces mapping whole pmas while an early-resume save may
// leave pages unsaved, since unsaved pages are mapped separately (read-only).
const earlyResumeMapUnit = 2 << 20

// PrepareEarlyResumeSave drops all AddressSpace mappings and cached internal
// mappings, so that writes after an early-resume save resumes the application
// fault and wait for unsaved pages. See pgalloc.AsyncPagesFileSave.EnableEarlyResume.
//
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) PrepareEarlyResumeSave() {
	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		pseg.ValuePtr().internalMappings = safemem.BlockSeq{}
	}
	mm.unmapASLocked(mm.applicationAddrRange())
}

// unsavedFileRange returns pseg's MemoryFile and the file range of the part
// of ar in pseg, if a write to it must wait for an early-resume save.
func (pseg pmaIterator) unsavedFileRange(ar hostarch.AddrRange) (*pgalloc.MemoryFile, memmap.FileRange, bool) {
	mf, ok := pseg.ValuePtr().file.(*pgalloc.MemoryFile)
	if !ok || !mf.IsEarlyResumeSaving() {
		return nil, memmap.FileRange{}, false
	}
	fr := pseg.fileRangeOf(pseg.Range().Intersect(ar))
	return mf, fr, mf.HasUnsaved(fr)
}

type unsavedFileRangeOf struct {
	mf *pgalloc.MemoryFile
	fr memmap.FileRange
}

// unsavedFileRanges returns the file ranges of pmas from pseg through ar.End
// that a write must wait for an early-resume save to save.
func unsavedFileRanges(pseg pmaIterator, ar hostarch.AddrRange) []unsavedFileRangeOf {
	var unsaved []unsavedFileRangeOf
	for ; pseg.Ok() && pseg.Start() < ar.End; pseg = pseg.NextSegment() {
		if mf, fr, ok := pseg.unsavedFileRange(ar); ok {
			unsaved = append(unsaved, unsavedFileRangeOf{mf, fr})
		}
	}
	return unsaved
}

// mapPMAWriteProtectedLocked is equivalent to mapPMALocked, except that pages
// that an early-resume save has not saved yet are mapped read-only.
//
// +checklocksread:mm.activeMu
func (mm *MemoryManager) mapPMAWriteProtectedLocked(ctx context.Context, pseg pmaIterator, ar hostarch.AddrRange, perms hostarch.AccessType, precommit bool) error {
	mf, ok := pseg.ValuePtr().file.(*pgalloc.MemoryFile)
	if !perms.Write || !ok || !mf.IsEarlyResumeSaving() {
		return mm.mapPMALocked(ctx, pseg, ar, perms, precommit)
	}
	fr := pseg.fileRangeOf(ar)
	readOnly := perms
	readOnly.Write = false
	start := ar.Start
	for _, ufr := range mf.UnsavedRanges(fr, nil) {
		uar := hostarch.AddrRange{
			Start: ar.Start + hostarch.Addr(ufr.Start-fr.Start),
			End:   ar.Start + hostarch.Addr(ufr.End-fr.Start),
		}
		if start < uar.Start {
			if err := mm.mapPMALocked(ctx, pseg, hostarch.AddrRange{start, uar.Start}, perms, precommit); err != nil {
				return err
			}
		}
		if err := mm.mapPMALocked(ctx, pseg, uar, readOnly, precommit); err != nil {
			return err
		}
		start = uar.End
	}
	if start < ar.End {
		return mm.mapPMALocked(ctx, pseg, hostarch.AddrRange{start, ar.End}, perms, precommit)
	}
	return nil
}
