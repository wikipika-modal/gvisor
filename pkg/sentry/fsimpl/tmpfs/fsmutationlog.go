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

package tmpfs

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ErrMutationLogOverflowed is the error of a journaled mount whose generation's buffered
// records exceeded logBufCap: tracking stops (logFailed) and every FSMutationLogWrite fails
// with this error until FSMutationLogResync restarts the journal.
var ErrMutationLogOverflowed = errors.New("fsmutationlog: mutation log overflowed; tracking disabled")

// logBufCap bounds the bytes of records (structural + content) journaled in one incremental
// generation. Exceeding it fails the log: since records are dropped from that point on, no
// later incremental segment can be consistent until a resync. It is a var so tests can
// lower it.
var logBufCap = 64 << 20

// logInitMapSize is the initial size of the log mmap; it grows on demand (see ensureLogCap).
// The backing file is sparse, so an unused mapping costs only address space.
const logInitMapSize = 4 << 20

// The following helpers commit records to the mutation log. When mutation logging is
// disabled they are no-ops, so ordinary tmpfs mounts don't pay the cost of this logging.

// logCreate records the creation (or hard-linking) of `child` as `name` under `parentDir`,
// including its initial inode state. Pipes and sockets are not recorded.
//
// Preconditions: filesystem.mu locked for writing.
func (fs *filesystem) logCreate(parentDir *directory, name string, child *dentry) {
	if !fs.logEnabled.Load() {
		return
	}
	ftype, ok := fmlgFtype(child.inode)
	if !ok {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	fs.markChangedLocked(child.inode)
	if fs.logFailed || fs.logFinalized {
		return
	}
	fs.logScratch = fmlgAppendCreateWithState(fs.logScratch[:0], parentDir.inode.ino, name, child, ftype)
	fs.appendMutationLocked(fmlgKindCreateWithState, fs.logScratch)
}

// logRename records the move of `renamed` from (oldParentIno, oldName) to (newParentIno,
// newName). A directory rename results in a single record. Pipes and sockets are not
// recorded.
//
// Preconditions: filesystem.mu locked for writing.
func (fs *filesystem) logRename(renamed *dentry, oldParentIno uint64, oldName string, newParentIno uint64, newName string) {
	if !fs.logEnabled.Load() {
		return
	}
	if _, ok := fmlgFtype(renamed.inode); !ok {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if fs.logFailed || fs.logFinalized {
		return
	}
	fs.logScratch = fmlgAppendRename(fs.logScratch[:0], renamed.inode.ino, oldParentIno, oldName, newParentIno, newName)
	fs.appendMutationLocked(fmlgKindRename, fs.logScratch)
}

// logRenameExchange records an exchange without dropping either inode's links.
//
// Preconditions: filesystem.mu locked for writing.
func (fs *filesystem) logRenameExchange(renamed, replaced *dentry, oldParent *directory, oldName string, newParent *directory, newName string) {
	if !fs.logEnabled.Load() {
		return
	}
	_, logRenamed := fmlgFtype(renamed.inode)
	_, logReplaced := fmlgFtype(replaced.inode)
	if !logRenamed {
		if logReplaced {
			fs.logRename(replaced, newParent.inode.ino, newName, oldParent.inode.ino, oldName)
		}
		return
	}
	if !logReplaced {
		fs.logRename(renamed, oldParent.inode.ino, oldName, newParent.inode.ino, newName)
		return
	}

	// Readers prune overwritten inodes and their subtrees. Three renames through
	// an unused journal-only name keep both inodes linked throughout replay.
	var tempName string
	for i := 0; ; i++ {
		tempName = fmt.Sprintf(".fsmutationlog-exchange-%d", i)
		if _, exists := oldParent.childMap[tempName]; !exists {
			break
		}
	}
	fs.logRename(renamed, oldParent.inode.ino, oldName, oldParent.inode.ino, tempName)
	fs.logRename(replaced, newParent.inode.ino, newName, oldParent.inode.ino, oldName)
	fs.logRename(renamed, oldParent.inode.ino, tempName, newParent.inode.ino, newName)
}

// logUnlink records the removal of the (parentIno, name) edge to child.
// Pipes and sockets are not recorded.
//
// Preconditions: filesystem.mu locked for writing.
func (fs *filesystem) logUnlink(child *dentry, parentIno uint64, name string) {
	if !fs.logEnabled.Load() {
		return
	}
	if _, ok := fmlgFtype(child.inode); !ok {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if fs.logFailed || fs.logFinalized {
		return
	}
	fs.logScratch = fmlgAppendUnlink(fs.logScratch[:0], child.inode.ino, parentIno, name)
	fs.appendMutationLocked(fmlgKindUnlink, fs.logScratch)
}

// logDirty appends a NODESTATE carrying `in`'s current state for a mutation that has no
// close event to capture it: the path-based metadata ops (chmod/chown/utimes/truncate via
// SetStatAt, xattr set/remove) and their fd variants. File content changes go through
// logOpenForWrite/logCloseForWrite instead. Content records commute with structural
// records (see fsmutationlog_fmlg.go), so they are emitted immediately, like the
// structural records. It needs only the inode, so it is safe to call from the
// setstat/xattr sites, which do not hold filesystem.mu (callers hold at most inode.mu;
// the encode takes dataMu.RLock and the xattr lock, both inward of inode.mu).
func (fs *filesystem) logDirty(in *inode) {
	if !fs.logEnabled.Load() {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	fs.markChangedLocked(in)
	if fs.logFailed || fs.logFinalized {
		return
	}
	fs.logScratch = fmlgAppendNodeState(fs.logScratch[:0], in)
	fs.appendMutationLocked(fmlgKindNodeState, fs.logScratch)
}

// logOpenForWrite tracks that `in` has a writable file description. Mutations made through
// it produce no records; they are captured instead by the drain (a fresh NODESTATE for every
// open-for-write file, exact against the paused filestore) and by logCloseForWrite when its
// last description closes.
func (fs *filesystem) logOpenForWrite(in *inode) {
	if !fs.logEnabled.Load() {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if fs.logFinalized {
		return
	}
	if fs.logOpenFiles == nil {
		fs.logOpenFiles = make(map[*inode]uint64)
	}
	fs.logOpenFiles[in]++
}

// logCloseForWrite drops `in`'s writable-description refcount; when the last one closes it
// appends a fresh NODESTATE capturing the file's state at close (its writes produced no
// records, so this is the only place they are journaled).
func (fs *filesystem) logCloseForWrite(in *inode) {
	if !fs.logEnabled.Load() {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	fs.markChangedLocked(in)
	n := fs.logOpenFiles[in]
	if n > 1 {
		fs.logOpenFiles[in] = n - 1
		return
	}
	delete(fs.logOpenFiles, in)
	if fs.logFailed || fs.logFinalized || fs.logFD < 0 || n == 0 {
		return
	}
	fs.logScratch = fmlgAppendNodeState(fs.logScratch[:0], in)
	fs.appendMutationLocked(fmlgKindNodeState, fs.logScratch)
}

// DO_NOT_SUBMIT: get rid of the "drain" terminology everywhere?
// logMmapWritable tracks shared writable mappings for reconciliation.
func (fs *filesystem) logMmapWritable(in *inode) {
	if !fs.logEnabled.Load() {
		return
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if fs.logFinalized {
		return
	}
	if fs.mmapWritable == nil {
		fs.mmapWritable = make(map[*inode]struct{})
	}
	fs.mmapWritable[in] = struct{}{}
}

// initMutationLog discards any prior file incarnation before enabling logging.
func (fs *filesystem) initMutationLog() error {
	if err := unix.Ftruncate(fs.logFD, 0); err != nil {
		return err
	}
	if err := fs.writeLogAt(fmlgHeader(nil, fs.root.inode.ino, fmlgFlagsNone, fmlgFailureNone), 0 /* start of file */); err != nil {
		return err
	}
	fs.logGen.Store(fmlgInitialEpoch)
	fs.logOff = fmlgHeaderSize
	return fs.appendLogFrame(fmlgKindBegin, fmlgU64(nil, fmlgInitialEpoch-1 /* all journals start at epoch 1 */))
}

// beginLogEpochIfNeeded preserves a sealed segment until another append or capture.
// Preconditions: logMu locked.
func (fs *filesystem) beginLogEpochIfNeeded() error {
	if !fs.logSealed {
		return nil
	}
	if fs.logGen.Load() == ^uint64(0) {
		return fmt.Errorf("fsmutationlog: epoch exhausted")
	}
	fs.logGen.Add(1)
	fs.logOff = fmlgHeaderSize
	fs.logSeq = 0
	fs.logSealed = false
	return fs.appendLogFrame(fmlgKindBegin, fmlgU64(nil, fs.lastEmittedLogGen))
}

// appendMutationLocked commits one mutation record.
// Preconditions: logMu locked; journal enabled and not failed/finalized.
func (fs *filesystem) appendMutationLocked(kind uint32, rec []byte) {
	if err := fs.beginLogEpochIfNeeded(); err != nil {
		fs.setLogFailedLocked(fmlgFailureIO)
		return
	}
	if fs.logOff+fmlgFrameSize(uint64(len(rec))) > uint64(logBufCap) {
		fs.setLogFailedLocked(fmlgFailureOverflow)
		return
	}
	if err := fs.appendLogFrame(kind, rec); err != nil {
		fs.setLogFailedLocked(fmlgFailureIO)
	}
}

// ensureLogCap grows the log mapping so it covers at least need bytes, remapping if
// necessary (ftruncate the sparse backing file, then mmap the larger size). A segment may
// need to grow past logBufCap: the cap bounds the structural records of one generation, not
// the trailing NODESTATE records.
//
// Preconditions: fs.logFD >= 0; serialized by logMu (execution) or the paused drain.
func (fs *filesystem) ensureLogCap(need uint64) error {
	if need <= fs.logMapSize {
		return nil
	}
	newSize := fs.logMapSize
	if newSize == 0 {
		newSize = logInitMapSize
	}
	for newSize < need {
		newSize *= 2
	}
	if err := unix.Ftruncate(fs.logFD, int64(newSize)); err != nil {
		return err
	}
	m, err := unix.Mmap(fs.logFD, 0, int(newSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	if fs.logMapping != nil {
		unix.Munmap(fs.logMapping)
	}
	fs.logMapping = m
	fs.logMapSize = newSize
	return nil
}

// writeLogAt memcpys rec into the log mapping at off, growing the mapping if needed.
//
// Preconditions: fs.logFD >= 0; serialized by logMu (execution) or the paused drain.
func (fs *filesystem) writeLogAt(rec []byte, off uint64) error {
	if err := fs.ensureLogCap(off + uint64(len(rec))); err != nil {
		return err
	}
	copy(fs.logMapping[off:], rec)
	return nil
}

// logWriter writes sequentially into the log mapping from the start of the file.
//
// Preconditions: as for writeLogAt.
type logWriter struct {
	fs  *filesystem
	off uint64
}

// Write implements io.Writer.Write.
func (w *logWriter) Write(p []byte) (int, error) {
	if err := w.fs.writeLogAt(p, w.off); err != nil {
		return 0, err
	}
	w.off += uint64(len(p))
	return len(p), nil
}

// setLogFailedLocked publishes a sticky failure even when no frame fits.
// Preconditions: logMu locked.
func (fs *filesystem) setLogFailedLocked(reason uint64) {
	if fs.logFailed {
		return
	}
	fs.logFailed = true
	fs.logFailure = reason
	if len(fs.logMapping) >= fmlgHeaderSize {
		fmlgStore(fs.logMapping[fmlgFailureOffset:], reason)
	}
}

// clearLogFailedLocked undoes setLogFailedLocked when a resync restarts the journal.
// Preconditions: logMu locked.
func (fs *filesystem) clearLogFailedLocked() {
	fs.logFailed = false
	fs.logFailure = fmlgFailureNone
	// Clear the failure status published in the mapped file header.
	if len(fs.logMapping) >= fmlgHeaderSize {
		fmlgStore(fs.logMapping[fmlgFailureOffset:], fmlgFailureNone)
	}
}

func (fs *filesystem) mutationLogError() error {
	if fs.logFailure == fmlgFailureOverflow {
		return ErrMutationLogOverflowed
	}
	return fmt.Errorf("fsmutationlog: journal failed (status %d)", fs.logFailure)
}

// FSMutationLogWrite seals one epoch and returns its generation and length.
// The caller must capture the journal and filestore before resuming writers.
// sinceGen must match the last successful drain or resync.
//
// Preconditions: The kernel must be paused and quiesced.
func FSMutationLogWrite(ctx context.Context, vfsfs *vfs.Filesystem, sinceGen uint64) (newGen uint64, length uint64, err error) {
	fs, _ := vfsfs.Impl().(*filesystem)
	if fs == nil {
		return 0, 0, fmt.Errorf("non-tmpfs filesystem: %T", vfsfs.Impl())
	}
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if !fs.logEnabled.Load() || fs.logFD < 0 || fs.logFinalized {
		return 0, 0, fmt.Errorf("fsmutationlog: journal unavailable (not enabled, restored, or finalized)")
	}
	if fs.logFailed {
		return 0, 0, fs.mutationLogError()
	}
	if sinceGen != fs.lastEmittedLogGen {
		return 0, 0, fmt.Errorf("fsmutationlog: since-gen %d does not match last emitted generation %d", sinceGen, fs.lastEmittedLogGen)
	}
	if err := fs.fmlgWriteDelta(fmlgEndSnapshot); err != nil {
		fs.setLogFailedLocked(fmlgFailureIO)
		return 0, 0, err
	}
	fs.markEpochEmittedLocked()
	return fs.lastEmittedLogGen, fs.logOff, nil
}

// FSMutationLogResync writes a FULL segment of the journaled upper to dst
// and restarts the journal after it, clearing any failure. The returned
// generation is the next sinceGen for FSMutationLogWrite.
//
// Preconditions: The kernel must be paused and quiesced.
func FSMutationLogResync(ctx context.Context, vfsfs *vfs.Filesystem, dst io.Writer) (newGen uint64, length uint64, err error) {
	fs, _ := vfsfs.Impl().(*filesystem)
	if fs == nil {
		return 0, 0, fmt.Errorf("non-tmpfs filesystem: %T", vfsfs.Impl())
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if !fs.logEnabled.Load() || fs.logFD < 0 || fs.logFinalized {
		return 0, 0, fmt.Errorf("fsmutationlog: journal unavailable (not enabled, restored, or finalized)")
	}
	newGen = fs.logGen.Load() + 1
	length, err = fs.writeFullSegmentLocked(dst, newGen, fmlgEndSnapshot /* END reason */, fs.logFailure, true /* useTrackedLastModifiedLogEpochs */)
	if err != nil {
		return 0, 0, err
	}
	fs.pruneMmapWritableLocked()
	fs.logGen.Store(newGen)
	fs.markEpochEmittedLocked()
	fs.clearLogFailedLocked()
	return newGen, length, nil
}

// FSMutationLogDump writes a FULL segment of the journaled upper to dst without
// touching the journal, which need not exist. Every record reports the
// segment's epoch as its last modified epoch, so nothing is known to be
// unchanged.
//
// Preconditions: The kernel must be paused and quiesced.
func FSMutationLogDump(ctx context.Context, vfsfs *vfs.Filesystem, dst io.Writer) (gen uint64, length uint64, err error) {
	fs, _ := vfsfs.Impl().(*filesystem)
	if fs == nil {
		return 0, 0, fmt.Errorf("non-tmpfs filesystem: %T", vfsfs.Impl())
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	gen = fs.logGen.Load() + 1
	length, err = fs.writeFullSegmentLocked(dst, gen, fmlgEndSnapshot /* END reason */, fmlgFailureNone, false /* useTrackedLastModifiedLogEpochs */)
	if err != nil {
		return 0, 0, err
	}
	return gen, length, nil
}

// markEpochEmittedLocked records that the current epoch has been handed off to
// a consumer, so the next mutation starts a new epoch.
//
// Preconditions: logMu locked.
func (fs *filesystem) markEpochEmittedLocked() {
	fs.lastEmittedLogGen = fs.logGen.Load()
	fs.logSealed = true
}

// markChangedLocked records that in's content may differ from what the last
// capture reported.
//
// Preconditions: logMu locked.
func (fs *filesystem) markChangedLocked(in *inode) {
	in.lastModifiedLogEpoch = fs.lastEmittedLogGen + 1
}

// pruneMmapWritableLocked stops tracking inodes without a shared writable
// mapping. Such a mapping holds its writable file description, so
// logCloseForWrite marks the inode changed once the last mapping is gone. Both
// callers include such inodes in the current capture before pruning them.
//
// Preconditions: logMu locked.
func (fs *filesystem) pruneMmapWritableLocked() {
	for in := range fs.mmapWritable {
		if rf, ok := in.impl.(*regularFile); !ok || !rf.hasWritableMapping() {
			delete(fs.mmapWritable, in)
		}
	}
}

// fmlgFullFlushBytes is how much of a FULL segment is buffered before it is
// written out.
const fmlgFullFlushBytes = 1 << 20

// writeFullSegmentLocked writes a FULL segment that recreates the upper from
// empty: the root's NODESTATE, then a CREATE_WITH_STATE per entry, parents
// first. The header carries failure, the journal's failure status. With
// useTrackedLastModifiedLogEpochs, emits tracked lastModifiedLogEpochs to aid
// consumers in tracking inode staleness. Open writers and writable mappings
// always report the latest epoch.
//
// Preconditions: filesystem.mu locked; logMu locked if
// useTrackedLastModifiedLogEpochs; kernel paused and quiesced.
func (fs *filesystem) writeFullSegmentLocked(dst io.Writer, gen, reason, failure uint64, useTrackedLastModifiedLogEpochs bool) (uint64, error) {
	if !fs.root.inode.isDir() {
		return 0, fmt.Errorf("fsmutationlog: FULL segments need a directory root")
	}
	lastModifiedLogEpoch := func(in *inode) uint64 {
		if !useTrackedLastModifiedLogEpochs {
			return gen
		}
		if _, mapped := fs.mmapWritable[in]; mapped || fs.logOpenFiles[in] > 0 {
			return gen
		}
		return in.lastModifiedLogEpoch
	}
	buf := fmlgHeader(nil, fs.root.inode.ino, fmlgFlagFull, failure)
	var flushed uint64
	var seq uint32
	var err error
	frame := func(kind uint32, payload []byte) {
		buf = fmlgAppendFrame(buf, gen, kind, seq, payload)
		seq++
		if len(buf) >= fmlgFullFlushBytes && err == nil {
			_, err = dst.Write(buf)
			flushed += uint64(len(buf))
			buf = buf[:0]
		}
	}
	frame(fmlgKindBegin, fmlgU64(nil, gen-1 /* previous epoch */))
	rec := fmlgAppendNodeState(nil, fs.root.inode)
	frame(fmlgKindNodeState, fmlgU64(rec, lastModifiedLogEpoch(fs.root.inode)))
	stack := []*dentry{fs.root}
	for len(stack) > 0 && err == nil {
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for name, child := range d.inode.impl.(*directory).childMap {
			if child.isSelfFilestoreWhiteout() {
				continue
			}
			ftype, ok := fmlgFtype(child.inode)
			if !ok {
				continue
			}
			rec = fmlgAppendCreateWithState(rec[:0], d.inode.ino, name, child, ftype)
			frame(fmlgKindCreateWithState, fmlgU64(rec, lastModifiedLogEpoch(child.inode)))
			if ftype == fmlgTypeDir {
				stack = append(stack, child)
			}
		}
	}
	length := flushed + uint64(len(buf)) + fmlgFrameSize(fmlgEndPayloadSize)
	frame(fmlgKindEnd, fmlgAppendEnd(nil, fmlgEnd{
		endOffset:  length,
		frameCount: uint64(seq) + 1,
		reason:     reason,
	}))
	if err == nil {
		_, err = dst.Write(buf)
	}
	return length, err
}

// FinalizeFSMutationLog seals a graceful-exit epoch and trims the backing file
// to the committed prefix. If the journal has failed, which loses records, a
// graceful-exit FULL segment replaces it. It must run before inode destruction.
// Other tmpfs mounts (including restored mounts) are ignored. Repeated calls are
// harmless.
//
// Preconditions: No further guest mutations can occur.
func FinalizeFSMutationLog(vfsfs *vfs.Filesystem) error {
	fs, ok := vfsfs.Impl().(*filesystem)
	if !ok {
		return nil
	}
	return fs.finalizeMutationLog()
}

func (fs *filesystem) finalizeMutationLog() error {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	fs.logMu.Lock()
	defer fs.logMu.Unlock()
	if fs.logFinalized {
		return fs.logFinalizeErr
	}
	if !fs.logEnabled.Load() {
		return nil
	}
	fs.logFinalized = true
	fs.logEnabled.Store(false)
	if fs.logFailed {
		fs.logFinalizeErr = fs.mutationLogError()
	} else if err := fs.fmlgWriteDelta(fmlgEndGracefulExit); err != nil {
		fs.setLogFailedLocked(fmlgFailureIO)
		fs.logFinalizeErr = err
	}
	if fs.logFailed {
		length, err := fs.writeFullSegmentLocked(&logWriter{fs: fs}, fs.logGen.Load()+1, fmlgEndGracefulExit /* END reason */, fs.logFailure, true /* useTrackedLastModifiedLogEpochs */)
		if err != nil {
			fs.logFinalizeErr = errors.Join(fs.logFinalizeErr, fmt.Errorf("write mutation-log exit FULL segment: %w", err))
		} else {
			fs.logOff = length
			fs.logFinalizeErr = nil
		}
	}
	if err := unix.Munmap(fs.logMapping); err != nil {
		fs.logFinalizeErr = errors.Join(fs.logFinalizeErr, fmt.Errorf("unmap mutation log: %w", err))
		return fs.logFinalizeErr
	}
	fs.logMapping = nil
	fs.logMapSize = 0
	if err := unix.Ftruncate(fs.logFD, int64(fs.logOff)); err != nil {
		fs.logFinalizeErr = errors.Join(fs.logFinalizeErr, fmt.Errorf("truncate mutation log: %w", err))
	}
	return fs.logFinalizeErr
}

// fmlgWriteDelta reconciles live content channels and commits the END frame.
// Preconditions: logMu locked; kernel paused and quiesced.
func (fs *filesystem) fmlgWriteDelta(reason uint64) error {
	if err := fs.beginLogEpochIfNeeded(); err != nil {
		return err
	}
	tracked := make(map[*inode]struct{}, len(fs.logOpenFiles)+len(fs.mmapWritable))
	for in := range fs.logOpenFiles {
		tracked[in] = struct{}{}
	}
	for in := range fs.mmapWritable {
		tracked[in] = struct{}{}
	}
	fs.pruneMmapWritableLocked()
	var rec []byte
	for in := range tracked {
		rec = fmlgAppendNodeState(rec[:0], in)
		if err := fs.appendLogFrame(fmlgKindNodeState, rec); err != nil {
			return err
		}
	}
	end := fmlgAppendEnd(nil, fmlgEnd{
		endOffset:  fs.logOff + fmlgFrameSize(fmlgEndPayloadSize),
		frameCount: fs.logSeq + 1,
		reason:     reason,
	})
	if err := fs.appendLogFrame(fmlgKindEnd, end); err != nil {
		return err
	}
	fs.logSealed = true
	return nil
}
