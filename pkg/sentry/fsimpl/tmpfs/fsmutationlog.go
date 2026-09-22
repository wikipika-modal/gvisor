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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ErrMutationLogOverflowed is the terminal error of a journaled mount: once a generation's
// buffered records exceed logBufCap, tracking is permanently disabled (logFailed) and every
// subsequent FSMutationLogWrite fails with this error. The consumer should stop draining the
// log and fall back to a full-walk snapshot.
var ErrMutationLogOverflowed = errors.New("fsmutationlog: mutation log overflowed; tracking disabled")

// logBufCap bounds the bytes of records (structural + content) journaled in one incremental
// generation. Exceeding it fails the log: since records are dropped from that point on, no
// later segment can be consistent, so the failure is terminal. It is a var so tests can
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
	if err := fs.writeLogAt(fmlgHeader(nil, fs.root.inode.ino), 0); err != nil {
		return err
	}
	fs.logGen.Store(1)
	fs.logOff = fmlgHeaderSize
	return fs.appendLogFrame(fmlgKindBegin, fmlgU64(nil, 0))
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

func (fs *filesystem) mutationLogError() error {
	if fs.logFailure == fmlgFailureOverflow {
		return ErrMutationLogOverflowed
	}
	return fmt.Errorf("fsmutationlog: journal failed (status %d)", fs.logFailure)
}

// FSMutationLogWrite seals one epoch and returns its generation and length.
// The caller must capture the journal and filestore before resuming writers.
// sinceGen must match the last successful drain; there is no full baseline.
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
	fs.lastEmittedLogGen = fs.logGen.Load()
	return fs.lastEmittedLogGen, fs.logOff, nil
}

// FinalizeFSMutationLog seals a graceful-exit epoch and trims the backing file
// to the committed prefix. It must run before inode destruction. Other tmpfs
// mounts (including restored mounts) are ignored. Repeated calls are harmless.
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
		if rf, ok := in.impl.(*regularFile); !ok || !rf.hasWritableMapping() {
			delete(fs.mmapWritable, in)
		}
	}
	var rec []byte
	for in := range tracked {
		rec = fmlgAppendNodeState(rec[:0], in)
		if err := fs.appendLogFrame(fmlgKindNodeState, rec); err != nil {
			return err
		}
	}
	end := fmlgU64(nil, fs.logOff+fmlgFrameSize(24))
	end = fmlgU64(end, fs.logSeq+1) // includes BEGIN and END
	end = fmlgU64(end, reason)
	if err := fs.appendLogFrame(fmlgKindEnd, end); err != nil {
		return err
	}
	fs.logSealed = true
	return nil
}
