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
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// FMLG ("File Mutation LoG") is the wire format emitted by FSMutationLogWrite. Rather than a
// coalesced state diff, it is an ordered journal of the operations that mutated the overlay
// upper: the consumer replays the records against an inode-keyed tree to reconstruct the
// upper's state.
//
// Records are keyed by inode number (which gVisor never reuses), so a rename is a single
// record that re-points one tree edge and structural ordering is the only invariant.
// CREATE_WITH_STATE and NODESTATE carry inode metadata and data layout. The
// consumer applies each state update in journal order, keyed by inode number.
//
// FMLG v2 uses the framed format specified in g3doc/fmlg-v2.md. Mutation
// frames each carry one record, whose tag is in the frame header. CREATE_WITH_STATE
// includes the initial inode state; NODESTATE carries subsequent updates.
const (
	fmlgMagic           = "FMLG"
	fmlgVersion         = uint16(2)
	fmlgHeaderSize      = 32
	fmlgFrameHeaderSize = 24
	fmlgFailureOffset   = 24
)

// Tag 0 is reserved for the legacy CREATE without inode state. Tags are
// explicit so a record's meaning cannot change when another kind is added.
const (
	fmlgKindRename          uint32 = 1
	fmlgKindUnlink          uint32 = 2
	fmlgKindNodeState       uint32 = 3
	fmlgKindCreateWithState uint32 = 4
	fmlgKindBegin           uint32 = 5
	fmlgKindEnd             uint32 = 6
)

const (
	fmlgEndSnapshot uint64 = iota
	fmlgEndGracefulExit
)

const (
	fmlgFailureNone uint64 = iota
	fmlgFailureOverflow
	fmlgFailureIO
)

var fmlgCRC = crc32.MakeTable(crc32.Castagnoli)

func fmlgFrameSize(payloadLen uint64) uint64 {
	return (fmlgFrameHeaderSize + payloadLen + 7) &^ 7
}

// fmlgStore publishes aligned little-endian words on the sentry's supported
// little-endian amd64 and arm64 hosts. Sequentially consistent stores order
// invalidation before overwrites and publication after the payload copy.
func fmlgStore(b []byte, value uint64) {
	(*atomicbitops.Uint64)(unsafe.Pointer(&b[0])).Store(value)
}

// appendLogFrame commits a frame at logOff. All offsets and mappings are
// 8-byte aligned. Readers require a stable copy or a dead sentry.
//
// Preconditions: logMu locked; journal mapped; writers quiesced or serialized.
func (fs *filesystem) appendLogFrame(kind uint32, payload []byte) error {
	// The 64 MiB journal cap bounds frames well below 2^32; guard the wire
	// conversion independently in case that cap changes.
	if fs.logSeq > uint64(^uint32(0)) {
		return fmt.Errorf("fsmutationlog: frame sequence overflow")
	}
	end := fs.logOff + fmlgFrameSize(uint64(len(payload)))
	if uint64(len(payload)) > uint64(^uint32(0)) || end < fs.logOff {
		return fmt.Errorf("fsmutationlog: frame too large")
	}
	if err := fs.ensureLogCap(end); err != nil {
		return err
	}
	frame := fs.logMapping[fs.logOff:end]
	fmlgStore(frame, 0)
	var header [fmlgFrameHeaderSize]byte
	binary.LittleEndian.PutUint64(header[0:], fs.logGen.Load())
	binary.LittleEndian.PutUint32(header[8:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[12:], kind)
	binary.LittleEndian.PutUint32(header[16:], uint32(fs.logSeq))
	crc := crc32.Update(0, fmlgCRC, header[:20])
	crc = crc32.Update(crc, fmlgCRC, payload)
	binary.LittleEndian.PutUint32(header[20:], crc)
	copy(frame[8:], header[8:])
	copy(frame[fmlgFrameHeaderSize:], payload)
	clear(frame[fmlgFrameHeaderSize+len(payload):])
	fmlgStore(frame, fs.logGen.Load())
	fs.logOff = end
	fs.logSeq++
	return nil
}

// File types carried by CREATE_WITH_STATE.
const (
	fmlgTypeReg uint8 = iota
	fmlgTypeDir
	fmlgTypeSymlink
	fmlgTypeDevice
)

// Low-level little-endian appenders. They build records into a reused scratch slice so a
// mutation site can append with no allocation in the common case.

func fmlgU8(b []byte, v uint8) []byte   { return append(b, v) }
func fmlgU32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func fmlgU64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }
func fmlgI64(b []byte, v int64) []byte  { return binary.LittleEndian.AppendUint64(b, uint64(v)) }
func fmlgStr(b []byte, s string) []byte { b = fmlgU32(b, uint32(len(s))); return append(b, s...) }
func fmlgBytes(b []byte, v []byte) []byte {
	b = fmlgU32(b, uint32(len(v)))
	return append(b, v...)
}

// fmlgFtype reports the CREATE ftype for in, or ok=false for types the snapshot does not
// materialize (named pipes, sockets), which are not journaled.
func fmlgFtype(in *inode) (uint8, bool) {
	switch in.impl.(type) {
	case *regularFile:
		return fmlgTypeReg, true
	case *directory:
		return fmlgTypeDir, true
	case *symlink:
		return fmlgTypeSymlink, true
	case *deviceFile:
		return fmlgTypeDevice, true
	default:
		return 0, false
	}
}

// fmlgHeader is written once, before the first epoch.
func fmlgHeader(b []byte, rootIno uint64) []byte {
	b = append(b, fmlgMagic...)
	b = binary.LittleEndian.AppendUint16(b, fmlgVersion)
	b = binary.LittleEndian.AppendUint16(b, 0) // flags
	b = fmlgU64(b, rootIno)
	b = fmlgU64(b, 1) // initial epoch
	b = fmlgU64(b, fmlgFailureNone)
	return b
}

// fmlgAppendCreateWithState encodes a directory entry and its initial inode state.
// The inode number is encoded once; there is no nested NODESTATE record.
//
// Preconditions: filesystem.mu locked; child not a pipe/socket (caller checked ftype).
func fmlgAppendCreateWithState(b []byte, parentIno uint64, name string, child *dentry, ftype uint8) []byte {
	in := child.inode
	b = fmlgU64(b, in.ino)
	b = fmlgU64(b, parentIno)
	b = fmlgStr(b, name)
	b = fmlgU8(b, ftype)
	switch impl := in.impl.(type) {
	case *symlink:
		b = fmlgStr(b, impl.target)
	case *deviceFile:
		b = fmlgU32(b, impl.major)
		b = fmlgU32(b, impl.minor)
	}
	return fmlgAppendInodeState(b, in)
}

// fmlgAppendRename appends a RENAME record moving ino from (oldParentIno, oldName) to
// (newParentIno, newName).
func fmlgAppendRename(b []byte, ino, oldParentIno uint64, oldName string, newParentIno uint64, newName string) []byte {
	b = fmlgU64(b, ino)
	b = fmlgU64(b, oldParentIno)
	b = fmlgStr(b, oldName)
	b = fmlgU64(b, newParentIno)
	b = fmlgStr(b, newName)
	return b
}

// fmlgAppendUnlink appends an UNLINK record removing the (parentIno, name) edge.
func fmlgAppendUnlink(b []byte, ino, parentIno uint64, name string) []byte {
	b = fmlgU64(b, ino)
	b = fmlgU64(b, parentIno)
	b = fmlgStr(b, name)
	return b
}

// fmlgAppendNodeState appends a NODESTATE record with in's current metadata, regular-file
// data layout, and xattrs. size/segments are emitted only for regular files; nlink is
// omitted deliberately — the consumer's replayed edge set is authoritative (a regular
// file's nlink is its link count), and a symlink's size is derived from the CREATE
// record's target.
//
// Preconditions: the kernel is paused and quiesced (so in's fields are stable), or the
// caller otherwise guarantees no concurrent mutation of in.
func fmlgAppendNodeState(b []byte, in *inode) []byte {
	b = fmlgU64(b, in.ino)
	return fmlgAppendInodeState(b, in)
}

// fmlgAppendInodeState encodes the state shared by CREATE_WITH_STATE and NODESTATE.
// Preconditions: in's metadata is stable, as required by fmlgAppendNodeState.
func fmlgAppendInodeState(b []byte, in *inode) []byte {
	b = fmlgU32(b, in.mode.Load())
	b = fmlgU32(b, in.uid.Load())
	b = fmlgU32(b, in.gid.Load())
	b = fmlgI64(b, in.mtime.Load()/1e9) // seconds, matching the tar path
	if rf, ok := in.impl.(*regularFile); ok {
		rf.dataMu.RLock()
		b = fmlgU64(b, rf.size.RacyLoad())
		nsegAt := len(b)
		b = fmlgU32(b, 0) // segment count placeholder, patched below
		var nseg uint32
		for seg := rf.data.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			b = fmlgU64(b, seg.Start())
			b = fmlgU64(b, seg.End())
			b = fmlgU64(b, seg.Value())
			nseg++
		}
		rf.dataMu.RUnlock()
		binary.LittleEndian.PutUint32(b[nsegAt:], nseg)
	} else {
		// Non-regular files have no content channel; their size field stays 0 (display-only).
		b = fmlgU64(b, 0) // size
		b = fmlgU32(b, 0) // nseg
	}
	xattrs := in.xattrs.RawXattrs()
	b = fmlgU32(b, uint32(len(xattrs)))
	for k, v := range xattrs {
		b = fmlgStr(b, k)
		b = fmlgBytes(b, []byte(v))
	}
	return b
}
