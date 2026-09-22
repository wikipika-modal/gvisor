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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// This file exercises the mutation log (fsmutationlog.go / fsmutationlog_fmlg.go). It
// reuses the fsIndexTest harness, which issues real tmpfs operations, then replays each
// emitted FMLG segment into an inode-keyed tree exactly as the modal-runtime consumer
// will -- so the tests validate both the wire format and the replay semantics. Unlike the
// FFIX index (a coalesced state diff), the log is replayed cumulatively: assertions are
// on the reconstructed upper, so a deleted path is simply absent (not a whiteout), and
// only overlay whiteout devices flatten to whiteouts.

func TestFSMutationLogACLMode(t *testing.T) {
	for _, viaFD := range []bool{false, true} {
		name := "path"
		if viaFD {
			name = "fd"
		}
		t.Run(name, func(t *testing.T) {
			h := newFSIndexTest(t)
			h.mkdirAll("dir")
			h.chmod("dir", 0o750)
			ino := h.inoOf("dir")
			st := newFMLGState()
			previous := h.writeLog(0, st).gen
			fd := h.openReadonly("dir")
			defer fd.DecRef(h.ctx)

			for _, change := range []struct {
				name string
				mask vfs.AccessTypes
				mode uint32
			}{
				// An extended ACL changes stat's group bits from r-x to rwx.
				{"set", vfs.MayRead | vfs.MayWrite | vfs.MayExec, 0o770},
				// Replacing only the ACL must update an already-captured inode.
				{"replace", vfs.MayRead, 0o740},
				// Removing the ACL retains the mode, but still journals the change.
				{"remove", 0, 0o740},
			} {
				t.Run(change.name, func(t *testing.T) {
					acl := &vfs.PosixACL{UGOPerms: 0o750, Mask: &change.mask}
					if change.name == "remove" {
						acl = nil
					}
					var err error
					if viaFD {
						_, _, err = fd.SetPosixACL(h.ctx, vfs.AccessACL, acl, false)
					} else {
						// Overlay forwards setfacl to this VFS entry point on its upper.
						_, _, err = h.vfsObj.SetPosixACLAt(h.ctx, h.creds, h.pop("dir"), vfs.AccessACL, acl, false)
					}
					if err != nil {
						t.Fatal(err)
					}
					previous = h.writeLog(previous, st).gen
					segment, err := scanFMLG(readFMLG(t, h))
					if err != nil {
						t.Fatal(err)
					}
					if len(segment.frames) != 3 || segment.frames[1].kind != fmlgKindNodeState {
						t.Fatalf("want BEGIN, NODESTATE, END; got %v", segment.frames)
					}
					payload := segment.frames[1].payload
					if got := binary.LittleEndian.Uint64(payload); got != ino {
						t.Errorf("NODESTATE inode = %d, want %d", got, ino)
					}
					if got, want := binary.LittleEndian.Uint32(payload[8:]), uint32(linux.ModeDirectory)|change.mode; got != want {
						t.Errorf("NODESTATE mode = %#o, want %#o", got, want)
					}
				})
			}
		})
	}
}

// TestFSMutationLogBaseline checks that the first segment -- an ordinary incremental drain
// of the log accumulated since filesystem creation -- still reconstructs the whole tree.
func TestFSMutationLogBaseline(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f1", "a")
	fs.put("f2", "b")
	fs.mkdirAll("d")
	fs.put("d/g", "c")

	base := fs.writeLog(0, st)
	base.wantPresent("./f1", "./f2", "./d", "./d/g")
}

// TestFSMutationLogInterleavedRenameRecreate is the motivating example: within one
// interval, write into a directory, rename it away, recreate a fresh directory at the old
// name, and write into that. Replaying the ordered log must land every entry at its final
// path -- the case that forces the FFIX index into subtree-flattening + tombstone
// suppression, here handled by construction.
func TestFSMutationLogInterleavedRenameRecreate(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	// Baseline: d1 with a prior child.
	fs.mkdirAll("d1")
	fs.put("d1/a", "a")
	base := fs.writeLog(0, st)
	base.wantPresent("./d1", "./d1/a")

	// write d1/y ; mv d1 d2 ; mkdir d1 ; write d1/x
	fs.put("d1/y", "y")
	fs.rename("d1", "d2")
	fs.mkdirAll("d1")
	fs.put("d1/x", "x")

	delta := fs.writeLog(base.gen, st)
	// The prior subtree moved wholesale to d2; a fresh d1 holds only x.
	delta.wantPresent("./d2", "./d2/a", "./d2/y", "./d1", "./d1/x")
	delta.wantAbsent("./d1/a", "./d1/y")
}

// TestFSMutationLogRenameDirectoryWithChild renames a directory holding a nested subtree.
// A single RENAME record re-points one edge; replay moves the whole subtree, so every
// descendant reappears at its new path with no per-descendant records.
func TestFSMutationLogRenameDirectoryWithChild(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.mkdirAll("d1/sub")
	fs.put("d1/x", "data")
	fs.put("d1/sub/y", "data")
	base := fs.writeLog(0, st)
	base.wantPresent("./d1", "./d1/x", "./d1/sub", "./d1/sub/y")

	fs.rename("d1", "d2")

	delta := fs.writeLog(base.gen, st)
	delta.wantPresentOnce("./d2", "./d2/x", "./d2/sub", "./d2/sub/y")
	delta.wantAbsent("./d1", "./d1/x", "./d1/sub", "./d1/sub/y")
}

// TestFSMutationLogDeleteRecreate deletes and recreates a path in one interval. The log
// records UNLINK then CREATE; replay ends with the fresh file present and no whiteout.
func TestFSMutationLogDeleteRecreate(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "v0")
	base := fs.writeLog(0, st)
	base.wantPresent("./f")

	fs.delete("f")
	fs.put("f", "v1")

	delta := fs.writeLog(base.gen, st)
	delta.wantPresentOnce("./f")
	delta.wantNoWhiteout("./f")
}

// TestFSMutationLogUnlinkIsAbsent checks that a plain deletion leaves the path absent (the
// log has no tombstones -- an UNLINK just drops the edge).
func TestFSMutationLogUnlinkIsAbsent(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("keep", "x")
	fs.put("gone", "x")
	base := fs.writeLog(0, st)
	base.wantPresent("./keep", "./gone")

	fs.delete("gone")
	delta := fs.writeLog(base.gen, st)
	delta.wantPresent("./keep")
	delta.wantAbsent("./gone")
	delta.wantNoWhiteout("./gone")
}

// TestFSMutationLogRenameOverExisting renames a over an existing b. Replay drops the
// replaced b and moves a into its place; b holds a's content and a is absent.
func TestFSMutationLogRenameOverExisting(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("a", "a-data")
	fs.put("b", "b-data")
	base := fs.writeLog(0, st)
	base.wantPresent("./a", "./b")

	fs.rename("a", "b")

	delta := fs.writeLog(base.gen, st)
	delta.wantPresentOnce("./b")
	delta.wantAbsent("./a")
}

// TestFSMutationLogRenameAcrossDirectories moves a file between directories.
func TestFSMutationLogRenameAcrossDirectories(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.mkdirAll("src")
	fs.mkdirAll("dst")
	fs.put("src/f", "data")
	base := fs.writeLog(0, st)
	base.wantPresent("./src", "./dst", "./src/f")

	fs.rename("src/f", "dst/f")

	delta := fs.writeLog(base.gen, st)
	delta.wantPresentOnce("./dst/f")
	delta.wantAbsent("./src/f")
}

func TestFSMutationLogRenameExchange(t *testing.T) {
	for _, kinds := range [][2]string{{"file", "file"}, {"dir", "dir"}, {"file", "dir"}, {"symlink", "file"}, {"file", "hardlink"}, {"pipe", "file"}, {"file", "pipe"}, {"pipe", "pipe"}} {
		for _, across := range []bool{false, true} {
			for _, incremental := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s-%s/across=%t/incremental=%t", kinds[0], kinds[1], across, incremental), func(t *testing.T) {
					h := newFSIndexTest(t)
					st := newFMLGState()
					oldParent, newParent := "src", "src"
					if across {
						newParent = "dst"
					}
					h.mkdirAll(oldParent)
					h.mkdirAll(newParent)
					oldPath, newPath := oldParent+"/a", newParent+"/b"
					// A guest entry must not collide with the journal's temporary name.
					collision := oldParent + "/.fsmutationlog-exchange-0"
					h.put(collision, "keep")
					want := map[string]uint64{collision: h.inoOf(collision)}
					for i, path := range []string{oldPath, newPath} {
						other := newPath
						if i == 1 {
							other = oldPath
						}
						switch kinds[i] {
						case "file":
							h.put(path, path)
						case "dir":
							h.mkdirAll(path + "/sub")
							h.put(path+"/sub/child", path)
							want[other+"/sub"] = h.inoOf(path + "/sub")
							want[other+"/sub/child"] = h.inoOf(path + "/sub/child")
						case "symlink":
							h.symlink(path, "target")
						case "hardlink":
							h.hardlink(oldPath, path)
						case "pipe":
							if err := h.vfsObj.MknodAt(h.ctx, h.creds, h.pop(path), &vfs.MknodOptions{Mode: linux.S_IFIFO | 0o600}); err != nil {
								t.Fatal(err)
							}
							continue
						}
						want[other] = h.inoOf(path)
					}
					var since uint64
					if incremental {
						since = h.writeLog(0, st).gen
					}
					if err := h.vfsObj.RenameAt(h.ctx, h.creds, h.pop(oldPath), h.pop(newPath), &vfs.RenameOptions{Flags: linux.RENAME_EXCHANGE}); err != nil {
						t.Fatal(err)
					}
					captured := h.writeLog(since, st)
					for path, ino := range want {
						captured.wantPresentOnce("./" + path)
						got := st.rootIno
						for _, part := range strings.Split(path, "/") {
							got = st.children[got][part]
						}
						if got != ino || got != h.inoOf(path) {
							t.Errorf("%s: replayed inode = %d, want %d", path, got, ino)
						}
					}
					for path := range captured.present {
						if path != "." && path != "./src" && path != "./dst" {
							if _, ok := want[strings.TrimPrefix(path, "./")]; !ok {
								t.Errorf("unexpected replayed path %q", path)
							}
						}
					}
				})
			}
		}
	}
}

// TestFSMutationLogWhiteoutDevice checks the overlay `mv` case: renaming the upper file
// and dropping a whiteout device at the origin flattens to a live entry at the new path
// and exactly one whiteout at the old.
func TestFSMutationLogWhiteoutDevice(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "data")
	base := fs.writeLog(0, st)
	base.wantPresent("./f")

	fs.rename("f", "g")
	fs.whiteout("f")

	delta := fs.writeLog(base.gen, st)
	delta.wantPresentOnce("./g")
	delta.wantWhiteoutOnce("./f")
}

// TestFSMutationLogEntryKinds puts one of every journaled kind into a segment and checks
// they all round-trip through replay (this also confirms the CREATE tail encodings for
// symlink target and device numbers parse correctly).
func TestFSMutationLogEntryKinds(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("reg", "data")
	fs.mkdirAll("dir")
	fs.symlink("sym", "reg")
	fs.hardlink("reg", "hard") // second name for reg's inode

	base := fs.writeLog(0, st)
	base.wantPresent("./reg", "./dir", "./sym", "./hard")
}

// TestFSMutationLogSkipsPipesAndSockets checks that pipes and sockets, whose creation is
// not journaled, are never named by a RENAME or UNLINK either, while the regular files they
// replace or are replaced by are still journaled.
func TestFSMutationLogSkipsPipesAndSockets(t *testing.T) {
	for _, mode := range []linux.FileMode{linux.S_IFIFO, linux.S_IFSOCK} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			h := newFSIndexTest(t)
			st := newFMLGState()
			mknod := func(path string) uint64 {
				if err := h.vfsObj.MknodAt(h.ctx, h.creds, h.pop(path), &vfs.MknodOptions{Mode: mode | 0o600}); err != nil {
					t.Fatal(err)
				}
				return h.inoOf(path)
			}

			h.put("f", "f")
			h.put("g", "g")
			first := mknod("p")
			fIno, gIno := h.inoOf("f"), h.inoOf("g")
			base := h.writeLog(0, st)
			base.wantPresent("./f", "./g")

			h.rename("p", "q")
			h.rename("q", "f")
			h.delete("f")
			second := mknod("p")
			h.rename("g", "p")

			delta := h.writeLog(base.gen, st)
			delta.wantPresentOnce("./p")
			delta.wantAbsent("./f", "./g", "./q")
			s, err := scanFMLG(readFMLG(t, h))
			if err != nil {
				t.Fatal(err)
			}
			var unlinkedF, renamedG bool
			for _, frame := range s.frames {
				if frame.kind != fmlgKindRename && frame.kind != fmlgKindUnlink {
					continue
				}
				switch ino := binary.LittleEndian.Uint64(frame.payload); ino {
				case first, second:
					t.Errorf("record kind %d names unjournaled inode %d", frame.kind, ino)
				case fIno:
					unlinkedF = unlinkedF || frame.kind == fmlgKindUnlink
				case gIno:
					renamedG = renamedG || frame.kind == fmlgKindRename
				}
			}
			if !unlinkedF || !renamedG {
				t.Errorf("UNLINK of f journaled = %t, RENAME of g journaled = %t; want both", unlinkedF, renamedG)
			}
		})
	}
}

// TestFSMutationLogGenerationMismatchFails checks that asking for changes since a
// generation the log never handed out fails (there is no full baseline to resync from), and
// that a correctly-cursored drain still succeeds afterwards.
func TestFSMutationLogGenerationMismatchFails(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("a", "a")
	base := fs.writeLog(0, st)

	fs.put("b", "b")

	if _, _, err := FSMutationLogWrite(fs.ctx, fs.fs, base.gen+999); err == nil {
		t.Fatalf("FSMutationLogWrite(sinceGen=%d): got nil error, want a mismatch error", base.gen+999)
	}
	// The rejected drain consumed nothing: the matching one succeeds.
	delta := fs.writeLog(base.gen, st)
	delta.wantPresent("./b")
}

// TestFSMutationLogOverflowFails checks the memory bound: once a generation buffers more
// than the cap, the log fails permanently -- the drain and every later drain return
// ErrMutationLogOverflowed and appending stops, so the consumer must fall back.
func TestFSMutationLogOverflowFails(t *testing.T) {
	orig := logBufCap
	logBufCap = 400 // a handful of CREATE+NODESTATE pairs overflow the cap
	t.Cleanup(func() { logBufCap = orig })

	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("seed", "x")
	base := fs.writeLog(0, st)

	for _, name := range []string{"a", "b", "c", "d", "e"} {
		fs.put(name, "x")
	}

	if _, _, err := FSMutationLogWrite(fs.ctx, fs.fs, base.gen); !errors.Is(err, ErrMutationLogOverflowed) {
		t.Fatalf("FSMutationLogWrite after overflow: got %v, want ErrMutationLogOverflowed", err)
	}
	// The failure is terminal: appends are dropped and drains keep failing.
	fs.put("f", "x")
	if _, _, err := FSMutationLogWrite(fs.ctx, fs.fs, base.gen); !errors.Is(err, ErrMutationLogOverflowed) {
		t.Fatalf("FSMutationLogWrite after terminal failure: got %v, want ErrMutationLogOverflowed", err)
	}
}

// TestFSMutationLogMmapReemitsNodeState checks the mmap gap: a file with a live writable
// shared mapping bypasses the write path, so the log forces a fresh NODESTATE for it on
// every delta while the mapping is live, once more after unmap, and not after that.
func TestFSMutationLogMmapReemitsNodeState(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("db", "seed")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("db")

	m := fs.mapWritable("db")
	first := fs.writeLog(base.gen, st)
	if st.nodeStates[ino] == 0 {
		t.Errorf("mapped file: no NODESTATE re-emitted in first delta")
	}
	second := fs.writeLog(first.gen, st)
	if st.nodeStates[ino] == 0 {
		t.Errorf("mapped file: no NODESTATE re-emitted in second delta")
	}

	m.unmap()
	final := fs.writeLog(second.gen, st)
	if st.nodeStates[ino] == 0 {
		t.Errorf("unmapped file: expected one final NODESTATE")
	}
	fs.writeLog(final.gen, st)
	if st.nodeStates[ino] != 0 {
		t.Errorf("quiescent file: unexpected NODESTATE after unmap")
	}
}

// TestFSMutationLogWriteWhileOpenDrained checks that a file written while it stays open for
// write gets an exact, up-to-date NODESTATE at every drain (live mutation channels are
// folded at the pause), and that the writes themselves produce no records: exactly one
// NODESTATE per drain.
func TestFSMutationLogWriteWhileOpenDrained(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "v0")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fd := fs.openForWrite("f")
	fs.writeTo(fd, "12345")
	first := fs.writeLog(base.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("drain while open: got %d NODESTATEs, want exactly 1", got)
	}
	if got := st.sizes[ino]; got != 5 {
		t.Errorf("drain while open: size = %d, want 5", got)
	}
	first.wantPresent("./f")

	// More writes, still no close: the next drain catches up again.
	fs.writeTo(fd, "abcdefgh") // offsets 5..12
	second := fs.writeLog(first.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("second drain while open: got %d NODESTATEs, want exactly 1", got)
	}
	if got := st.sizes[ino]; got != 13 {
		t.Errorf("second drain while open: size = %d, want 13", got)
	}

	// Closing emits one final NODESTATE during execution; later drains emit nothing.
	fs.closeFd(fd)
	third := fs.writeLog(second.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("drain at close: got %d NODESTATEs, want exactly 1", got)
	}
	third.wantPresent("./f")
	fs.writeLog(third.gen, st)
	if got := st.nodeStates[ino]; got != 0 {
		t.Errorf("after close: got %d NODESTATEs, want 0", got)
	}
}

// TestFSMutationLogCloseEmitsNodeState checks that a file written and closed within a
// generation produces exactly one content record -- at close (writes through an open
// description are journaled lazily, not per write).
func TestFSMutationLogCloseEmitsNodeState(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "v0")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fd := fs.openForWrite("f")
	fs.writeTo(fd, "12345678")
	fs.closeFd(fd)

	delta := fs.writeLog(base.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("write+close in one generation: got %d NODESTATEs, want exactly 1 (at close)", got)
	}
	if got := st.sizes[ino]; got != 8 {
		t.Errorf("close NODESTATE: size = %d, want 8", got)
	}
	delta.wantPresentOnce("./f")
}

// TestFSMutationLogOpenForWriteRefcount checks that the open-for-write set counts writable
// descriptions per inode: the file stays covered (a drain emits) until the last one closes.
func TestFSMutationLogOpenForWriteRefcount(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "x")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fd1 := fs.openForWrite("f")
	fd2 := fs.openForWrite("f")
	fs.writeTo(fd1, "11")
	d1 := fs.writeLog(base.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("two writers, one wrote: got %d NODESTATEs, want 1", got)
	}

	// Closing one of two descriptions emits nothing and keeps the file covered.
	fs.closeFd(fd1)
	d2 := fs.writeLog(d1.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("one writer left: got %d NODESTATEs, want 1 (still open)", got)
	}

	// The last close emits exactly one NODESTATE.
	fs.writeTo(fd2, "2222")
	fs.closeFd(fd2)
	d3 := fs.writeLog(d2.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("last close: got %d NODESTATEs, want exactly 1", got)
	}
	d3.wantPresent("./f")
	fs.writeLog(d3.gen, st)
	if got := st.nodeStates[ino]; got != 0 {
		t.Errorf("everything closed: got %d NODESTATEs, want 0", got)
	}
}

// TestFSMutationLogReadonlyOpenNotTracked checks that read-only opens never enter the
// open-for-write set (and so produce no drain-time NODESTATEs, and none at close either).
func TestFSMutationLogReadonlyOpenNotTracked(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "xyz")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fd := fs.openReadonly("f")
	d1 := fs.writeLog(base.gen, st)
	if got := st.nodeStates[ino]; got != 0 {
		t.Errorf("read-only open: got %d NODESTATEs, want 0", got)
	}

	fs.closeFd(fd)
	d2 := fs.writeLog(d1.gen, st)
	if got := st.nodeStates[ino]; got != 0 {
		t.Errorf("read-only close: got %d NODESTATEs, want 0", got)
	}
	d2.wantPresent("./f") // unchanged by any of this
}

func TestFSMutationLogReadonlyTruncate(t *testing.T) {
	for _, incremental := range []bool{false, true} {
		for _, closeBeforeCapture := range []bool{false, true} {
			t.Run(fmt.Sprintf("incremental=%t/closed=%t", incremental, closeBeforeCapture), func(t *testing.T) {
				h := newFSIndexTest(t)
				st := newFMLGState()
				h.put("f", "contents before truncation")
				ino := h.inoOf("f")
				var since uint64
				if incremental {
					since = h.writeLog(0, st).gen
				}
				fd, err := h.vfsObj.OpenAt(h.ctx, h.creds, h.pop("f"), &vfs.OpenOptions{
					Flags: linux.O_RDONLY | linux.O_TRUNC,
				})
				if err != nil {
					t.Fatal(err)
				}
				if closeBeforeCapture {
					fd.DecRef(h.ctx)
				} else {
					defer fd.DecRef(h.ctx)
				}
				captured := h.writeLog(since, st)
				captured.wantPresentOnce("./f")
				if got := st.sizes[ino]; got != 0 {
					t.Errorf("replayed size = %d, want 0", got)
				}
				h.writeLog(captured.gen, st)
				if got := st.nodeStates[ino]; got != 0 {
					t.Errorf("unchanged read-only file emitted %d NODESTATEs", got)
				}
			})
		}
	}
}

// TestFSMutationLogUnlinkedButOpen checks that a file unlinked while still open for write
// keeps its state journaled to the end (NODESTATE at close), and is simply absent from the
// reconstructed tree.
func TestFSMutationLogUnlinkedButOpen(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "x")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fd := fs.openForWrite("f")
	fs.delete("f")
	fs.writeTo(fd, "more") // through the still-open description
	fs.closeFd(fd)

	delta := fs.writeLog(base.gen, st)
	delta.wantAbsent("./f")
	delta.wantNoWhiteout("./f")
	if got := st.nodeStates[ino]; got == 0 {
		t.Error("unlinked-but-open file: no NODESTATE journaled for the dropped write")
	}
	if got := st.sizes[ino]; got != 4 {
		t.Errorf("unlinked-but-open file: size = %d, want 4", got)
	}
}

// TestFSMutationLogSetStatEmitsNodeState checks that a metadata-only change with no open
// file description (chmod on a path) still journals a NODESTATE immediately.
func TestFSMutationLogSetStatEmitsNodeState(t *testing.T) {
	fs := newFSIndexTest(t)
	st := newFMLGState()

	fs.put("f", "data")
	base := fs.writeLog(0, st)
	ino := fs.inoOf("f")

	fs.chmod("f", 0o600)
	delta := fs.writeLog(base.gen, st)
	if got := st.nodeStates[ino]; got != 1 {
		t.Errorf("chmod: got %d NODESTATEs, want exactly 1", got)
	}
	delta.wantPresentOnce("./f")
}

// writeLog drains an FMLG segment for the changes since sinceGen, replays it into st, and
// returns an index result (reusing the shared assertion helpers) built from the
// reconstructed tree.
//
// It exercises the real host-file path: the mount adopted a persistent temp file at creation
// (see newFSIndexTest) and memcpy'd records into it during the harness mutations.
// The drain re-emits mmap-tracked files and writes the header; the segment is read back
// from [0, length).
func (h *fsIndexTest) writeLog(sinceGen uint64, st *fmlgState) index {
	h.t.Helper()
	gen, length, err := FSMutationLogWrite(h.ctx, h.fs, sinceGen)
	if err != nil {
		h.t.Fatalf("FSMutationLogWrite(sinceGen=%d): %v", sinceGen, err)
	}
	buf := make([]byte, length)
	if length > 0 {
		f, err := os.Open(h.logPath)
		if err != nil {
			h.t.Fatalf("open log file: %v", err)
		}
		defer f.Close()
		if _, err := f.ReadAt(buf, 0); err != nil {
			h.t.Fatalf("read log segment [0,%d): %v", length, err)
		}
	}
	st.apply(h.t, buf)
	present, whiteouts := st.flatten()
	return index{t: h.t, gen: gen, present: present, whiteouts: whiteouts}
}

// inoOf returns the inode number of the entry at path.
func (h *fsIndexTest) inoOf(path string) uint64 {
	h.t.Helper()
	tfs := h.fs.Impl().(*filesystem)
	tfs.mu.RLock()
	defer tfs.mu.RUnlock()
	return h.lookupLocked(tfs, path).inode.ino
}

// fmlgNode is a replayed node: its structural identity plus (for whiteout detection) the
// device numbers a CREATE carried.
type fmlgNode struct {
	ftype        uint8
	major, minor uint32
}

// fmlgState is the consumer-side inode tree a sequence of FMLG segments replays into. It
// mirrors what the modal-runtime consumer maintains.
type fmlgState struct {
	rootIno  uint64
	nodes    map[uint64]*fmlgNode
	children map[uint64]map[string]uint64 // parentIno -> name -> childIno

	// nodeStates counts NODESTATE records seen for each inode in the most recently
	// applied segment (reset per apply), so a test can assert on mmap re-emission.
	nodeStates map[uint64]int

	// sizes is the file size carried by the most recent NODESTATE for each inode,
	// persisted across applies, so a test can assert content recency.
	sizes map[uint64]uint64
}

func newFMLGState() *fmlgState {
	return &fmlgState{
		nodes:      map[uint64]*fmlgNode{},
		children:   map[uint64]map[string]uint64{},
		nodeStates: map[uint64]int{},
		sizes:      map[uint64]uint64{},
	}
}

func (s *fmlgState) edge(parentIno uint64) map[string]uint64 {
	m := s.children[parentIno]
	if m == nil {
		m = map[string]uint64{}
		s.children[parentIno] = m
	}
	return m
}

// apply replays one FMLG segment into s.
func (s *fmlgState) apply(t *testing.T, b []byte) {
	t.Helper()
	s.nodeStates = map[uint64]int{}
	segment, err := scanFMLG(b)
	if err != nil || !segment.ended || segment.failure != 0 {
		t.Fatalf("invalid complete FMLG segment: %+v, %v", segment, err)
	}
	rootIno := segment.root
	// The root is implicit in the header on every segment; seed it and record rootIno
	// unconditionally, since the first segment is now an ordinary incremental one that
	// reconstructs the tree from empty.
	s.rootIno = rootIno
	if s.nodes == nil {
		s.nodes = map[uint64]*fmlgNode{}
	}
	if s.nodes[rootIno] == nil {
		s.nodes[rootIno] = &fmlgNode{ftype: fmlgTypeDir}
	}

	for _, frame := range segment.frames {
		if frame.kind == fmlgKindBegin || frame.kind == fmlgKindEnd {
			continue
		}
		b := frame.payload
		pos := 0
		u32 := func() uint32 { v := binary.LittleEndian.Uint32(b[pos:]); pos += 4; return v }
		u64 := func() uint64 { v := binary.LittleEndian.Uint64(b[pos:]); pos += 8; return v }
		str := func() string {
			n := int(u32())
			v := string(b[pos : pos+n])
			pos += n
			return v
		}

		readState := func(ino uint64) {
			pos += 4 + 4 + 4 + 8 // mode, uid, gid, mtimeSec
			s.sizes[ino] = u64() // size
			nseg := int(u32())
			pos += nseg * 24
			for nx := int(u32()); nx > 0; nx-- {
				pos += int(u32()) // key
				pos += int(u32()) // value
			}
		}
		switch frame.kind {
		case fmlgKindCreateWithState:
			ino := u64()
			parentIno := u64()
			name := str()
			ftype := b[pos]
			pos++
			n := &fmlgNode{ftype: ftype}
			switch ftype {
			case fmlgTypeSymlink:
				_ = str() // target
			case fmlgTypeDevice:
				n.major = u32()
				n.minor = u32()
			}
			s.nodes[ino] = n
			s.edge(parentIno)[name] = ino
			readState(ino)
		case fmlgKindRename:
			ino := u64()
			oldParentIno := u64()
			oldName := str()
			newParentIno := u64()
			newName := str()
			if got := s.edge(oldParentIno)[oldName]; got != ino {
				t.Fatalf("RENAME source %d/%s = %d, want inode %d", oldParentIno, oldName, got, ino)
			}
			if _, occupied := s.edge(newParentIno)[newName]; occupied {
				t.Fatalf("RENAME destination %d/%s must be unlinked first", newParentIno, newName)
			}
			delete(s.edge(oldParentIno), oldName)
			s.edge(newParentIno)[newName] = ino
		case fmlgKindUnlink:
			_ = u64() // ino
			parentIno := u64()
			name := str()
			delete(s.edge(parentIno), name)
		case fmlgKindNodeState:
			ino := u64()
			s.nodeStates[ino]++
			readState(ino)
		default:
			t.Fatalf("unknown FMLG record kind %d", frame.kind)
		}
		if pos != len(b) {
			t.Fatalf("record tag %d left %d trailing payload bytes", frame.kind, len(b)-pos)
		}
	}
}

// flatten walks the reconstructed tree from the root into live-entry and whiteout path
// sets (the shape the index assertions consume): regular files, directories, and symlinks
// are live; whiteout devices (major/minor 0/0) are whiteouts; other devices are skipped.
func (s *fmlgState) flatten() (present, whiteouts map[string]int) {
	present = map[string]int{}
	whiteouts = map[string]int{}
	var walk func(ino uint64, prefix string)
	walk = func(ino uint64, prefix string) {
		for name, childIno := range s.children[ino] {
			path := prefix + "/" + name
			n := s.nodes[childIno]
			if n == nil {
				continue
			}
			switch n.ftype {
			case fmlgTypeReg, fmlgTypeSymlink:
				present[path]++
			case fmlgTypeDir:
				present[path]++
				walk(childIno, path)
			case fmlgTypeDevice:
				if n.major == 0 && n.minor == 0 {
					whiteouts[path]++
				}
			}
		}
	}
	walk(s.rootIno, ".")
	return present, whiteouts
}

// scanFMLG is an independent, bounds-checked framing reader for stable copies.
// It returns the validated prefix even when the next frame is incomplete.
type fmlgTestFrame struct {
	offset, end uint64
	kind        uint32
	payload     []byte
}

type fmlgTestSegment struct {
	root, epoch, previous, failure, length, reason uint64
	ended                                          bool
	frames                                         []fmlgTestFrame
}

func scanFMLG(b []byte) (s fmlgTestSegment, err error) {
	if len(b) < 32 || string(b[:4]) != "FMLG" || binary.LittleEndian.Uint16(b[4:]) != 2 || binary.LittleEndian.Uint16(b[6:]) != 0 || binary.LittleEndian.Uint64(b[16:]) != 1 {
		return s, fmt.Errorf("invalid v2 header")
	}
	s.root = binary.LittleEndian.Uint64(b[8:])
	s.failure = binary.LittleEndian.Uint64(b[24:])
	s.length = 32
	for pos := uint64(32); pos < uint64(len(b)); {
		if uint64(len(b))-pos < 24 {
			return s, fmt.Errorf("short frame header at %d", pos)
		}
		h := b[pos : pos+24]
		epoch := binary.LittleEndian.Uint64(h)
		n := uint64(binary.LittleEndian.Uint32(h[8:]))
		kind := binary.LittleEndian.Uint32(h[12:])
		seq := uint64(binary.LittleEndian.Uint32(h[16:]))
		end := pos + ((24 + n + 7) &^ 7)
		if epoch == 0 || (s.epoch != 0 && epoch != s.epoch) || seq != uint64(len(s.frames)) || end > uint64(len(b)) {
			return s, fmt.Errorf("invalid or incomplete frame at %d", pos)
		}
		payload := b[pos+24 : pos+24+n]
		crc := crc32.Update(0, crc32.MakeTable(crc32.Castagnoli), h[:20])
		crc = crc32.Update(crc, crc32.MakeTable(crc32.Castagnoli), payload)
		if crc != binary.LittleEndian.Uint32(h[20:]) {
			return s, fmt.Errorf("checksum mismatch at %d", pos)
		}
		if seq == 0 {
			if kind != 5 || n != 8 || epoch-1 != binary.LittleEndian.Uint64(payload) {
				return s, fmt.Errorf("invalid BEGIN")
			}
			s.epoch, s.previous = epoch, binary.LittleEndian.Uint64(payload)
		} else {
			switch kind {
			case 1, 2, 3, 4:
				if n == 0 {
					return s, fmt.Errorf("empty mutation record")
				}
			case 6:
				if n != 24 || binary.LittleEndian.Uint64(payload) != end || binary.LittleEndian.Uint64(payload[8:]) != seq+1 || binary.LittleEndian.Uint64(payload[16:]) > 1 {
					return s, fmt.Errorf("invalid END")
				}
				s.ended, s.reason = true, binary.LittleEndian.Uint64(payload[16:])
			default:
				return s, fmt.Errorf("invalid frame kind %d", kind)
			}
		}
		s.frames = append(s.frames, fmlgTestFrame{pos, end, kind, payload})
		s.length = end
		if s.ended {
			return s, nil
		}
		pos = end
	}
	return s, fmt.Errorf("missing END")
}

func readFMLG(t *testing.T, h *fsIndexTest) []byte {
	t.Helper()
	b, err := os.ReadFile(h.logPath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFSMutationLogV2InitialHeader(t *testing.T) {
	h := newFSIndexTest(t)
	s, err := scanFMLG(readFMLG(t, h))
	if err == nil || s.epoch != 1 || s.previous != 0 || len(s.frames) != 1 || s.ended || s.failure != 0 {
		t.Fatalf("initial epoch: %+v, %v", s, err)
	}
}

func TestFSMutationLogGracefulFinalization(t *testing.T) {
	for _, priorDrain := range []bool{false, true} {
		t.Run(fmt.Sprint(priorDrain), func(t *testing.T) {
			h := newFSIndexTest(t)
			h.put("f", "seed")
			st := newFMLGState()
			var previous uint64
			if priorDrain {
				previous = h.writeLog(0, st).gen
			}
			ino := h.inoOf("f")
			fd := h.openForWrite("f")
			defer h.closeFd(fd)
			h.writeTo(fd, "final contents")
			h.mapWritable("f")
			if err := FinalizeFSMutationLog(h.fs); err != nil {
				t.Fatal(err)
			}
			b := readFMLG(t, h)
			s, err := scanFMLG(b)
			if err != nil || !s.ended || s.reason != fmlgEndGracefulExit || s.previous != previous || s.epoch != previous+1 || s.length != uint64(len(b)) {
				t.Fatalf("final epoch: %+v, %v, file length %d", s, err, len(b))
			}
			st.apply(t, b)
			if st.sizes[ino] != uint64(len("final contents")) || st.nodeStates[ino] == 0 {
				t.Fatalf("final NODESTATE not reconciled: size %d, records %d", st.sizes[ino], st.nodeStates[ino])
			}
			if err := FinalizeFSMutationLog(h.fs); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, readFMLG(t, h)) {
				t.Fatal("repeated finalization changed the journal")
			}
			if _, _, err := FSMutationLogWrite(h.ctx, h.fs, s.epoch); err == nil {
				t.Fatal("drain succeeded after finalization")
			}
			// Cleanup-like close/metadata hooks cannot remap or append.
			h.chmod("f", 0600)
			if !bytes.Equal(b, readFMLG(t, h)) {
				t.Fatal("mutation changed the finalized journal")
			}
		})
	}
}

func TestFSMutationLogEmptyFinalEpoch(t *testing.T) {
	h := newFSIndexTest(t)
	st := newFMLGState()
	first := h.writeLog(0, st)
	before := readFMLG(t, h)
	if err := FinalizeFSMutationLog(h.fs); err != nil {
		t.Fatal(err)
	}
	s, err := scanFMLG(readFMLG(t, h))
	if err != nil || s.previous != first.gen || s.epoch != first.gen+1 || len(s.frames) != 2 || s.reason != fmlgEndGracefulExit {
		t.Fatalf("empty final epoch: %+v, %v", s, err)
	}
	old, err := scanFMLG(before)
	if err != nil || old.reason != fmlgEndSnapshot {
		t.Fatalf("live drain not sealed: %+v, %v", old, err)
	}
}

func TestFSMutationLogRecoveryRejectsStaleTail(t *testing.T) {
	h := newFSIndexTest(t)
	for i := 0; i < 30; i++ {
		h.put(fmt.Sprintf("old-%02d", i), "old content")
	}
	base := h.writeLog(0, newFMLGState())
	old := readFMLG(t, h)
	h.put("new", "new content")
	b := readFMLG(t, h)
	s, err := scanFMLG(b)
	if err == nil || s.ended || s.previous != base.gen || s.length != h.fs.Impl().(*filesystem).logOff {
		t.Fatalf("active epoch prefix: %+v, %v", s, err)
	}
	if !bytes.Equal(old[s.length:], b[s.length:]) {
		t.Fatal("test did not preserve stale tail")
	}
	// Even a valid older END frame at exactly the next boundary is rejected.
	oldSegment, _ := scanFMLG(old)
	end := oldSegment.frames[len(oldSegment.frames)-1]
	copy(b[s.length:], old[end.offset:end.end])
	recovered, err := scanFMLG(b)
	if err == nil || recovered.ended || recovered.length != s.length {
		t.Fatalf("accepted old END: %+v, %v", recovered, err)
	}
}

func TestFSMutationLogRecoveryAtEveryTruncation(t *testing.T) {
	h := newFSIndexTest(t)
	h.put("f", "data")
	h.rename("f", "g")
	h.writeLog(0, newFMLGState())
	b := readFMLG(t, h)
	full, err := scanFMLG(b)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:full.length]
	for n := 0; n <= len(b); n++ {
		s, err := scanFMLG(b[:n])
		var want int
		for _, frame := range full.frames {
			if frame.end <= uint64(n) {
				want++
			}
		}
		if len(s.frames) != want || (err == nil) != (n == len(b)) {
			t.Fatalf("cut %d: frames %d want %d, err %v", n, len(s.frames), want, err)
		}
	}
}

func TestFSMutationLogFramePublicationAndCorruption(t *testing.T) {
	h := newFSIndexTest(t)
	h.put("f", "data")
	h.writeLog(0, newFMLGState())
	b := readFMLG(t, h)
	s, err := scanFMLG(b)
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range s.frames {
		// Invalidation precedes every overwrite; no payload, partially copied
		// payload, and fully copied payload remain unreadable until publication.
		for _, copied := range []uint64{0, 1, (frame.end - frame.offset) / 2, frame.end - frame.offset - 8} {
			bad := bytes.Clone(b)
			clear(bad[frame.offset : frame.offset+8])
			clear(bad[frame.offset+8+copied : frame.end])
			prefix, err := scanFMLG(bad)
			if err == nil || len(prefix.frames) != i {
				t.Fatalf("unpublished frame %d, copy %d: %+v, %v", i, copied, prefix, err)
			}
		}
		for j := frame.offset; j < frame.offset+24+uint64(len(frame.payload)); j++ {
			bad := bytes.Clone(b)
			bad[j] ^= 1
			prefix, err := scanFMLG(bad)
			if err == nil || len(prefix.frames) != i {
				t.Fatalf("corrupt byte %d: frames %d want %d, err %v", j, len(prefix.frames), i, err)
			}
		}
	}
}

func TestFSMutationLogFailedFinalizationTruncatesPrefix(t *testing.T) {
	h := newFSIndexTest(t)
	h.put("f", "data")
	fs := h.fs.Impl().(*filesystem)
	fs.logMu.Lock()
	fs.setLogFailedLocked(fmlgFailureOverflow)
	fs.logMu.Unlock()
	if err := FinalizeFSMutationLog(h.fs); !errors.Is(err, ErrMutationLogOverflowed) {
		t.Fatalf("finalize failed journal: %v", err)
	}
	b := readFMLG(t, h)
	s, err := scanFMLG(b)
	if err == nil || s.ended || s.failure != fmlgFailureOverflow || s.length != uint64(len(b)) {
		t.Fatalf("failed prefix: %+v, %v", s, err)
	}
}

func TestFSMutationLogTruncateFailure(t *testing.T) {
	h := newFSIndexTest(t)
	fs := h.fs.Impl().(*filesystem)
	fd := fs.logFD
	fs.logFD = -1 // Existing capacity suffices; only the final truncate uses it.
	err := FinalizeFSMutationLog(h.fs)
	fs.logFD = fd
	if err == nil || fs.logMapping != nil {
		t.Fatalf("finalize with invalid FD: err %v, mapping %v", err, fs.logMapping)
	}
	if retry := FinalizeFSMutationLog(h.fs); retry != err {
		t.Fatalf("finalization lost its failure: %v, want %v", retry, err)
	}
}

func TestFSMutationLogDrainWriteFailureIsSticky(t *testing.T) {
	h := newFSIndexTest(t)
	fs := h.fs.Impl().(*filesystem)
	h.put("f", "data")
	fd := fs.logFD
	capacity := fs.logMapSize
	fs.logMapSize = fs.logOff // Force END to require a mapping growth.
	readOnly, err := os.Open(h.logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	fs.logFD = int(readOnly.Fd())
	_, _, err = FSMutationLogWrite(h.ctx, h.fs, 0)
	fs.logFD, fs.logMapSize = fd, capacity
	if err == nil {
		t.Fatal("expected mapping growth failure")
	}
	before := readFMLG(t, h)
	h.put("not-logged", "data")
	if !bytes.Equal(before, readFMLG(t, h)) {
		t.Fatal("failed journal accepted another frame")
	}
	if _, _, err := FSMutationLogWrite(h.ctx, h.fs, 0); err == nil || errors.Is(err, ErrMutationLogOverflowed) {
		t.Fatalf("expected non-overflow journal failure: %v", err)
	}
	if err := FinalizeFSMutationLog(h.fs); err == nil {
		t.Fatal("failed journal finalized successfully")
	}
	s, err := scanFMLG(readFMLG(t, h))
	if err == nil || s.ended || s.failure != fmlgFailureIO {
		t.Fatalf("failed journal: %+v, %v", s, err)
	}
}

func BenchmarkFMLGFrame(b *testing.B) {
	for _, size := range []int{64, 512, 4096} {
		payload := bytes.Repeat([]byte{0x5a}, size)
		for _, framed := range []bool{false, true} {
			b.Run(fmt.Sprintf("bytes=%d/framed=%t", size, framed), func(b *testing.B) {
				fs := &filesystem{logMapping: make([]byte, 8192), logMapSize: 8192}
				fs.logGen.Store(1)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					fs.logOff = fmlgHeaderSize
					if framed {
						if err := fs.appendLogFrame(fmlgKindNodeState, payload); err != nil {
							b.Fatal(err)
						}
					} else {
						copy(fs.logMapping[fs.logOff:], payload)
					}
				}
			})
		}
	}
}

func TestFSMutationLogDisabledMountIsInert(t *testing.T) {
	h := newFSIndexTest(t)
	fs := h.fs.Impl().(*filesystem)
	fs.logEnabled.Store(false)
	before := readFMLG(t, h)
	if _, _, err := FSMutationLogWrite(h.ctx, h.fs, 0); err == nil {
		t.Fatal("disabled mount accepted a drain")
	}
	if err := FinalizeFSMutationLog(h.fs); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readFMLG(t, h)) {
		t.Fatal("disabled mount changed its journal")
	}
}

func TestFSMutationLogCreateWithStateWireFormat(t *testing.T) {
	h := newFSIndexTest(t)
	h.mkdirAll("d")
	h.writeLog(0, newFMLGState())
	s, err := scanFMLG(readFMLG(t, h))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.frames) != 3 {
		t.Fatalf("got %d frames, want BEGIN, CREATE_WITH_STATE, END", len(s.frames))
	}
	rec := s.frames[1]
	if rec.kind != 4 {
		t.Fatalf("CREATE_WITH_STATE tag = %d, want fresh tag 4 (legacy CREATE is 0)", rec.kind)
	}
	// ino + parent + name length + "d" + ftype + initial state, without a
	// nested tag or a second inode number. An empty directory has no segments/xattrs.
	b := rec.payload
	if len(b) != 58 {
		t.Fatalf("CREATE_WITH_STATE payload = %d bytes, want 58", len(b))
	}
	if binary.LittleEndian.Uint64(b) != h.inoOf("d") || binary.LittleEndian.Uint64(b[8:]) != s.root || binary.LittleEndian.Uint32(b[16:]) != 1 || b[20] != 'd' || b[21] != 1 {
		t.Fatalf("wrong directory identity: %x", b[:22])
	}
	if binary.LittleEndian.Uint32(b[22:]) != 0o40755 || binary.LittleEndian.Uint64(b[42:]) != 0 || binary.LittleEndian.Uint32(b[50:]) != 0 || binary.LittleEndian.Uint32(b[54:]) != 0 {
		t.Fatalf("wrong initial directory state: %x", b[22:])
	}
}

func TestFSMutationLogRejectsLegacyCreateTag(t *testing.T) {
	h := newFSIndexTest(t)
	fs := h.fs.Impl().(*filesystem)
	fs.logMu.Lock()
	// A valid checksum must not allow the reserved legacy CREATE tag through.
	err := fs.appendLogFrame(0, []byte{0})
	fs.logMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s, err := scanFMLG(readFMLG(t, h))
	if err == nil || len(s.frames) != 1 || s.ended {
		t.Fatalf("accepted legacy CREATE in v2: %+v, %v", s, err)
	}
}

func TestFSMutationLogSequenceLimit(t *testing.T) {
	h := newFSIndexTest(t)
	fs := h.fs.Impl().(*filesystem)
	fs.logMu.Lock()
	defer fs.logMu.Unlock()

	// The largest wire sequence is representable without truncation.
	fs.logSeq = uint64(^uint32(0))
	offset := fs.logOff
	if err := fs.appendLogFrame(fmlgKindBegin, fmlgU64(nil, 0)); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(fs.logMapping[offset+16:]); got != ^uint32(0) {
		t.Fatalf("sequence = %d, want max u32", got)
	}

	// The next frame must fail before publishing bytes or advancing the cursor.
	offset = fs.logOff
	sequence := fs.logSeq
	if err := fs.appendLogFrame(fmlgKindBegin, fmlgU64(nil, 0)); err == nil {
		t.Fatal("accepted overflowing sequence")
	}
	if fs.logOff != offset || fs.logSeq != sequence {
		t.Fatal("overflow advanced the journal")
	}
}
