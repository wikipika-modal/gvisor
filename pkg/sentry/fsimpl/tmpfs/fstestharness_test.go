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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Shared test harness for the tmpfs mutation-log tests (fsmutationlog_test.go): a
// tmpfs mount with mutation-log tracking enabled plus helpers that issue real
// filesystem operations (put/mkdirAll/chmod/symlink/hardlink/whiteout/rename/
// delete/mapWritable) and the `index` result type its assertions run against.

type fsIndexTest struct {
	t      *testing.T
	ctx    context.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	fs     *vfs.Filesystem

	// ms is a stub MappingSpace shared by every real mmap the harness issues; the
	// index never invalidates through it. nextMapAddr hands out a distinct
	// page-aligned range per mapping so they never collide in a file's MappingSet.
	// active holds every mapping not yet torn down, so teardown can release them.
	ms          *stubMappingSpace
	nextMapAddr hostarch.Addr
	active      map[*mapping]struct{}

	// logPath is the persistent host file backing the mutation log across a test's drains;
	// opened and adopted at mount creation (see newFSIndexTest), read back in writeLog.
	logPath string
}

// newFSIndexTest mounts a new tmpfs and returns a harness for it. The mount and
// any mappings a test leaves behind are torn down automatically when it ends.
func newFSIndexTest(t *testing.T) *fsIndexTest {
	t.Helper()
	baseCtx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(baseCtx)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	// Enable mutation-log tracking (as the overlay upper does in production) so the
	// fsmutationlog tests exercise a real logging mount. The mount adopts a persistent host
	// log file at creation, mirroring the boot-time donation; the file backs the log across a
	// test's drains and is read back in writeLog.
	logPath := filepath.Join(t.TempDir(), "fmlg.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	logFD, err := fd.NewFromFile(logFile)
	logFile.Close()
	if err != nil {
		t.Fatalf("dup log fd: %v", err)
	}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOpts{EnableMutationLog: true, MutationLogFD: logFD},
		},
	}, nil)
	if err != nil {
		t.Fatalf("create tmpfs root mount: %v", err)
	}
	root := mntns.Root(baseCtx)

	// unlink/rmdir/rename check whether the target is a mountpoint, which requires
	// a mount namespace in the context -- the real caller's context, backed by a
	// task, has one. Thread it through so those operations run as they do in
	// production rather than dereferencing a nil namespace.
	ctx := vfs.WithMountNamespace(baseCtx, mntns)

	h := &fsIndexTest{
		t:           t,
		ctx:         ctx,
		creds:       creds,
		vfsObj:      vfsObj,
		root:        root,
		fs:          root.Mount().Filesystem(),
		ms:          &stubMappingSpace{},
		nextMapAddr: 0x40000000,
		active:      map[*mapping]struct{}{},
		logPath:     logPath,
	}
	// t.Cleanup is LIFO: teardownMappings (registered last) runs first, releasing
	// mappings before the mount they point into goes away.
	t.Cleanup(func() {
		root.DecRef(baseCtx)
		mntns.DecRef(baseCtx)
	})
	t.Cleanup(h.teardownMappings)
	return h
}

// pop builds a PathOperation that resolves path relative to the mount root.
func (h *fsIndexTest) pop(path string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: h.root, Start: h.root, Path: fspath.Parse(path)}
}

// put creates name under the root, or overwrites it if it already exists, with
// the given contents. Creating and overwriting both go through the tmpfs
// create/write hooks that feed the mutation log, so put is how a test both adds
// a file and changes one.
func (h *fsIndexTest) put(name, contents string) {
	h.t.Helper()
	fd, err := h.vfsObj.OpenAt(h.ctx, h.creds, h.pop(name), &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT,
		Mode:  linux.ModeRegular | 0o644,
	})
	if err != nil {
		h.t.Fatalf("put %q: open: %v", name, err)
	}
	defer fd.DecRef(h.ctx)
	if _, err := fd.Write(h.ctx, usermem.BytesIOSequence([]byte(contents)), vfs.WriteOptions{}); err != nil {
		h.t.Fatalf("put %q: write: %v", name, err)
	}
}

// openForWrite opens the existing file at name read-write, returning the open
// file description. Opening a regular file writable registers it with the
// mutation log's open-for-write set (see logOpenForWrite).
func (h *fsIndexTest) openForWrite(name string) *vfs.FileDescription {
	h.t.Helper()
	fd, err := h.vfsObj.OpenAt(h.ctx, h.creds, h.pop(name), &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		h.t.Fatalf("openForWrite %q: %v", name, err)
	}
	return fd
}

// openReadonly opens the existing file at name read-only: it must NOT register
// with the mutation log's open-for-write set.
func (h *fsIndexTest) openReadonly(name string) *vfs.FileDescription {
	h.t.Helper()
	fd, err := h.vfsObj.OpenAt(h.ctx, h.creds, h.pop(name), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		h.t.Fatalf("openReadonly %q: %v", name, err)
	}
	return fd
}

// writeTo writes contents to fd at its current offset.
func (h *fsIndexTest) writeTo(fd *vfs.FileDescription, contents string) {
	h.t.Helper()
	if _, err := fd.Write(h.ctx, usermem.BytesIOSequence([]byte(contents)), vfs.WriteOptions{}); err != nil {
		h.t.Fatalf("write: %v", err)
	}
}

// closeFd drops fd's last reference, running its Release (the mutation log's
// close-time NODESTATE hook for writable descriptions).
func (h *fsIndexTest) closeFd(fd *vfs.FileDescription) {
	h.t.Helper()
	fd.DecRef(h.ctx)
}

// mkdirAll creates path and any missing parent directories (like `mkdir -p`).
func (h *fsIndexTest) mkdirAll(path string) {
	h.t.Helper()
	prefix := ""
	for _, name := range strings.Split(path, "/") {
		if prefix == "" {
			prefix = name
		} else {
			prefix += "/" + name
		}
		err := h.vfsObj.MkdirAt(h.ctx, h.creds, h.pop(prefix), &vfs.MkdirOptions{Mode: 0o755})
		if err != nil && !linuxerr.Equals(linuxerr.EEXIST, err) {
			h.t.Fatalf("mkdir %q: %v", prefix, err)
		}
	}
}

// chmod changes only the permission bits of name -- a metadata-only change, with
// no write to the file's contents.
func (h *fsIndexTest) chmod(name string, mode uint16) {
	h.t.Helper()
	opts := &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: mode}}
	if err := h.vfsObj.SetStatAt(h.ctx, h.creds, h.pop(name), opts); err != nil {
		h.t.Fatalf("chmod %q: %v", name, err)
	}
}

// symlink creates a symbolic link at name pointing at target.
func (h *fsIndexTest) symlink(name, target string) {
	h.t.Helper()
	if err := h.vfsObj.SymlinkAt(h.ctx, h.creds, h.pop(name), target); err != nil {
		h.t.Fatalf("symlink %q -> %q: %v", name, target, err)
	}
}

// hardlink creates newName as a hard link to the existing file oldName.
func (h *fsIndexTest) hardlink(oldName, newName string) {
	h.t.Helper()
	if err := h.vfsObj.LinkAt(h.ctx, h.creds, h.pop(oldName), h.pop(newName)); err != nil {
		h.t.Fatalf("hardlink %q -> %q: %v", newName, oldName, err)
	}
}

// whiteout creates an overlay whiteout character device at name, exactly as
// gVisor's overlay does (overlay.CreateWhiteout) to mask a deleted file that
// exists in a lower layer. The index emits it as a WHITEOUT record.
func (h *fsIndexTest) whiteout(name string) {
	h.t.Helper()
	major, minor := linux.DecodeDeviceID(linux.WHITEOUT_DEV)
	opts := &vfs.MknodOptions{
		Mode:     linux.S_IFCHR | linux.WHITEOUT_MODE,
		DevMajor: uint32(major),
		DevMinor: minor,
	}
	if err := h.vfsObj.MknodAt(h.ctx, h.creds, h.pop(name), opts); err != nil {
		h.t.Fatalf("whiteout %q: %v", name, err)
	}
}

// stubMappingSpace is a no-op memmap.MappingSpace standing in for the address
// space a real mmap would map into. The index never triggers an invalidation, so
// Invalidate is never called.
type stubMappingSpace struct{}

func (*stubMappingSpace) Invalidate(hostarch.AddrRange, memmap.InvalidateOpts) {}

// mapping is a handle to one real writable shared mapping the harness has
// established, used to tear it down.
type mapping struct {
	h   *fsIndexTest
	rf  *regularFile
	id  memmap.MappingIdentity
	ar  hostarch.AddrRange
	off uint64
}

// mapWritable establishes a real writable shared memory mapping of name -- the
// same ConfigureMMap + AddMapping that the mmap(2) syscall drives -- and returns
// a handle for unmapping it. ConfigureMMap records the file for the index
// (markMmapWritable); AddMapping bumps its writable-mapping count.
func (h *fsIndexTest) mapWritable(name string) *mapping {
	h.t.Helper()
	fd, err := h.vfsObj.OpenAt(h.ctx, h.creds, h.pop(name), &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		h.t.Fatalf("mapWritable %q: open: %v", name, err)
	}
	opts := memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.AnyAccess,
		Private:  false, // shared
	}
	if err := fd.ConfigureMMap(h.ctx, &opts); err != nil {
		fd.DecRef(h.ctx)
		h.t.Fatalf("mapWritable %q: ConfigureMMap: %v", name, err)
	}
	rf, ok := opts.Mappable.(*regularFile)
	if !ok {
		opts.MappingIdentity.DecRef(h.ctx)
		fd.DecRef(h.ctx)
		h.t.Fatalf("mapWritable %q: not a regular file", name)
	}
	ar := hostarch.AddrRange{Start: h.nextMapAddr, End: h.nextMapAddr + hostarch.PageSize}
	h.nextMapAddr += hostarch.PageSize
	if err := rf.AddMapping(h.ctx, h.ms, ar, opts.Offset, true /* writable */); err != nil {
		opts.MappingIdentity.DecRef(h.ctx)
		fd.DecRef(h.ctx)
		h.t.Fatalf("mapWritable %q: AddMapping: %v", name, err)
	}
	// The mapping now holds its own reference through opts.MappingIdentity (released
	// in unmap); drop the OpenAt reference, as an app closing the fd after mmap
	// would.
	fd.DecRef(h.ctx)
	m := &mapping{h: h, rf: rf, id: opts.MappingIdentity, ar: ar, off: opts.Offset}
	h.active[m] = struct{}{}
	return m
}

// unmap tears down a mapping, as munmap would: RemoveMapping drops the file's
// writable-mapping count, so the file leaves the tracking set on the next index.
func (m *mapping) unmap() {
	m.h.t.Helper()
	m.rf.RemoveMapping(m.h.ctx, m.h.ms, m.ar, m.off, true /* writable */)
	m.id.DecRef(m.h.ctx)
	delete(m.h.active, m)
}

// teardownMappings releases any mapping a test left in place, so the filesystem
// can be torn down without leaking references.
func (h *fsIndexTest) teardownMappings() {
	for m := range h.active {
		m.rf.RemoveMapping(h.ctx, h.ms, m.ar, m.off, true /* writable */)
		m.id.DecRef(h.ctx)
	}
	h.active = nil
}

// delete removes the entry at path with a real unlink (for a file) or rmdir (for
// an empty directory), as the syscalls would: the dentry is detached and marked
// dead, and a whiteout tombstone is recorded for the index.
func (h *fsIndexTest) delete(path string) {
	h.t.Helper()
	if h.isDir(path) {
		if err := h.vfsObj.RmdirAt(h.ctx, h.creds, h.pop(path)); err != nil {
			h.t.Fatalf("rmdir %q: %v", path, err)
		}
		return
	}
	if err := h.vfsObj.UnlinkAt(h.ctx, h.creds, h.pop(path)); err != nil {
		h.t.Fatalf("unlink %q: %v", path, err)
	}
}

// rename moves the entry at oldPath to newPath with a real rename, as the syscall
// would: the old path becomes a whiteout and the (same) dentry reappears at the
// new path.
func (h *fsIndexTest) rename(oldPath, newPath string) {
	h.t.Helper()
	if err := h.vfsObj.RenameAt(h.ctx, h.creds, h.pop(oldPath), h.pop(newPath), &vfs.RenameOptions{}); err != nil {
		h.t.Fatalf("rename %q -> %q: %v", oldPath, newPath, err)
	}
}

// isDir reports whether the entry at path is a directory.
func (h *fsIndexTest) isDir(path string) bool {
	h.t.Helper()
	tfs := h.fs.Impl().(*filesystem)
	tfs.mu.RLock()
	defer tfs.mu.RUnlock()
	_, ok := h.lookupLocked(tfs, path).inode.impl.(*directory)
	return ok
}

// lookupLocked walks the dentry tree to the entry at path.
//
// Preconditions: filesystem.mu must be locked.
func (h *fsIndexTest) lookupLocked(tfs *filesystem, path string) *dentry {
	h.t.Helper()
	d := tfs.root
	for _, name := range strings.Split(path, "/") {
		dir, ok := d.inode.impl.(*directory)
		if !ok {
			h.t.Fatalf("lookup %q: %q is not a directory", path, name)
		}
		child := dir.childMap[name]
		if child == nil {
			h.t.Fatalf("lookup %q: no entry named %q", path, name)
		}
		d = child
	}
	return d
}

// index is the decoded result of one drain (writeLog): the returned generation and the
// paths it holds, split into live entries and whiteout tombstones.
type index struct {
	t         *testing.T
	gen       uint64
	present   map[string]int // live (non-whiteout) entries, path -> record count
	whiteouts map[string]int // whiteouts (tombstones or overlay whiteout devices) -> count
}

// wantGenAfter asserts that the index's generation advanced past prev.
func (ix index) wantGenAfter(prev uint64) {
	ix.t.Helper()
	if ix.gen <= prev {
		ix.t.Errorf("generation did not advance: got %d, want > %d", ix.gen, prev)
	}
}

// wantPresent asserts that each path is a live entry in the index.
func (ix index) wantPresent(paths ...string) {
	ix.t.Helper()
	for _, p := range paths {
		if ix.present[p] == 0 {
			ix.t.Errorf("index is missing live entry %q", p)
		}
	}
}

// wantAbsent asserts that each path is not a live entry -- because it was either
// left unchanged, or deleted (and so appears only as a whiteout).
func (ix index) wantAbsent(paths ...string) {
	ix.t.Helper()
	for _, p := range paths {
		if ix.present[p] != 0 {
			ix.t.Errorf("index unexpectedly contains live entry %q (%d times)", p, ix.present[p])
		}
	}
}

// wantWhiteoutOnce asserts that each path has exactly one whiteout. It catches
// double-whiteouts, e.g. a tombstone and an overlay whiteout device both landing
// on the same path after a rename.
func (ix index) wantWhiteoutOnce(paths ...string) {
	ix.t.Helper()
	for _, p := range paths {
		if got := ix.whiteouts[p]; got != 1 {
			ix.t.Errorf("whiteout %q appears %d times, want exactly 1", p, got)
		}
	}
}

// wantNoWhiteout asserts that each path has no whiteout, e.g. a file recreated at
// a just-deleted path must not carry a lingering tombstone.
func (ix index) wantNoWhiteout(paths ...string) {
	ix.t.Helper()
	for _, p := range paths {
		if got := ix.whiteouts[p]; got != 0 {
			ix.t.Errorf("path %q has %d whiteout(s), want none", p, got)
		}
	}
}

// wantPresentOnce asserts that each path is a live entry exactly once.
func (ix index) wantPresentOnce(paths ...string) {
	ix.t.Helper()
	for _, p := range paths {
		if got := ix.present[p]; got != 1 {
			ix.t.Errorf("live entry %q appears %d times, want exactly 1", p, got)
		}
	}
}
