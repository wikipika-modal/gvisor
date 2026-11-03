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

package erofs

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// newTwoFileImage returns an image whose root directory holds the regular
// files "a" (10 bytes) at aNid and "b" (20 bytes) at bNid.
func newTwoFileImage(aNid, bNid uint32) []byte {
	const rootNid = 96
	data := make([]byte, 10*hostarch.PageSize)
	sb := erofs.SuperBlock{Magic: erofs.SuperBlockMagicV1, BlockSizeBits: uint8(hostarch.PageShift), RootNid: rootNid, Blocks: 10}
	sb.MarshalUnsafe(data[erofs.SuperBlockOffset:])
	rootOff := rootNid << erofs.InodeSlotBits
	root := erofs.InodeCompact{Format: erofs.InodeDataLayoutFlatInline << erofs.InodeDataLayoutBit, Mode: linux.S_IFDIR | 0755, Size: 2*erofs.DirentSize + 2, Nlink: 2}
	root.MarshalUnsafe(data[rootOff:])
	dirOff := rootOff + erofs.InodeCompactSize
	for i, f := range []struct {
		nid  uint32
		size uint32
	}{{aNid, 10}, {bNid, 20}} {
		dirent := erofs.Dirent{NidLow: f.nid, NameOff: uint16(2*erofs.DirentSize + i), FileType: 1}
		dirent.MarshalUnsafe(data[dirOff+i*erofs.DirentSize:])
		data[dirOff+2*erofs.DirentSize+i] = 'a' + byte(i)
		file := erofs.InodeCompact{Format: erofs.InodeDataLayoutFlatPlain << erofs.InodeDataLayoutBit, Mode: linux.S_IFREG | 0444, Nlink: 1, Size: f.size, RawBlockAddr: 4}
		file.MarshalUnsafe(data[f.nid<<erofs.InodeSlotBits:])
	}
	return data
}

// A file held open across a restore onto an image where it moved keeps its
// inode number, and no other file takes it over.
func TestReresolveKeepsInodeNumbers(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root := mountTestImage(ctx, t, newTwoFileImage(100, 101))
	at := func(path string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	}
	fd, err := vfsObj.OpenAt(ctx, creds, at("a"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatal(err)
	}
	defer fd.DecRef(ctx)
	before, err := fd.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Swap in an image where "b" took over the nid of "a", as afterLoad
	// would on restore.
	newFD, err := unix.Dup(int(imageFile(t, newTwoFileImage(101, 100)).Fd()))
	if err != nil {
		t.Fatal(err)
	}
	image, err := erofs.OpenImage(os.NewFile(uintptr(newFD), "image"))
	if err != nil {
		t.Fatal(err)
	}
	fs := fd.Impl().(*regularFileFD).inode().fs
	fs.imageChanged = image.SuperBlock() != fs.image.SuperBlock()
	fs.image.Close()
	*fs.image = *image
	if err := fs.CompleteRestore(ctx, vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	after, err := fd.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := vfsObj.OpenAt(ctx, creds, at(""), &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		t.Fatal(err)
	}
	defer dir.DecRef(ctx)
	direntInos := map[string]uint64{}
	if err := dir.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		direntInos[d.Name] = d.Ino
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	b, err := vfsObj.StatAt(ctx, creds, at("b"), &vfs.StatOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if after.Ino != before.Ino {
		t.Errorf("held file's inode number changed from %d to %d", before.Ino, after.Ino)
	}
	if b.Ino == before.Ino {
		t.Errorf("b reports inode number %d, which the held file had before the restore", b.Ino)
	}
	if direntInos["a"] != after.Ino || direntInos["b"] != b.Ino {
		t.Errorf("getdents reports inode numbers %v, but stat reports a=%d and b=%d", direntInos, after.Ino, b.Ino)
	}
	if after.Size != 10 || b.Size != 20 {
		t.Errorf("sizes are %d and %d after the restore, want 10 and 20", after.Size, b.Size)
	}
}
