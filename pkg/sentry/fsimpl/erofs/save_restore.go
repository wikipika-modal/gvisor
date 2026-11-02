// Copyright 2023 The gVisor Authors.
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
	goContext "context"
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(ctx goContext.Context) {
	fs.memoryFile = pgalloc.MemoryFileFromContext(ctx)
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		panic(fmt.Sprintf("no image FD available for filesystem with unique ID %q, map: %#v", fs.iopts.UniqueID, fdmap))
	}
	newImage, err := erofs.OpenImage(os.NewFile(uintptr(fd), "EROFS image file"))
	if err != nil {
		panic(fmt.Sprintf("erofs.OpenImage failed: %v", err))
	}
	fs.imageChanged = newImage.SuperBlock() != fs.image.SuperBlock()
	// We need to update the image in place, as there are other pointers
	// pointing to this image as well.
	*fs.image = *newImage
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
//
// Saved inodes hold offsets into the image they were read from. They are kept
// if the restored image has the same superblock and the same inode at every
// saved nid. Otherwise, like gofer, every saved dentry is looked up again by
// path in the new image, and the restore fails if a file is missing, or its
// type, or a regular file's size or mtime, changed.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	start := time.Now()
	inodes := fs.savedInodes()
	if !fs.imageChanged && fs.imageHas(inodes) {
		log.Infof("erofs: mount %q kept %d inodes on an unchanged image in %v", fs.iopts.UniqueID, len(inodes), time.Since(start))
		return nil
	}
	// Unreferenced dentries are only a cache, so they needn't match the new
	// image.
	fs.evictAllCachedDentries(ctx)
	inodes = fs.savedInodes()
	dentries, err := fs.reresolve(len(inodes))
	if err != nil {
		return vfs.ErrCorruption{Err: fmt.Errorf("erofs mount %q: %w", fs.iopts.UniqueID, err)}
	}
	log.Infof("erofs: mount %q re-resolved %d dentries and %d inodes onto a changed image in %v", fs.iopts.UniqueID, dentries, len(inodes), time.Since(start))
	return nil
}

func (fs *filesystem) savedInodes() []*inode {
	var inodes []*inode
	for b := range fs.inodeBuckets {
		ib := &fs.inodeBuckets[b]
		ib.mu.RLock()
		for _, i := range ib.inodeMap {
			inodes = append(inodes, i)
		}
		ib.mu.RUnlock()
	}
	return inodes
}

// imageHas returns whether the image holds the same inodes at the nids of
// inodes.
func (fs *filesystem) imageHas(inodes []*inode) bool {
	for _, i := range inodes {
		if ino, err := fs.image.Inode(i.Nid()); err != nil || ino != i.Inode {
			return false
		}
	}
	return true
}

// reresolve looks up every dentry by path in the image, replaces its inode's
// image fields, and re-indexes the inodes by their new nids. It returns the
// number of dentries.
func (fs *filesystem) reresolve(savedInodes int) (int, error) {
	nids := make(map[*inode]uint64, savedInodes)
	dentries := 0
	var walk func(d *dentry, nid uint64) error
	walk = func(d *dentry, nid uint64) error {
		dentries++
		if prev, ok := nids[d.inode]; ok {
			if prev != nid {
				return fmt.Errorf("hard links to %q now resolve to nids %d and %d", genericDebugPathname(fs, d), prev, nid)
			}
		} else {
			ino, err := fs.image.Inode(nid)
			if err != nil {
				return fmt.Errorf("reading %q at nid %d: %w", genericDebugPathname(fs, d), nid, err)
			}
			if err := checkSameFile(&d.inode.Inode, &ino); err != nil {
				return fmt.Errorf("%q %w", genericDebugPathname(fs, d), err)
			}
			d.inode.Inode = ino
			nids[d.inode] = nid
		}
		d.dirMu.RLock()
		defer d.dirMu.RUnlock()
		for name, child := range d.childMap {
			childNid, err := d.inode.Lookup(name)
			if err != nil {
				return fmt.Errorf("looking up %q: %w", genericDebugPathname(fs, child), err)
			}
			if err := walk(child, childNid); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(fs.root, fs.image.RootNid()); err != nil {
		return 0, err
	}
	if len(nids) != savedInodes {
		return 0, fmt.Errorf("%d saved inodes, but %d are reachable by path", savedInodes, len(nids))
	}
	for b := range fs.inodeBuckets {
		fs.inodeBuckets[b].init()
	}
	for i, nid := range nids {
		ib := fs.inodeBucket(nid)
		ib.mu.Lock()
		_, dup := ib.inodeMap[nid]
		ib.inodeMap[nid] = i
		ib.mu.Unlock()
		if dup {
			return 0, fmt.Errorf("two saved files now resolve to nid %d", nid)
		}
	}
	return dentries, nil
}

// checkSameFile returns an error if restored can't stand in for saved.
func checkSameFile(saved, restored *erofs.Inode) error {
	if was, is := saved.Mode()&linux.S_IFMT, restored.Mode()&linux.S_IFMT; was != is {
		return fmt.Errorf("changed type from %#o to %#o", was, is)
	}
	if !saved.IsRegular() {
		return nil
	}
	if saved.Size() != restored.Size() {
		return fmt.Errorf("changed size from %d to %d", saved.Size(), restored.Size())
	}
	if saved.Mtime() != restored.Mtime() || saved.MtimeNsec() != restored.MtimeNsec() {
		return fmt.Errorf("changed mtime from %d.%09d to %d.%09d", saved.Mtime(), saved.MtimeNsec(), restored.Mtime(), restored.MtimeNsec())
	}
	return nil
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ goContext.Context, parent *dentry) {
	d.parent.Store(parent)
}

// afterLoad is called by stateify.
func (d *dentry) afterLoad(goContext.Context) {
	if d.refs.Load() != -1 {
		refs.Register(d)
	}
}
