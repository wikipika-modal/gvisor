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

package kernel

import (
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// FsMutationLogOpts holds options to Kernel.FsMutationLog.
type FsMutationLogOpts struct {
	// Path is the mount point inside the container whose overlay upper layer is
	// journaled. Empty defaults to "/".
	Path string

	// SinceGen requests the segment of changes since this generation (as returned by a
	// previous call); 0 drains the full history of a mount that has not been drained yet.
	// A mismatched SinceGen fails until a Resync.
	SinceGen uint64

	// Generation is the generation the written segment reflects; the caller passes it as
	// SinceGen next time for incrementality. A dump leaves the journal's cursor alone, so
	// its Generation is not a SinceGen.
	Generation uint64

	// Length is the size of the written segment. The caller reflinks the log file while the
	// container is paused and reads [0, Length) for the segment.
	Length uint64

	// Dump, if set, receives a FULL segment of the journaled upper instead; the
	// mount need not have a journal. SinceGen is unused; Length is the size of
	// the FULL segment.
	Dump io.Writer

	// Resync restarts the journal after the Dump, even if it had failed.
	Resync bool
}

// FsMutationLog pauses the kernel, then captures incremental metadata changes to the
// overlay upper layer mounted at opts.Path. With opts.Dump, it writes a full metadata
// dump instead; opts.Resync also restarts the journal. opts.Path must be an overlayfs
// whose upper is a disk-backed tmpfs (runsc --overlay2 medium "self" or "dir=").
func (k *Kernel) FsMutationLog(ctx context.Context, opts *FsMutationLogOpts) error {
	if len(opts.Path) == 0 {
		opts.Path = "/"
	}

	k.Pause()
	defer k.Unpause()
	return k.quiescePausedAnd(ctx, func() error {
		// Select the tmpfs upper layer mounted at opts.Path: its private disk-backed
		// MemoryFile carries a ResourceID whose Path is the mount path. tmpfs mounts on
		// the shared (memory-medium) MemoryFile have no ResourceID and are skipped.
		fss := k.vfs.GetFilesystems()
		defer func() {
			for _, fs := range fss {
				fs.DecRef(ctx)
			}
		}()
		var targetFS *vfs.Filesystem
		for _, fs := range fss {
			mf := tmpfs.MemoryFileOf(fs)
			if mf == nil {
				continue
			}
			resourceID := mf.ResourceID()
			if !resourceID.Ok() || resourceID.Path != opts.Path {
				continue
			}
			if targetFS != nil {
				return fmt.Errorf("multiple disk-backed overlay upper layers found at path %q (multi-container fsmutationlog is not supported)", opts.Path)
			}
			targetFS = fs
		}
		if targetFS == nil {
			return fmt.Errorf("no disk-backed overlay upper layer found at path %q; fsmutationlog requires runsc --overlay2 medium 'self' or 'dir='", opts.Path)
		}

		var newGen, length uint64
		var err error
		switch {
		case opts.Dump != nil && opts.Resync:
			newGen, length, err = tmpfs.FSMutationLogResync(ctx, targetFS, opts.Dump)
		case opts.Dump != nil:
			newGen, length, err = tmpfs.FSMutationLogDump(ctx, targetFS, opts.Dump)
		default:
			newGen, length, err = tmpfs.FSMutationLogWrite(ctx, targetFS, opts.SinceGen)
		}
		if err != nil {
			return fmt.Errorf("failed to write mutation log for path %q: %w", opts.Path, err)
		}
		opts.Generation = newGen
		opts.Length = length
		return nil
	})
}
