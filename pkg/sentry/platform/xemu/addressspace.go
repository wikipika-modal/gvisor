// Copyright 2024 The gVisor Authors.
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

package xemu

import (
	"fmt"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// addressSpace is a platform.AddressSpace: an application mm held by the module
// and manipulated via ioctls on an address-space fd.
type addressSpace struct {
	platform.NoAddressSpaceIO

	xemu *XEMU

	// fd is the address-space fd returned by XEMU_CREATE_ADDRESS_SPACE.
	fd int
}

// newAddressSpace returns a fresh, empty application address space, reusing a
// pooled one if there is any. Errors are bare unix.Errno: this runs on the
// fork/execve syscall path, where ExtractErrno panics on a wrapped error.
//
// A dead donor's request times out; dropDonor discards it and the next attempt
// re-forks. Each attempt uses a fresh address-space fd, since a donor that died
// mid-request may already have bound the previous one.
func newAddressSpace(p *XEMU) (*addressSpace, error) {
	if as := p.asPoolGet(); as != nil {
		return as, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		d, err := p.getDonor()
		if err != nil {
			return nil, err
		}

		asfd, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(p.deviceFile.FD()), xemuCreateAddressSpace, 0)
		if errno != 0 {
			return nil, errno
		}

		status, commErr := d.createBind(p.donorSeq.Add(1), int(asfd))
		if commErr != nil {
			unix.Close(int(asfd))
			p.dropDonor(d)
			continue
		}
		if status != 0 {
			unix.Close(int(asfd))
			return nil, unix.Errno(status)
		}

		// Clear the bound mm (a copy of the donor's) so the application starts
		// empty; gVisor populates it via MapFile.
		as := &addressSpace{xemu: p, fd: int(asfd)}
		if err := as.unmapRange(0, maxUserAddr); err != nil {
			unix.Close(as.fd)
			return nil, err
		}
		return as, nil
	}
	return nil, unix.EAGAIN
}

// mmapArgs matches struct xemu_mmap_args (packed; all fields are naturally
// aligned so the packing is a no-op).
type mmapArgs struct {
	addr     uint64
	length   uint64
	prot     int32
	flags    int32
	fd       int32
	reserved int32
	offset   int64
}

// munmapArgs matches struct xemu_munmap_args.
type munmapArgs struct {
	addr   uint64
	length uint64
}

// MapFile implements platform.AddressSpace.MapFile. precommit is ignored: the
// module forces MAP_NONBLOCK (populating must not block in the switch context),
// so pages always fault in lazily.
func (as *addressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	fd, err := f.DataFD(fr)
	if err != nil {
		return err
	}
	args := mmapArgs{
		addr:   uint64(addr),
		length: fr.Length(),
		prot:   int32(at.Prot()),
		flags:  unix.MAP_SHARED | unix.MAP_FIXED,
		fd:     int32(fd),
		offset: int64(fr.Start),
	}
	return as.mmap(&args)
}

// Unmap implements platform.AddressSpace.Unmap.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	if err := as.unmapRange(uint64(addr), length); err != nil {
		panic(fmt.Sprintf("xemu: MUNMAP at %#x length %#x: %v", addr, length, err))
	}
}

func (as *addressSpace) unmapRange(addr, length uint64) error {
	args := munmapArgs{addr: addr, length: length}
	return as.munmap(&args)
}

// Release implements platform.AddressSpace.Release.
func (as *addressSpace) Release() {
	if as.xemu.asPoolPut(as) {
		return
	}
	unix.Close(as.fd)
	as.fd = -1
}

// PreFork implements platform.AddressSpace.PreFork.
func (as *addressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (as *addressSpace) PostFork() {}
