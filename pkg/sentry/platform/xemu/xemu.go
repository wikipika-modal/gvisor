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

//go:build amd64 || arm64
// +build amd64 arm64

// Package xemu provides a platform implementation based on the XEMU
// accelerated emulation kernel module (/dev/xemu).
//
// Unlike ptrace or systrap, XEMU runs application code on the sentry's own
// OS threads: a thread swaps its mm to the application address space via an
// ioctl, runs the application until it traps (syscall, fault, signal, or
// interrupt), and the same ioctl returns with the application's register
// state. There is no separate stub process, so switches avoid a cross-process
// context switch. The trade-off is that the platform is responsible for
// saving and restoring floating point state around each switch, because the
// module only swaps general-purpose registers and the fs/gs base.
package xemu

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/hostmm"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// Device is the default XEMU device file.
const Device = "/dev/xemu"

// ioctl commands, matching _IO('x'=0x78, nr) in the module's uapi header.
const (
	xemuVersion            = 0x7800
	xemuCreateAddressSpace = 0x7801
	xemuInterrupt          = 0x7803
	xemuMmap               = 0x7810
	xemuMunmap             = 0x7811
	xemuBind               = 0x7812
	xemuSwitch             = 0x7813
)

// maxUserAddr is the first address that may not be used by applications; XEMU
// runs applications in a real Linux mm, so no additional range is reserved. It
// is defined per-arch (a fixed ceiling on amd64, derived from the probed host
// TASK_SIZE on arm64).

// XEMU is a platform.Platform backed by the XEMU kernel module.
type XEMU struct {
	platform.MMapMinAddr
	platform.NoCPUPreemptionDetection
	platform.UseHostGlobalMemoryBarrier
	platform.NoCPUNumbers

	// deviceFile is the open handle to /dev/xemu. It is shared by every
	// address space and context.
	deviceFile *fd.FD

	// xsaveMode selects how the application's floating point state is saved and
	// restored around a switch on amd64 (set by archInit; unused on arm64,
	// which always uses fixed-layout FPSIMD).
	xsaveMode xsaveMode

	// asPoolMu guards asPool, a stack of idle application address spaces kept
	// for reuse.
	asPoolMu sync.Mutex
	asPool   []*addressSpace

	// donorSock is the SEQPACKET socketpair connecting the sentry to the mm
	// donor. It is created in New (before the seccomp filter is installed,
	// which does not permit socketpair). The donor inherits its end across the
	// fork; the sentry keeps both ends open so a re-forked donor can inherit
	// it again.
	donorSock [2]int

	// donorParentPid is the sentry's pid, checked by the donor to detect a
	// parent that died before it installed PR_SET_PDEATHSIG.
	donorParentPid int

	// donorMu guards the lazy fork of the mm donor (see donor.go) on the first
	// address space creation. A failed start is not cached, so a later creation
	// retries.
	donorMu   sync.Mutex
	donorInst *donor

	// donorSeq tags each donor request so a reply left buffered by a timed-out
	// request is skipped rather than mistaken for a later request's reply. It is
	// global (not per-donor) so sequence numbers stay unique across re-forks.
	donorSeq atomicbitops.Uint32
}

// xsaveMode selects the instructions the switch assembly uses to save and
// restore the application's floating point state on amd64.
type xsaveMode uintptr

const (
	xsaveModeFxsave xsaveMode = iota
	xsaveModeXsave
	xsaveModeXsaveopt
)

// asPoolMax bounds the number of idle address spaces kept for reuse. Creating
// one costs a donor round trip and a fork, while recycling one costs a single
// full-range XEMU_MUNMAP, so pooling makes fork- and exec-heavy workloads
// considerably cheaper.
const asPoolMax = 100

// donorReplyTimeout bounds how long a donor request waits for a reply before the
// donor is treated as dead and re-forked. It is generous relative to a live
// donor's sub-millisecond round-trip so a slow-but-alive donor is not dropped.
const donorReplyTimeout = 2 // seconds

// New returns a new XEMU platform using the given /dev/xemu handle.
func New(deviceFile *fd.FD) (*XEMU, error) {
	if deviceFile == nil {
		return nil, fmt.Errorf("xemu: no device file")
	}
	// Confirm the module is present and speaks the expected ABI.
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(deviceFile.FD()), xemuVersion, 0); errno != 0 {
		return nil, fmt.Errorf("xemu: XEMU_VERSION ioctl failed: %v", errno)
	}
	// Create the donor socketpair now, before the seccomp filter is installed:
	// the donor is forked lazily (post-seccomp) but socketpair is not permitted
	// by the filter. SEQPACKET gives the request/response exchange message
	// boundaries.
	donorSock, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("xemu: donor socketpair: %w", err)
	}
	// Set the receive timeout now, before seccomp: the sentry keeps the donor's
	// peer end open (a re-forked donor must inherit it), so a dead donor never
	// yields EOF/EPIPE, and this timeout is how createBind detects one and
	// re-forks.
	tv := unix.Timeval{Sec: donorReplyTimeout}
	if err := unix.SetsockoptTimeval(donorSock[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("xemu: donor socket timeout: %w", err)
	}
	mbCh := hostmm.Probe(false)
	x := &XEMU{
		UseHostGlobalMemoryBarrier: platform.UseHostGlobalMemoryBarrier{MemBarrier: <-mbCh},
		deviceFile:                 deviceFile,
		donorSock:                  donorSock,
		donorParentPid:             unix.Getpid(),
	}
	// Architecture-specific setup: amd64 derives the FP save/restore mode and
	// warns on a mapped vsyscall page; arm64 configures the user address range.
	x.archInit()
	return x, nil
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
func (*XEMU) SupportsAddressSpaceIO() bool {
	return false
}

// MapUnit implements platform.Platform.MapUnit.
func (*XEMU) MapUnit() uint64 {
	// The cost of a MapFile is a single ioctl regardless of the number of
	// pages, so there's no benefit to batching.
	return 0
}

// MaxUserAddress implements platform.Platform.MaxUserAddress.
func (*XEMU) MaxUserAddress() hostarch.Addr {
	return hostarch.Addr(maxUserAddr)
}

// NewAddressSpace implements platform.Platform.NewAddressSpace.
func (p *XEMU) NewAddressSpace(opts platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return newAddressSpace(p)
}

// NewContext implements platform.Platform.NewContext.
func (p *XEMU) NewContext(pkgcontext.Context) platform.Context {
	c := &context{xemu: p}
	c.args.siginfo = &c.signalInfo
	c.interrupt.Dst = c
	return c
}

// asPoolGet returns an idle address space, or nil if the pool is empty.
func (p *XEMU) asPoolGet() *addressSpace {
	p.asPoolMu.Lock()
	defer p.asPoolMu.Unlock()
	if len(p.asPool) == 0 {
		return nil
	}
	as := p.asPool[len(p.asPool)-1]
	p.asPool[len(p.asPool)-1] = nil
	p.asPool = p.asPool[:len(p.asPool)-1]
	return as
}

// asPoolPut empties as and returns it to the pool. It reports whether as was
// pooled; if not, the caller must destroy it.
func (p *XEMU) asPoolPut(as *addressSpace) bool {
	p.asPoolMu.Lock()
	full := len(p.asPool) >= asPoolMax
	p.asPoolMu.Unlock()
	if full {
		return false
	}
	// Emptying the address space tears down every mapping the application had,
	// which can take a while, so do it outside the lock.
	if err := as.unmapRange(0, maxUserAddr); err != nil {
		log.Warningf("xemu: clearing address space for reuse: %v", err)
		return false
	}
	p.asPoolMu.Lock()
	defer p.asPoolMu.Unlock()
	if len(p.asPool) >= asPoolMax {
		return false
	}
	p.asPool = append(p.asPool, as)
	return true
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount. Each context
// runs on its own OS thread with its mm swapped, so concurrency is bounded only
// by the number of task goroutines.
func (*XEMU) ConcurrencyCount() int {
	return int(^uint(0) >> 1) // math.MaxInt
}

type constructor struct{}

// New implements platform.Constructor.New.
func (*constructor) New(opts platform.Options) (platform.Platform, error) {
	return New(opts.DeviceFile)
}

func init() {
	platform.Register("xemu", &constructor{})
}
