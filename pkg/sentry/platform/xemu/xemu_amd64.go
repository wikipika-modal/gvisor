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

//go:build amd64
// +build amd64

package xemu

import (
	"bytes"
	"os"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// maxUserAddr is the first address that may not be used by applications: the
// x86-64 user address ceiling TASK_SIZE_MAX, which is itself 2^47 - PAGE_SIZE.
const maxUserAddr = 0x00007ffffffff000

// archInit derives the FP save/restore mode from the host CPU and warns if the
// host maps a vsyscall page.
func (p *XEMU) archInit() {
	fpu.InitHostState()
	fs := cpuid.HostFeatureSet()
	switch {
	case fs.UseXsaveopt():
		p.xsaveMode = xsaveModeXsaveopt
	case fs.UseXsave():
		p.xsaveMode = xsaveModeXsave
	default:
		p.xsaveMode = xsaveModeFxsave
	}

	// The application runs in a real host mm, so a host vsyscall page (if the
	// kernel mapped one) is directly reachable and services the legacy
	// gettimeofday/time/getcpu entry points without a trap, bypassing sentry
	// mediation. XEMU requires the host booted with vsyscall=none; warn if not.
	if vsyscallMapped() {
		log.Warningf("xemu: host vsyscall page is mapped; boot with vsyscall=none or applications will bypass the sentry for legacy vsyscalls")
	}
}

// vsyscallMapped reports whether the host kernel maps a vsyscall page (i.e. it
// was not booted vsyscall=none). It fails open: an unreadable maps file yields
// false, since the check is advisory.
func vsyscallMapped() bool {
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return false
	}
	return bytes.Contains(maps, []byte("[vsyscall]"))
}

// cpuidFaultUnsupported records that the host does not support CPUID faulting,
// so the application sees the host CPUID rather than the sentry's feature set.
// This is a property of the CPU, so one failure applies to every thread.
var cpuidFaultUnsupported atomicbitops.Bool

// enableCPUIDFault makes CPUID executed by the application raise SIGSEGV, so
// that Switch can emulate it against the sentry's feature set instead of
// letting the application read the host CPU directly.
//
// ARCH_SET_CPUID is per-thread and a task goroutine migrates between threads,
// so this is memoized against the thread the previous switch ran on rather than
// done once per context. Enabling it twice on a thread is harmless.
func (c *context) enableCPUIDFault(tid uint64) {
	if c.cpuidFaultTID == tid || cpuidFaultUnsupported.Load() {
		return
	}
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_ARCH_PRCTL, linux.ARCH_SET_CPUID, 0, 0); errno != 0 {
		cpuidFaultUnsupported.Store(true)
		log.Warningf("xemu: cannot enable CPUID faulting (%v); applications will see the host CPUID", errno)
		return
	}
	c.cpuidFaultTID = tid
}

// xemuSwitchToApp is the amd64 switch: the module swaps only general-purpose
// registers and the fs/gs base, so the asm restores and saves the application's
// x87/SSE/AVX state (XSAVE-family when supported, else FXSAVE) around the
// ioctl.
//
//go:noescape
func xemuSwitchToApp(asfd uintptr, args *switchArgs, guestFP *byte, xsaveMode uintptr) uintptr

// switchToApp runs the application until it traps.
func (c *context) switchToApp(asfd uintptr, fp *fpu.State) uintptr {
	return xemuSwitchToApp(asfd, &c.args, fp.BytePointer(), uintptr(c.xemu.xsaveMode))
}
