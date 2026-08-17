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

//go:build arm64
// +build arm64

package xemu

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// maxUserAddr is the first address that may not be used by applications. On
// arm64 the user address range depends on the host's VA size (39/48/52-bit), so
// it is derived from the probed TASK_SIZE in archInit rather than a fixed
// constant.
var maxUserAddr uint64

// archInit configures the arm64 user address range from the host's TASK_SIZE.
// arm64 has no XSAVE/xcr0 equivalent (the switch asm uses fixed-layout FPSIMD),
// so nothing FP-related is set here.
func (p *XEMU) archInit() {
	arch.ConfigureAddressSpace(uintptr(linux.TaskSize))
	maxUserAddr = uint64(linux.TaskSize)
}

// enableCPUIDFault is a no-op: arm64 has no CPUID instruction to trap.
func (c *context) enableCPUIDFault(tid uint64) {}

// xemuSwitchToApp is the arm64 switch: the module swaps general-purpose
// registers and TPIDR_EL0 but not FPSIMD, so the asm restores and saves the
// application's FPSIMD vector registers and FPSR/FPCR around the ioctl. There
// is no XSAVE-style feature selection on arm64.
//
//go:noescape
func xemuSwitchToApp(asfd uintptr, args *switchArgs, guestFP *byte) uintptr

// switchToApp runs the application until it traps.
func (c *context) switchToApp(asfd uintptr, fp *fpu.State) uintptr {
	return xemuSwitchToApp(asfd, &c.args, fp.BytePointer())
}
