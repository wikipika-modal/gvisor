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
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// archSyscallFilters returns architecture-specific syscall filters.
func archSyscallFilters() map[uintptr]seccomp.SyscallRule {
	return map[uintptr]seccomp.SyscallRule{
		// enableCPUIDFault makes the application's CPUID trap so that the
		// sentry can emulate it.
		unix.SYS_ARCH_PRCTL: seccomp.PerArg{
			seccomp.EqualTo(linux.ARCH_SET_CPUID),
			seccomp.EqualTo(0),
		},
	}
}
