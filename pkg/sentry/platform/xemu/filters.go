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
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// SeccompInfo implements platform.Platform.SeccompInfo.
func (*XEMU) SeccompInfo() platform.SeccompInfo {
	rules := map[uintptr]seccomp.SyscallRule{
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuSwitch)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuInterrupt)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuMmap)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuMunmap)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuBind)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuCreateAddressSpace)},
			seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.EqualTo(xemuVersion)},
		},
		// The two forks this platform performs (the sentry's runtime
		// threads are covered by the base sentry filter): the sentry forks
		// the donor, and the donor forks each bind grandchild; both are
		// plain children. clone's first arg is the flags.
		unix.SYS_CLONE: seccomp.PerArg{seccomp.EqualTo(uintptr(unix.SIGCHLD))},
		unix.SYS_WAIT4: seccomp.MatchAll{},
		// The donor sets PR_SET_PDEATHSIG so it dies with the sentry, and
		// checks getppid to detect a parent that died during startup.
		unix.SYS_PRCTL:   seccomp.PerArg{seccomp.EqualTo(unix.PR_SET_PDEATHSIG), seccomp.EqualTo(unix.SIGKILL)},
		unix.SYS_GETPPID: seccomp.MatchAll{},
		// Each bind request carries the address-space fd as SCM_RIGHTS data:
		// sendmsg on the sentry side, recvmsg in the donor. close_range is
		// the donor pruning its inherited copy of the sentry's fd table.
		unix.SYS_SENDMSG:     seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.AnyValue{}, seccomp.EqualTo(0)},
		unix.SYS_RECVMSG:     seccomp.PerArg{seccomp.NonNegativeFD{}, seccomp.AnyValue{}, seccomp.EqualTo(0)},
		unix.SYS_CLOSE_RANGE: seccomp.PerArg{seccomp.AnyValue{}, seccomp.AnyValue{}, seccomp.EqualTo(0)},
	}
	for sysno, rule := range archSyscallFilters() {
		rules[sysno] = rule
	}
	return platform.StaticSeccompInfo{
		PlatformName: "xemu",
		Filters:      seccomp.MakeSyscallRules(rules),
	}
}

// PrecompiledSeccompInfo implements platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{(*XEMU)(nil).SeccompInfo()}
}
