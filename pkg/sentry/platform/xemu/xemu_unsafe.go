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
	"runtime"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

// switchArgs matches struct xemu_switch_args: two userspace pointers that the
// module reads the initial register state from and writes the trap-point state
// back to. On arm64 the module reads user_pt_regs + tp_value (TPIDR_EL0) from
// regs; arch.Registers places TPIDR_EL0 immediately after the embedded
// PtraceRegs, so &Regs.PtraceRegs covers both.
//
// regs is a uintptr rather than a *linux.PtraceRegs because NotifyInterrupt
// poisons it, which the garbage collector must not see. Switch keeps the
// registers alive across the switch instead.
type switchArgs struct {
	regs    uintptr
	siginfo *linux.SignalInfo
}

// regsPoison is set in switchArgs.regs to make the module's copy_from_user of
// the register state fail with EFAULT, so a switch that has not yet entered the
// kernel does not run the application. Bit 63 is set in every kernel address
// and clear in every userspace address on both amd64 and arm64.
const regsPoison = 1 << 63

// setRegs publishes the registers the next switch reads, clearing any poison
// left behind by NotifyInterrupt. It must be called before the interrupt
// forwarder is armed, so that a poison cannot be lost.
func (c *context) setRegs(regs *linux.PtraceRegs) {
	atomic.StoreUintptr(&c.args.regs, uintptr(unsafe.Pointer(regs)))
}

// poisonRegs makes a switch that has not read its register state yet fail with
// EFAULT rather than run the application. See NotifyInterrupt.
func (c *context) poisonRegs() {
	atomic.StoreUintptr(&c.args.regs, atomic.LoadUintptr(&c.args.regs)|regsPoison)
}

// regsPoisoned reports whether the registers are poisoned, i.e. whether an
// EFAULT from the switch was caused by an interrupt rather than a real fault.
func (c *context) regsPoisoned() bool {
	return atomic.LoadUintptr(&c.args.regs)&regsPoison != 0
}

// xemuSwitchToApp (declared per-arch in xemu_amd64.go / xemu_arm64.go) runs the
// application on the current thread until it traps, saving and restoring
// floating point state around the switch ioctl and releasing the P for the
// duration. It returns the raw ioctl result: 0 for a syscall, a positive signal
// number for a fault/signal, or a negative errno.

// Use go:linkname to call into the runtime so the blocking switch ioctl
// relinquishes its P, allowing other task goroutines to run. These are the
// same runtime entry points used by the kvm platform.

//go:linkname entersyscall runtime.entersyscall
func entersyscall()

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()

// These forwarding functions must be nosplit because we must disallow
// preemption between entersyscall and exitsyscall, and the switch asm frame
// cannot be grown or moved.
//
// entersyscall (lazy P release, reclaimed by sysmon only if the switch blocks
// long) is used rather than entersyscallblock (eager P handoff): the switch
// ioctl usually returns fast because the application traps almost immediately,
// so eager handoff measured ~19% worse single-threaded and far worse under
// concurrency. This mirrors the kvm platform's choice.

//go:nosplit
func callEntersyscall() { entersyscall() }

//go:nosplit
func callExitsyscall() { exitsyscall() }

// beforeFork and afterFork bracket a raw fork in Go; they mask signals and
// suspend the runtime's fork-hostile bookkeeping. See ptrace/subprocess_unsafe.

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

// mmap issues XEMU_MMAP on the address-space fd.
func (as *addressSpace) mmap(args *mmapArgs) error {
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(as.fd), xemuMmap, uintptr(unsafe.Pointer(args))); errno != 0 {
		return errno
	}
	return nil
}

// munmap issues XEMU_MUNMAP on the address-space fd.
func (as *addressSpace) munmap(args *munmapArgs) error {
	if errno := hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(as.fd), xemuMunmap, uintptr(unsafe.Pointer(args))); errno != 0 {
		return errno
	}
	return nil
}

// startDonor forks the donor helper process (see type donor). The donor gets
// its own copy of the fd table (immediately pruned to just its socket end by
// donorMain); address-space fds are passed to it explicitly via SCM_RIGHTS. It
// must run on a locked OS thread with a consistent runtime state, matching the
// beforeFork/afterFork contract.
//
//go:norace
func startDonor(fds [2]int, parentPid int) (*donor, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	beforeFork()
	pid, _, errno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 {
		afterFork()
		return nil, errno
	}
	if pid == 0 {
		// Donor process: signals stay blocked (from beforeFork) and it issues
		// only raw syscalls. Never returns.
		donorMain(uintptr(fds[1]), uintptr(parentPid))
	}
	afterFork()
	// The donor keeps only its inherited copy of fds[1] (donorMain closes the
	// rest of its table copy). The sentry uses fds[0] and keeps fds[1] open so
	// a re-forked donor can inherit it again.
	return &donor{sock: fds[0]}, nil
}

// Linux struct iovec, msghdr, and one-fd cmsg for the raw recvmsg in donorMain.
// Pointer fields are uintptrs: they only ever hold addresses of donorMain stack
// locals, which cannot move (nosplit, and no Go runtime runs in the donor).
type rawIovec struct {
	base uintptr
	len  uint64
}

type rawMsghdr struct {
	name       uintptr
	namelen    uint32
	_          uint32
	iov        uintptr
	iovlen     uint64
	control    uintptr
	controllen uint64
	flags      int32
	_          uint32
}

type rawCmsg struct {
	len   uint64
	level int32
	typ   int32
	fd    int32
	_     int32
}

// rawCmsgLen is CMSG_LEN(sizeof(int)): the cmsg_len the kernel reports for a
// single received fd.
const rawCmsgLen = 20

// donorMain is the donor helper's request loop. It runs in a forked child with
// no working Go runtime, so it uses only raw syscalls and its own fixed stack:
// it must never allocate, grow the stack, or call into the runtime. Signals are
// blocked (inherited from beforeFork), so its syscalls are not interrupted.
//
//go:nosplit
//go:norace
func donorMain(sock, parentPid uintptr) {
	// Die when the sentry does. The sentry keeps the socket's peer end open for
	// its whole life (a re-forked donor must be able to inherit it), so a read
	// here never reports EOF; PR_SET_PDEATHSIG is the real teardown
	// (belt-and-braces with the sandbox's process teardown). Re-check the parent
	// did not already exit in the window between the clone and here.
	unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0)
	if ppid, _, _ := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0); ppid != parentPid {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
	}

	// The fork copied the sentry's whole fd table (address spaces, guest
	// memory, host files). Keep only the request socket: anything else held
	// here stays alive for as long as the donor does, and a donor stuck
	// exiting (e.g. wedged behind a lock during sandbox teardown) must not pin
	// a dead sandbox's resources.
	if sock > 0 {
		unix.RawSyscall(unix.SYS_CLOSE_RANGE, 0, sock-1, 0)
	}
	unix.RawSyscall(unix.SYS_CLOSE_RANGE, sock+1, uintptr(^uint32(0)), 0)

	for {
		// Request: msg[0:4] is the sequence number (echoed in the reply);
		// msg[4:8] is reserved. The address-space fd arrives as SCM_RIGHTS
		// ancillary data, since the donor has its own fd table. Reply: msg[4:8]
		// is the bind status.
		var msg [8]byte
		var cmsg rawCmsg
		iov := rawIovec{base: uintptr(unsafe.Pointer(&msg[0])), len: 8}
		hdr := rawMsghdr{
			iov:        uintptr(unsafe.Pointer(&iov)),
			iovlen:     1,
			control:    uintptr(unsafe.Pointer(&cmsg)),
			controllen: uint64(unsafe.Sizeof(cmsg)),
		}
		n, _, _ := unix.RawSyscall(unix.SYS_RECVMSG, sock, uintptr(unsafe.Pointer(&hdr)), 0)
		// A healthy sentry never closes the socket or sends a malformed
		// request; treat anything else as fatal and exit rather than spin.
		if n != 8 || hdr.flags&unix.MSG_CTRUNC != 0 || cmsg.len != rawCmsgLen ||
			cmsg.level != unix.SOL_SOCKET || cmsg.typ != unix.SCM_RIGHTS {
			unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		}
		asfd := uintptr(cmsg.fd)

		// Fork a grandchild that binds its (small, copy-of-donor) mm and exits
		// with the bind errno as status.
		pid, _, cloneErrno := unix.RawSyscall6(unix.SYS_CLONE, uintptr(unix.SIGCHLD), 0, 0, 0, 0, 0)
		if pid == 0 {
			_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, asfd, xemuBind, 0)
			unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(errno), 0, 0)
		}

		var status uint32
		if cloneErrno != 0 {
			// No grandchild was forked, so report the clone errno rather than
			// waiting on a child that doesn't exist.
			status = uint32(cloneErrno)
		} else {
			var ws int32
			unix.RawSyscall6(unix.SYS_WAIT4, pid, uintptr(unsafe.Pointer(&ws)), 0, 0, 0, 0)
			if ws&0x7f != 0 {
				// Killed by a signal before it could report the bind result
				// (e.g. an OOM SIGKILL); WEXITSTATUS would be 0, a false
				// success. Report a transient error so the caller retries.
				status = uint32(unix.EAGAIN)
			} else {
				status = uint32(ws>>8) & 0xff // WEXITSTATUS
			}
		}
		// The bound mm is now held by the address-space file; drop the donor's
		// reference to the fd.
		unix.RawSyscall(unix.SYS_CLOSE, asfd, 0, 0)

		// Reply: keep the echoed sequence in msg[0:4], set the status.
		msg[4], msg[5], msg[6], msg[7] = byte(status), byte(status>>8), byte(status>>16), byte(status>>24)
		unix.RawSyscall(unix.SYS_WRITE, sock, uintptr(unsafe.Pointer(&msg[0])), 8)
	}
}

// The module encodes the faulting access in the x86 page-fault error-code format
// in the siginfo on both arches (on arm64 it normalizes the ESR into these same
// bits), so the decode is arch-neutral. These are linux.X86_PF_INSTR/X86_PF_WRITE,
// spelled out because those constants are amd64-only in gVisor.
const (
	faultInstr = 0x10 // X86_PF_INSTR
	faultWrite = 0x02 // X86_PF_WRITE
)

// faultAccessType decodes the access type of a fault from the error code the
// module stores in the siginfo, matching systrap's sigErrorToAccessType.
func faultAccessType(si *linux.SignalInfo) hostarch.AccessType {
	code := hostarch.ByteOrder.Uint32(si.Fields[108:112])
	switch {
	case code&faultInstr != 0:
		return hostarch.AccessType{Execute: true}
	case code&faultWrite != 0:
		return hostarch.AccessType{Write: true}
	default:
		return hostarch.AccessType{Read: true}
	}
}
