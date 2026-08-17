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
	"runtime"
	"sync"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/hosttid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/interrupt"
)

// context is a platform.Context backed by XEMU. A context corresponds to a
// single application thread; it is only ever switched by one task goroutine at
// a time.
type context struct {
	platform.NoCPUNumbers

	// xemu is the owning platform.
	xemu *XEMU

	// args is the argument struct for the switch ioctl. It lives here rather
	// than in the Switch frame because NotifyInterrupt poisons args.regs from
	// another goroutine.
	args switchArgs

	// signalInfo is the signal info populated by the module on a fault or
	// signal return. args.siginfo points to it.
	signalInfo linux.SignalInfo

	// interrupt is used to translate platform.Context.Interrupt into a
	// XEMU_INTERRUPT ioctl targeting the switching thread.
	interrupt interrupt.Forwarder

	// tid is the host thread ID currently blocked in a switch ioctl for this
	// context, or 0. It is read by NotifyInterrupt on another goroutine.
	tid atomicbitops.Uint64

	// cpuidFaultTID is the thread CPUID faulting was last enabled on; see
	// enableCPUIDFault. It is only accessed by the switching goroutine.
	cpuidFaultTID uint64
}

// Switch implements platform.Context.Switch.
func (c *context) Switch(ctx pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	as := mm.AddressSpace().(*addressSpace)
	// arch.Registers embeds linux.PtraceRegs with identical layout to the
	// kernel's struct user_regs_struct, which is what the module reads/writes.
	regs := &ac.StateData().Regs.PtraceRegs
	fp := ac.FloatingPointData()
	// The module reaches the register and floating point state through
	// args.regs, which is a uintptr the garbage collector cannot see through.
	defer runtime.KeepAlive(ac)

	// The switch runs the application on this OS thread with its mm swapped in,
	// so the thread must stay fixed for the duration and for interrupts to
	// target the right tid.
	//
	// The unlock must stay paired: a goroutine that exits while locked kills
	// its OS thread, and older module builds record sentry threads as the
	// application mm's mm->owner for memcg attribution, so a destroyed thread
	// could leave that pointer dangling. Pooled Go threads are never
	// destroyed, which keeps every possible owner alive for the sandbox's
	// life. (Current modules pin the dead bind task as the owner instead, but
	// unpaired thread churn would still be a per-switch thread leak.)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := hosttid.Current()
	c.tid.Store(tid)
	c.enableCPUIDFault(tid)
	// Publish the registers before arming the forwarder: once NotifyInterrupt
	// can run, it may poison them, and that must not be overwritten.
	c.setRegs(regs)

	if !c.interrupt.Enable() {
		// Already interrupted before we started.
		c.tid.Store(0)
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}

	for {
		ret := c.switchToApp(uintptr(as.fd), fp)

		// CPUID faulting turns the application's CPUID into a SIGSEGV so that
		// the sentry can answer it with its own feature set. Emulate and resume
		// without disarming the interrupt forwarder: an interrupt that arrives
		// during emulation poisons the registers and is taken below.
		if r := int64(ret); r > 0 && linux.Signal(r) == linux.SIGSEGV && platform.TryCPUIDEmulate(ctx, mm, ac) {
			continue
		}

		// Disable does not wait for a racing NotifyInterrupt: a stale notify
		// may still poison the registers (cleared by the next switch's
		// setRegs) or kick a thread that is no longer, or newly, switching.
		// Either costs at most one spurious ErrContextInterrupt.
		c.interrupt.Disable()
		c.tid.Store(0)

		switch r := int64(ret); {
		case r == 0:
			// The application made a system call; its number and arguments are
			// now in regs (orig_rax = number, rax = -ENOSYS).
			return nil, hostarch.NoAccess, nil
		case r > 0:
			// The application took a signal; r is the signal number and
			// signalInfo has been populated.
			c.signalInfo.Signo = int32(r)
			// Only SIGSEGV is treated as a potentially recoverable page fault
			// that the sentry should try to handle by mapping in a page. Other
			// signals, including SIGBUS (e.g. accessing a file mapping beyond a
			// truncated end), are real faults that must be delivered to the
			// application; a non-empty access type here would make the sentry
			// loop forever trying to map an unmappable page.
			at := hostarch.NoAccess
			if linux.Signal(r) == linux.SIGSEGV {
				at = faultAccessType(&c.signalInfo)
			}
			return &c.signalInfo, at, platform.ErrContextSignal
		default:
			return c.switchError(unix.Errno(-r))
		}
	}
}

// enomemOnce limits the warning for a switch that could not allocate.
var enomemOnce sync.Once

// switchError maps a failed switch ioctl to a platform error.
func (c *context) switchError(errno unix.Errno) (*linux.SignalInfo, hostarch.AccessType, error) {
	switch {
	case errno == unix.EINTR:
		// The switch was kicked out of the guest by XEMU_INTERRUPT.
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	case errno == unix.EFAULT && c.regsPoisoned():
		// The switch read the poisoned register pointer and returned without
		// running the application. See NotifyInterrupt.
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	case errno == unix.EAGAIN, errno == unix.ENOMEM:
		// EAGAIN: the module took the application off the CPU without running
		// anything it can observe. ENOMEM: it could not allocate a context for
		// the switch. In both cases the application did not run and its state is
		// unchanged, so the task simply switches again rather than dying. Report
		// the memory failure once, so that retrying it forever is not silent.
		if errno == unix.ENOMEM {
			enomemOnce.Do(func() {
				log.Warningf("xemu: switch failed to allocate a context; retrying")
			})
		}
		return nil, hostarch.NoAccess, platform.ErrContextCPUPreempted
	default:
		return nil, hostarch.NoAccess, &platform.ContextError{
			Err:   fmt.Errorf("xemu switch failed: %v", errno),
			Errno: errno,
		}
	}
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt. It is called
// on a goroutine other than the one blocked in Switch.
//
// A lone XEMU_INTERRUPT can be lost: the module delivers it as task work on the
// target thread, which drops it if that thread has not bound a context yet (it
// is momentarily between arming the forwarder and the parked ioctl), and the
// single-shot Forwarder never re-fires. Poisoning the register pointer closes
// that window from the other side: a switch that has not copied its arguments
// in yet fails with EFAULT instead of running the application, while one that
// is already in the guest is kicked out by the ioctl below and returns EINTR.
func (c *context) NotifyInterrupt() {
	c.poisonRegs()
	hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(c.xemu.deviceFile.FD()), xemuInterrupt, uintptr(c.tid.Load()))
}

// Interrupt implements platform.Context.Interrupt.
func (c *context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// Release implements platform.Context.Release.
func (c *context) Release() {}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *context) FullStateChanged() {}

// PullFullState implements platform.Context.PullFullState.
func (c *context) PullFullState(as platform.AddressSpace, ac *arch.Context64) error {
	return nil
}

// Preempt implements platform.Context.Preempt.
func (c *context) Preempt() {}

// PrepareSleep implements platform.Context.PrepareSleep.
func (c *context) PrepareSleep() {}

// PrepareUninterruptibleSleep implements
// platform.Context.PrepareUninterruptibleSleep.
func (c *context) PrepareUninterruptibleSleep() {}

// PrepareStop implements platform.Context.PrepareStop.
func (c *context) PrepareStop() {}

// PrepareExecve implements platform.Context.PrepareExecve.
func (c *context) PrepareExecve() {}

// PrepareExit implements platform.Context.PrepareExit.
func (c *context) PrepareExit() {}
