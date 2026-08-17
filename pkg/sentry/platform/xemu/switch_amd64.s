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

#include "funcdata.h"
#include "textflag.h"

#define SYS_IOCTL	16
#define XEMU_SWITCH	0x7813

// Must match the xsaveMode constants in xemu_amd64.go.
#define XSAVE_MODE_XSAVE	1
#define XSAVE_MODE_XSAVEOPT	2

// The XSAVE-family RFBM, restricting the switch to the components gVisor
// manages: the hardware ANDs it with XCR0, and it must not be widened to the
// host's whole XCR0. Anything outside this set (PKRU, CET, AMX) belongs to the
// sentry's own thread state, which is not saved across the switch, and to
// state the application's fpu.State has no room for.
#define XCR0_EAX 231 // +checkconst fpu SupportedXFeatureStates
#define XCR0_EDX 0

// xemuSwitchToApp runs the application on the current thread until it traps.
//
// The XEMU module only swaps general-purpose registers and the fs/gs base, so
// this routine restores the application's floating point state before the
// switch ioctl and saves it after. MXCSR and the x87 control word are the only
// floating point state the sentry needs preserved across the switch: Go treats
// the SSE/AVX registers as clobbered by a call and never uses x87. Saving just
// those two is much cheaper than an XSAVE/XRSTOR pair of the sentry's own
// state, and mirrors what ring0 does around a switch to the application.
//
// callEntersyscall relinquishes the P so other task goroutines can run while
// the application executes.
//
// func xemuSwitchToApp(asfd uintptr, args *switchArgs, guestFP *byte, xsaveMode uintptr) uintptr
TEXT ·xemuSwitchToApp(SB), NOSPLIT, $16-40
	// The locals hold only the saved control words; the GC may scan this
	// goroutine while it is parked in the switch ioctl, so they must be
	// declared pointer-free or stack scanning throws "missing stackmap".
	NO_LOCAL_POINTERS
	CALL	·callEntersyscall(SB)

	STMXCSR	mxcsr-16(SP)
	FSTCW	cw-8(SP)

	// Restore the application's floating point state.
	MOVQ	guestFP+16(FP), DI
	MOVQ	xsaveMode+24(FP), BX
	TESTQ	BX, BX
	JZ	no_xrstor
	MOVL	$XCR0_EAX, AX
	MOVL	$XCR0_EDX, DX
	XRSTOR64	(DI)
	JMP	fprestore_done
no_xrstor:
	FXRSTOR64	(DI)
fprestore_done:

	// ioctl(asfd, XEMU_SWITCH, args): runs the application until it traps.
	MOVQ	asfd+0(FP), DI
	MOVQ	$XEMU_SWITCH, SI
	MOVQ	args+8(FP), DX
	MOVQ	$SYS_IOCTL, AX
	SYSCALL
	// Publish the result before touching the FPU, so that neither the save
	// below nor callExitsyscall can clobber it.
	MOVQ	AX, ret+32(FP)

	// Save the application's floating point state.
	MOVQ	guestFP+16(FP), DI
	MOVQ	xsaveMode+24(FP), BX
	TESTQ	BX, BX
	JZ	no_xsave
	MOVL	$XCR0_EAX, AX
	MOVL	$XCR0_EDX, DX
	CMPQ	BX, $XSAVE_MODE_XSAVEOPT
	JNE	no_xsaveopt
	XSAVEOPT64	(DI)
	JMP	fpsave_done
no_xsaveopt:
	XSAVE64	(DI)
	JMP	fpsave_done
no_xsave:
	FXSAVE64	(DI)
fpsave_done:

	// Restore the sentry's control words, after the save above so that the
	// application's versions are preserved before being clobbered here. FLDCW
	// is a waiting instruction, so any exception the application left pending
	// would be raised by it; clear those first (XRSTOR restores them on the
	// next switch).
	LDMXCSR	mxcsr-16(SP)
	FCLEX
	FLDCW	cw-8(SP)

	CALL	·callExitsyscall(SB)
	RET
