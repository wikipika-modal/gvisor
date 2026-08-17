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

#define SYS_IOCTL	29
#define XEMU_SWITCH	0x7813

// The FP buffer is gVisor's arm64 fpu.State, i.e. struct fpsimd_context (528
// bytes, matching arch.FpsimdContext and ring0's SaveVRegs/LoadVRegs): an 8-byte
// header, then FPSR and FPCR (u32 each) at offsets 8 and 12, then the 32 128-bit
// vector registers (q0..q31) at offset 16. SAVE_FPSTATE/LOAD_FPSTATE take the
// buffer base in R0 and move the whole state to/from it, clobbering R0 and R1.
// The q-register stp/ldp pairs at [x0],#32,...,#480 are emitted as WORDs because
// the Go assembler has no mnemonic for 128-bit SIMD register pairs.
//
// ring0.SaveFloatingPoint/LoadFloatingPoint move the same registers, but place
// FPSR and FPCR as 8-byte words at offsets 0 and 8 -- over the header and over
// both u32 fields -- so they disagree with every other reader of fpu.State and
// cannot be reused here.
#define SAVE_FPSTATE \
	MOVD	FPSR, R1; \
	MOVW	R1, 8(R0); \
	MOVD	FPCR, R1; \
	MOVW	R1, 12(R0); \
	ADD	$16, R0, R0; \
	WORD $0xad000400; \
	WORD $0xad010c02; \
	WORD $0xad021404; \
	WORD $0xad031c06; \
	WORD $0xad042408; \
	WORD $0xad052c0a; \
	WORD $0xad06340c; \
	WORD $0xad073c0e; \
	WORD $0xad084410; \
	WORD $0xad094c12; \
	WORD $0xad0a5414; \
	WORD $0xad0b5c16; \
	WORD $0xad0c6418; \
	WORD $0xad0d6c1a; \
	WORD $0xad0e741c; \
	WORD $0xad0f7c1e

#define LOAD_FPSTATE \
	MOVWU	8(R0), R1; \
	MOVD	R1, FPSR; \
	MOVWU	12(R0), R1; \
	MOVD	R1, FPCR; \
	ADD	$16, R0, R0; \
	WORD $0xad400400; \
	WORD $0xad410c02; \
	WORD $0xad421404; \
	WORD $0xad431c06; \
	WORD $0xad442408; \
	WORD $0xad452c0a; \
	WORD $0xad46340c; \
	WORD $0xad473c0e; \
	WORD $0xad484410; \
	WORD $0xad494c12; \
	WORD $0xad4a5414; \
	WORD $0xad4b5c16; \
	WORD $0xad4c6418; \
	WORD $0xad4d6c1a; \
	WORD $0xad4e741c; \
	WORD $0xad4f7c1e

// func xemuSwitchToApp(asfd uintptr, args *switchArgs, guestFP *byte) uintptr
TEXT ·xemuSwitchToApp(SB), NOSPLIT, $16-32
	NO_LOCAL_POINTERS
	CALL	·callEntersyscall(SB)

	// FPCR and FPSR are the only floating point state the sentry needs
	// preserved across the switch: Go treats the vector registers as clobbered
	// by a call. Saving just those two is much cheaper than saving and
	// restoring the sentry's whole FPSIMD state.
	MOVD	FPCR, R1
	MOVD	R1, fpcr-16(SP)
	MOVD	FPSR, R1
	MOVD	R1, fpsr-8(SP)

	// Restore the application's FPSIMD state.
	MOVD	guestFP+16(FP), R0
	LOAD_FPSTATE

	// ioctl(asfd, XEMU_SWITCH, args): runs the application until it traps.
	MOVD	asfd+0(FP), R0
	MOVD	$XEMU_SWITCH, R1
	MOVD	args+8(FP), R2
	MOVD	$SYS_IOCTL, R8
	SVC
	MOVD	R0, ret+24(FP)	// stash result; the caller frame survives below

	// Save the application's (possibly modified) FPSIMD state, then restore
	// the sentry's control registers.
	MOVD	guestFP+16(FP), R0
	SAVE_FPSTATE
	MOVD	fpcr-16(SP), R1
	MOVD	R1, FPCR
	MOVD	fpsr-8(SP), R1
	MOVD	R1, FPSR

	CALL	·callExitsyscall(SB)
	RET
