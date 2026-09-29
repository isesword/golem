package arch

import "github.com/isesword/golem/internal/emu"

// CallResult is one function call's integer result: the primary return value
// plus an optional second return register (SysV AMD64: RDX is the high half of
// a 128-bit result; AAPCS64 ignores Value2 today).
type CallResult struct {
	Value  uint64
	Value2 uint64
}

// CallRequest is one host→guest function call to establish: the entry point,
// the return address the callee hands control back to (a stop sentinel in
// practice), and the integer arguments. PrepareCall builds the call frame on
// the thread's EXISTING stack — it never allocates a stack and knows nothing
// about the AddressSpace.
type CallRequest struct {
	Entry  emu.GuestAddr // function entry; becomes PC
	Return emu.GuestAddr // return address (LR on ARM64; pushed on AMD64)
	Args   []uint64      // integer arguments in order; excess spill to the stack
}

// CallABI is the user-space function calling convention of one (ID, Variant)
// — AAPCS64 / AAPCS32 / SysV AMD64 / Win64. host↔guest calls and Function
// Interposition's return flow all go through this interface (DESIGN.md §3.2,
// §3.8). It is separate from Arch on purpose: the return-address concept
// lives here, not on the CPU — ARM has an LR register, AMD64 keeps the return
// address on the stack (invariant 13).
//
// P5a.5 reshaped the interface around whole-call operations: call
// establishment (PrepareCall), argument reads (ReadArgs) and result access
// (WriteResult/ReadResult) are convention-level transactions, so callers
// never name an argument/result/link register. The one exception is ArgReg —
// a debugger-grade introspection accessor (inline hooks rewriting an argument
// register); it must never appear on a call-establishment path.
type CallABI interface {
	// PrepareCall establishes a call frame for req on the current thread's
	// existing stack and registers:
	//
	//	ARM64:       X0..X7 ← Args[0:8]; Args[8:] at [SP, #(i-8)*8] (SP
	//	             decremented, 16-aligned); LR ← Return; PC ← Entry
	//	AMD64 SysV:  RDI/RSI/RDX/RCX/R8/R9 ← Args[0:6]; Args[6:] pushed
	//	             above the return address ([RSP+8+(i-6)*8] at entry);
	//	             [RSP] ← Return; entry RSP ≡ 8 (mod 16); PC ← Entry
	//
	// The stack must already exist (SP valid, memory mapped); PrepareCall
	// only moves SP within it. AMD64: nothing below the new RSP is written —
	// the 128-byte red zone of the frame being created stays intact.
	PrepareCall(b emu.Backend, req CallRequest) error

	// ReadArgs reads integer arguments 0..n-1 of the call currently in
	// flight (register portion first, then the stack spill area — valid at
	// function entry, before the callee moves SP).
	ReadArgs(b emu.Backend, n int) ([]uint64, error)

	// WriteResult writes a call's result back per the convention
	// (AAPCS64: X0 = Value; SysV: RAX = Value, RDX = Value2).
	WriteResult(b emu.Backend, r CallResult) error

	// ReadResult reads the call's result registers per the convention — the
	// exact inverse of WriteResult (AAPCS64: Value = X0; SysV: Value = RAX,
	// Value2 = RDX). CallFunc reports its return value through this.
	ReadResult(b emu.Backend) (CallResult, error)

	// ReturnFromCall performs one function return's register/stack effect:
	//
	//	ARM64:       PC ← X30 (LR)
	//	AMD64 SysV:  retAddr ← [RSP]; RSP += ptrSize; PC ← retAddr
	//
	// Function Interposition's host-function return path depends on this
	// (DESIGN.md §3.8): after WriteResult, the interceptor hands control
	// back to the guest caller through ReturnFromCall.
	ReturnFromCall(b emu.Backend) error

	// ArgReg names the register carrying integer argument i, for debugger /
	// inline-hook introspection (e.g. Hook.SetArg rewriting one argument).
	// ok is false when i has no register (beyond the register portion) — a
	// register-shaped answer does not exist for stack-spilled arguments.
	// Call establishment must go through PrepareCall, never through ArgReg.
	ArgReg(i int) (reg emu.Reg, ok bool)

	// --- transitional (P5a.5) ---------------------------------------------
	// Arg/Ret/LR are the pre-P5a.5 register-shaped role accessors, retained
	// while the emulator's call path migrates to the whole-call operations
	// above; they are removed in the P5a.5 cleanup commit. New code must not
	// use them.
	Arg(i int) emu.Reg
	Ret() emu.Reg
	// LR reports the register holding the return address; conventions
	// without one (SysV AMD64) report a sentinel that maps to no engine
	// register. Removed with the migration — the return-address role is
	// expressed through PrepareCall/ReturnFromCall.
	LR() emu.Reg
}
