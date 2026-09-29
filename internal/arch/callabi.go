package arch

import "github.com/isesword/golem/internal/emu"

// CallResult is one function call's integer result: the primary return value
// plus an optional second return register (unused by AAPCS64 today; reserved
// for conventions/runtimes with dual returns).
type CallResult struct {
	Value  uint64
	Value2 uint64
}

// CallABI is the user-space function calling convention of one (ID, Variant)
// — AAPCS64 / AAPCS32 / SysV AMD64 / Win64. host↔guest calls and Function
// Interposition's return flow all go through this interface (DESIGN.md §3.2,
// §3.8). It is separate from Arch on purpose: the return-address concept (LR)
// lives here, not on the CPU — ARM has an LR register, AMD64 does not
// (invariant 13).
type CallABI interface {
	// Arg returns the register carrying integer argument i of a plain
	// function call (AAPCS64: X0+i, i in [0,7]). An out-of-range i panics:
	// asking for a 9th integer argument register is a programming error,
	// not a guest condition.
	//
	// Arg and Ret are the register-level primitives ReadArgs/WriteResult are
	// defined over; callers on hot paths (the emulator's scheduler, JNI
	// dispatch, host fns) cache them ONCE at boot rather than walking the
	// interface per call (DESIGN.md §8).
	Arg(i int) emu.Reg
	// Ret returns the integer return-value register.
	Ret() emu.Reg

	// ReadArgs reads integer arguments 0..n-1 of the call currently in
	// flight (register portion first, then the stack spill area).
	//
	// Stack-spill argument support (>8 integer args on AAPCS64) is NOT
	// implemented at this stage — no current call path needs it — and
	// returns an error naming the limit; add it when a consumer appears.
	ReadArgs(b emu.Backend, n int) ([]uint64, error)

	// WriteResult writes a call's result back per the convention
	// (AAPCS64: X0 = Value; Value2 currently unused).
	WriteResult(b emu.Backend, r CallResult) error

	// ReturnFromCall performs one function return's register/stack effect:
	//
	//	ARM64:       PC ← X30 (LR)
	//	AMD64 SysV:  retAddr ← [RSP]; RSP += ptrSize; PC ← retAddr
	//
	// Function Interposition's host-function return path depends on this
	// (DESIGN.md §3.8): after WriteResult, the interceptor hands control
	// back to the guest caller through ReturnFromCall.
	ReturnFromCall(b emu.Backend) error

	// LR reports the register holding the return address. The concept
	// belongs to the calling convention, not the CPU: ARM keeps it in a
	// register (X30); AMD64 keeps it on the stack, where this accessor's
	// register-based shape does not apply — a stack-returning convention
	// expresses the same role through ReturnFromCall instead.
	LR() emu.Reg
}
