package arch

import "github.com/isesword/golem/internal/emu"

// CallResult is one function call's integer result: the primary return value
// plus an optional second return register (SysV AMD64: RDX is the high half of
// a 128-bit result; AAPCS64 ignores Value2 today).
type CallResult struct {
	Value  uint64
	Value2 uint64
}

// ArgKind is the width/alignment class of one call argument (Architecture
// Exception #1). It exists because the legacy []uint64 could
// not distinguish (uint32)1 from (uint64)1 — a distinction 32-bit ABIs
// MUST make: AAPCS32 and the Linux EABI place a 64-bit argument in an
// EVEN-NUMBERED register pair (r0:r1 or r2:r3), so a preceding 32-bit
// argument changes where the pair lands.
type ArgKind uint8

const (
	// ArgWord is one machine word of the TARGET's natural width: a single
	// 64-bit slot on 64-bit ABIs, one 32-bit register/stack word (the low
	// half of Value) on 32-bit ABIs. This is the legacy []uint64 semantics —
	// the default for callers with no width knowledge (plain integer args,
	// guest register values forwarded verbatim).
	ArgWord ArgKind = iota
	// ArgU64 is an unsigned 64-bit integer. On 32-bit ABIs it occupies an
	// even register pair / 8-byte stack slot; on 64-bit ABIs it is a single
	// slot, bit-identical to ArgWord.
	ArgU64
	// ArgI64 is a signed 64-bit integer. Same placement as ArgU64; the
	// distinction matters on the READ side (sign interpretation when a
	// 32-bit guest retrieves it), not on placement.
	ArgI64
	// ArgPtr is a guest pointer of the target's width: one 64-bit slot on
	// 64-bit ABIs, one 32-bit word on 32-bit ABIs. Placement matches
	// ArgWord today; the kind exists so precision paths (JNI, marshalers)
	// can state intent — and so a future ABI that boxes pointers has a
	// place to hang the rule.
	ArgPtr
)

// CallArg is one typed call argument: the value plus its width/alignment
// class (Architecture Exception #1 — see ArgKind). 64-bit ABIs
// (AAPCS64, SysV AMD64) treat every kind as a single 64-bit slot, so typed
// and untyped calls are bit-identical there; the kind becomes load-bearing
// on 32-bit ABIs (AAPCS32).
type CallArg struct {
	Value uint64
	Kind  ArgKind
}

// WordArgs maps plain 64-bit words to ArgWord CallArgs — the convenience
// entry for callers with no width/alignment knowledge (exactly the legacy
// []uint64 semantics).
func WordArgs(args ...uint64) []CallArg {
	if len(args) == 0 {
		return nil
	}
	out := make([]CallArg, len(args))
	for i, v := range args {
		out[i] = CallArg{Value: v, Kind: ArgWord}
	}
	return out
}

// CallRequest is one host→guest function call to establish: the entry point,
// the return address the callee hands control back to (a stop sentinel in
// practice), and the typed integer arguments. PrepareCall builds the call
// frame on the thread's EXISTING stack — it never allocates a stack and
// knows nothing about the AddressSpace.
type CallRequest struct {
	Entry  emu.GuestAddr // function entry; becomes PC
	Return emu.GuestAddr // return address (LR on ARM64; pushed on AMD64)
	Args   []CallArg     // typed arguments in order; excess spill to the stack
}

// CallABI is the user-space function calling convention of one (ID, Variant)
// — AAPCS64 / AAPCS32 / SysV AMD64 / Win64. host↔guest calls and Function
// Interposition's return flow all go through this interface (DESIGN.md §3.2,
// §3.8). It is separate from Arch on purpose: the return-address concept
// lives here, not on the CPU — ARM has an LR register, AMD64 keeps the return
// address on the stack (invariant 13).
//
// The whole-call model reshaped the interface: call
// establishment (PrepareCall), argument reads (ReadArgs) and result access
// (WriteResult/ReadResult) are convention-level transactions, so callers
// never name an argument/result/link register. Register-shaped questions are
// NOT part of the core contract — they live on the optional
// CallABIIntrospector interface below (debugger / inline hooks), so a future
// convention whose arguments do not map to plain registers is not forced to
// invent fake ones.
//
// Architecture Exception #1 introduced typed arguments: PrepareCall consumes
// []CallArg. Implementations for 64-bit conventions (AAPCS64, SysV AMD64)
// place every ArgKind in one 64-bit slot — bit-identical to the legacy
// behavior; a 32-bit convention (AAPCS32) interprets ArgWord/ArgPtr as one
// 32-bit word and ArgU64/ArgI64 as an even register pair / 8-byte stack
// slot. ReadArgs still reports plain words (the pair interpretation is the
// reader's convention detail).
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

	// ReadReturnAddress is the OBSERVATION semantic — "where does the
	// in-flight call return to", per convention:
	//
	//	ARM64:       X30 (LR)
	//	ARM32:       R14 (LR, verbatim — bit0 may carry the Thumb state of
	//	             the return site, exactly as ReturnFromCall consumes it)
	//	AMD64 SysV:  [RSP] (8-byte little-endian read at the current SP)
	//
	// Valid at FUNCTION-ENTRY call state. At an arbitrary PC the read still
	// succeeds (it is a register/stack observation), but the caller decides
	// whether that value MEANS a return address — the facade gates this by
	// hook kind and reports ErrContextUnavailable where it does not.
	ReadReturnAddress(b emu.Backend) (emu.GuestAddr, error)

	// InstallReturnContinuation REPLACES the existing return continuation
	// of the IN-FLIGHT call (wrap continuation, ABI observation+control
	// semantics). Frame-construction contract: PrepareCall BUILDS a call
	// frame; this method must NOT create one — it only rewrites where the
	// already-entered frame's existing return lands:
	//
	//	ARM64:       LR ← post
	//	ARM32:       LR ← post (bit0 may set the continuation's ISA state)
	//	AMD64 SysV:  [RSP] ← post in place — the caller's `call` pushed the
	//	             return address there; the original's `ret` pops post with
	//	             the stack back at the caller's exact state. (Pushing here
	//	             would strand the real return below the caller's SP — the
	//	             push that IS legitimate on this ABI belongs to
	//	             PrepareCall, which constructs the frame.)
	//
	// Valid in the ENTRY state, immediately before the original function
	// runs: the original's return then lands on the wrap's post
	// continuation instead of the real caller, whose return address was
	// captured first (ReadReturnAddress). The post continuation resumes the
	// real caller through ReturnTo.
	InstallReturnContinuation(b emu.Backend, post emu.GuestAddr) error

	// ReturnTo transfers control to an explicit address — the wrap post
	// continuation's "resume the real caller" step (the caller's return
	// address was captured at entry, before InstallReturnContinuation
	// re-aimed the return):
	//
	//	ARM64:       PC ← target
	//	ARM32:       PC/CPSR.T ← target (setPCBX interworking semantics)
	//	AMD64 SysV:  RIP ← target
	ReturnTo(b emu.Backend, target emu.GuestAddr) error
}

// CallABIIntrospector is an optional capability a CallABI may implement for
// debugger / inline-hook introspection (e.g. Hook.SetArg rewriting one
// argument register). It is NOT part of the core call contract: call
// establishment must go through PrepareCall, never through these accessors.
// Consumers type-assert:
//
//	if intro, ok := abi.(arch.CallABIIntrospector); ok { ... }
type CallABIIntrospector interface {
	// ArgReg names the register carrying integer argument i. ok is false
	// when i has no register (beyond the register portion) — a
	// register-shaped answer does not exist for stack-spilled arguments.
	ArgReg(i int) (reg emu.Reg, ok bool)
	// ResultReg names the register carrying integer result i of the
	// convention (SysV: 0→RAX, 1→RDX; AAPCS64: 0→X0). ok is false when the
	// convention has no such result register.
	ResultReg(i int) (reg emu.Reg, ok bool)
}
