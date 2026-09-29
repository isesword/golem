package amd64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// sysV64 is the System V AMD64 user-space function calling convention
// (arch.CallABI): integer arguments in RDI/RSI/RDX/RCX/R8/R9, the result in
// RAX (with RDX as the high half of a 128-bit result), and the return address
// ON THE STACK — pushed by `call`, popped by `ret`. The zero value is valid
// and stateless.
//
// This is the FUNCTION call ABI only. The Linux x86-64 syscall ABI is a
// different convention (number in RAX, 4th argument in R10 — NOT RCX, which
// the `syscall` instruction itself clobbers) and lives in platform/android's
// LinuxAMD64Transport; the two must never be merged (P5a requirement: the
// RCX-vs-R10 difference is pinned by TestArgRegsVsSyscallABI).
type sysV64 struct{}

// numArgRegs is the number of integer argument registers (RDI..R9); further
// arguments spill to the stack (not implemented yet — see ReadArgs).
const numArgRegs = 6

// argRegs are the SysV integer argument registers in argument order.
var argRegs = [numArgRegs]emu.Reg{RDI, RSI, RDX, RCX, R8, R9}

// Arg implements SysV AMD64: integer arguments 0..5 arrive in
// RDI/RSI/RDX/RCX/R8/R9. Arguments 6+ spill to the stack — there is no
// register to name for them, so an out-of-range i panics (programming error,
// per the arch.CallABI contract).
func (sysV64) Arg(i int) emu.Reg {
	if i < 0 || i >= numArgRegs {
		panic(fmt.Sprintf("amd64: Arg(%d) out of range — SysV passes integer args 0..5 in RDI/RSI/RDX/RCX/R8/R9, args 6+ spill to the stack", i))
	}
	return argRegs[i]
}

func (sysV64) Ret() emu.Reg { return RAX }

// LR reports NoLR: SysV AMD64 keeps the return address on the stack, so the
// register-shaped LR accessor does not apply (arch.CallABI documents this).
// NoLR maps to no engine register — a register-based LR consumer fails loudly
// instead of operating on a fabricated register. The return-address role is
// expressed through ReturnFromCall.
func (sysV64) LR() emu.Reg { return NoLR }

// ReadArgs reads integer arguments 0..n-1 from RDI/RSI/RDX/RCX/R8/R9.
// Arguments beyond the six registers spill to the stack per SysV; that path
// is not implemented yet (no current consumer) and reports an error.
func (c sysV64) ReadArgs(b emu.Backend, n int) ([]uint64, error) {
	if n < 0 {
		return nil, fmt.Errorf("amd64: ReadArgs(%d): negative count", n)
	}
	if n > numArgRegs {
		// Stack-spill arguments live at [RSP+8 + 8*(i-6)] at function entry
		// (above the return address). Left for when a caller actually needs
		// >6 integer args through this interface.
		return nil, fmt.Errorf("amd64: ReadArgs(%d): stack-spill arguments not implemented (register limit %d)", n, numArgRegs)
	}
	args := make([]uint64, n)
	for i := range args {
		v, err := b.RegRead(c.Arg(i))
		if err != nil {
			return nil, fmt.Errorf("amd64: ReadArgs: arg %d: %w", i, err)
		}
		args[i] = v
	}
	return args, nil
}

// WriteResult writes the call result: RAX ← Value, RDX ← Value2. RDX is the
// high half of a SysV 128-bit integer result — exactly what
// arch.CallResult.Value2 is reserved for; for a plain 64-bit result Value2 is
// 0 and writing RDX is harmless (caller-saved scratch at return).
func (c sysV64) WriteResult(b emu.Backend, r arch.CallResult) error {
	if err := b.RegWrite(c.Ret(), r.Value); err != nil {
		return fmt.Errorf("amd64: WriteResult: %w", err)
	}
	if err := b.RegWrite(RDX, r.Value2); err != nil {
		return fmt.Errorf("amd64: WriteResult (Value2/RDX): %w", err)
	}
	return nil
}

// ReturnFromCall performs the SysV return: retAddr ← [RSP]; RSP += 8;
// PC ← retAddr — the register/stack effect of one `ret`. Function
// Interposition's host-function return path depends on this (DESIGN.md §3.8).
//
// Stack discipline note: the 128-byte red zone below RSP is NOT emulated —
// no golem component may treat [RSP-128, RSP) as scratch space (pinned by the
// P5a stack-semantics tests).
func (sysV64) ReturnFromCall(b emu.Backend) error {
	rsp, err := b.RegRead(RSP)
	if err != nil {
		return fmt.Errorf("amd64: ReturnFromCall: read RSP: %w", err)
	}
	raw, err := b.MemRead(emu.GuestAddr(rsp), 8)
	if err != nil {
		return fmt.Errorf("amd64: ReturnFromCall: read return address at RSP %#x: %w", rsp, err)
	}
	if err := b.RegWrite(RSP, rsp+8); err != nil {
		return fmt.Errorf("amd64: ReturnFromCall: pop RSP: %w", err)
	}
	if err := b.RegWrite(RIP, binary.LittleEndian.Uint64(raw)); err != nil {
		return fmt.Errorf("amd64: ReturnFromCall: write PC: %w", err)
	}
	return nil
}
