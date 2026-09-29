package amd64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// sysV64 is the System V AMD64 user-space function calling convention
// (arch.CallABI): integer arguments in RDI/RSI/RDX/RCX/R8/R9 (excess spilled
// to the stack above the return address), the result in RAX (with RDX as the
// high half of a 128-bit result), and the return address ON THE STACK —
// pushed by `call`, popped by `ret`. The zero value is valid and stateless.
//
// This is the FUNCTION call ABI only. The Linux x86-64 syscall ABI is a
// different convention (number in RAX, 4th argument in R10 — NOT RCX, which
// the `syscall` instruction itself clobbers) and lives in platform/android's
// LinuxAMD64Transport; the two must never be merged (P5a requirement: the
// RCX-vs-R10 difference is pinned by TestArgRegsVsSyscallABI).
type sysV64 struct{}

// numArgRegs is the number of integer argument registers (RDI..R9); further
// arguments spill to the stack at [RSP+8+(i-6)*8] at function entry (above
// the return address).
const numArgRegs = 6

// argRegs are the SysV integer argument registers in argument order.
var argRegs = [numArgRegs]emu.Reg{RDI, RSI, RDX, RCX, R8, R9}

// ArgReg names integer argument register i for debugger / inline-hook
// introspection; ok is false outside the register portion [0,6) — args 6+
// live on the stack and have no register to name.
func (sysV64) ArgReg(i int) (emu.Reg, bool) {
	if i < 0 || i >= numArgRegs {
		return 0, false
	}
	return argRegs[i], true
}

// PrepareCall establishes a SysV call frame on the current stack — the exact
// stack/register state a `call Entry` instruction would produce:
//
//	RDI/RSI/RDX/RCX/R8/R9 ← Args[0:6]
//	[RSP]                ← Return (the return address `ret` will pop)
//	[RSP+8+(i-6)*8]      ← Args[i] for i ≥ 6 (stack args above the return
//	                       address, in argument order)
//	RSP ≡ 8 (mod 16) at entry (the ABI wants RSP+8 16-aligned after the
//	                       implicit return-address push)
//	RIP                  ← Entry
//
// Nothing below the new RSP is written: the 128-byte red zone of the frame
// being created stays intact.
func (sysV64) PrepareCall(b emu.Backend, req arch.CallRequest) error {
	for i, v := range req.Args {
		if i >= numArgRegs {
			break
		}
		if err := b.RegWrite(argRegs[i], v); err != nil {
			return fmt.Errorf("amd64: PrepareCall: arg %d: %w", i, err)
		}
	}
	rsp, err := b.RegRead(RSP)
	if err != nil {
		return fmt.Errorf("amd64: PrepareCall: read RSP: %w", err)
	}
	var stackArgs []uint64
	if len(req.Args) > numArgRegs {
		stackArgs = req.Args[numArgRegs:]
	}
	slots := uint64(len(stackArgs)) + 1 // stack args + return address
	// Round down to the highest RSP ≡ 8 (mod 16) that still fits all slots.
	newRSP := ((rsp - slots*8) &^ 15) - 8
	frame := make([]byte, slots*8)
	binary.LittleEndian.PutUint64(frame, uint64(req.Return))
	for i, v := range stackArgs {
		binary.LittleEndian.PutUint64(frame[8+i*8:], v)
	}
	if err := b.MemWrite(emu.GuestAddr(newRSP), frame); err != nil {
		return fmt.Errorf("amd64: PrepareCall: write %d stack slots at RSP %#x: %w", slots, newRSP, err)
	}
	if err := b.RegWrite(RSP, newRSP); err != nil {
		return fmt.Errorf("amd64: PrepareCall: write RSP: %w", err)
	}
	if err := b.RegWrite(RIP, uint64(req.Entry)); err != nil {
		return fmt.Errorf("amd64: PrepareCall: write RIP: %w", err)
	}
	return nil
}

// ReadArgs reads integer arguments 0..n-1: args 0..5 from
// RDI/RSI/RDX/RCX/R8/R9, args 6+ from the stack at [RSP+8+(i-6)*8] — valid
// at function entry, before the callee moves RSP.
func (sysV64) ReadArgs(b emu.Backend, n int) ([]uint64, error) {
	if n < 0 {
		return nil, fmt.Errorf("amd64: ReadArgs(%d): negative count", n)
	}
	args := make([]uint64, n)
	reg := n
	if reg > numArgRegs {
		reg = numArgRegs
	}
	for i := 0; i < reg; i++ {
		v, err := b.RegRead(argRegs[i])
		if err != nil {
			return nil, fmt.Errorf("amd64: ReadArgs: arg %d: %w", i, err)
		}
		args[i] = v
	}
	if n > numArgRegs {
		rsp, err := b.RegRead(RSP)
		if err != nil {
			return nil, fmt.Errorf("amd64: ReadArgs: read RSP: %w", err)
		}
		raw, err := b.MemRead(emu.GuestAddr(rsp+8), uint64(n-numArgRegs)*8)
		if err != nil {
			return nil, fmt.Errorf("amd64: ReadArgs: read stack args at RSP+8 %#x: %w", rsp+8, err)
		}
		for i := numArgRegs; i < n; i++ {
			args[i] = binary.LittleEndian.Uint64(raw[(i-numArgRegs)*8:])
		}
	}
	return args, nil
}

// WriteResult writes the call result: RAX ← Value, RDX ← Value2. RDX is the
// high half of a SysV 128-bit integer result — exactly what
// arch.CallResult.Value2 is reserved for; for a plain 64-bit result Value2 is
// 0 and writing RDX is harmless (caller-saved scratch at return).
func (sysV64) WriteResult(b emu.Backend, r arch.CallResult) error {
	if err := b.RegWrite(RAX, r.Value); err != nil {
		return fmt.Errorf("amd64: WriteResult: %w", err)
	}
	if err := b.RegWrite(RDX, r.Value2); err != nil {
		return fmt.Errorf("amd64: WriteResult (Value2/RDX): %w", err)
	}
	return nil
}

// ReadResult reads the call result: Value ← RAX, Value2 ← RDX — the exact
// inverse of WriteResult.
func (sysV64) ReadResult(b emu.Backend) (arch.CallResult, error) {
	v, err := b.RegRead(RAX)
	if err != nil {
		return arch.CallResult{}, fmt.Errorf("amd64: ReadResult: %w", err)
	}
	v2, err := b.RegRead(RDX)
	if err != nil {
		return arch.CallResult{}, fmt.Errorf("amd64: ReadResult (Value2/RDX): %w", err)
	}
	return arch.CallResult{Value: v, Value2: v2}, nil
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
