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

// ArgReg names integer argument register i, satisfying the optional
// arch.CallABIIntrospector capability for debugger / inline-hook
// introspection; ok is false outside the register portion [0,6) — args 6+
// live on the stack and have no register to name.
func (sysV64) ArgReg(i int) (emu.Reg, bool) {
	if i < 0 || i >= numArgRegs {
		return 0, false
	}
	return argRegs[i], true
}

// ResultReg names integer result register i (arch.CallABIIntrospector):
// 0 → RAX, 1 → RDX, matching WriteResult/ReadResult; i>1 is ok=false.
func (sysV64) ResultReg(i int) (emu.Reg, bool) {
	switch i {
	case 0:
		return RAX, true
	case 1:
		return RDX, true
	}
	return 0, false
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
// P9.5a: the register writes (args, RSP, RIP) are collected into one set
// and flushed in a single batch when the backend has the RegBatchWriter
// capability — the no-capability loop writes the identical set in the
// identical order, so the two paths cannot drift.
func (sysV64) PrepareCall(b emu.Backend, req arch.CallRequest) error {
	var writes [numArgRegs + 2]emu.RegWrite // args + RSP + RIP
	n := 0
	for i, a := range req.Args {
		if i >= numArgRegs {
			break
		}
		writes[n] = emu.RegWrite{Reg: argRegs[i], Value: a.Value}
		n++
	}
	rsp, err := b.RegRead(RSP)
	if err != nil {
		return fmt.Errorf("amd64: PrepareCall: read RSP: %w", err)
	}
	var stackArgs []arch.CallArg
	if len(req.Args) > numArgRegs {
		stackArgs = req.Args[numArgRegs:]
	}
	slots := uint64(len(stackArgs)) + 1 // stack args + return address
	// Round down to the highest RSP ≡ 8 (mod 16) that still fits all slots.
	newRSP := ((rsp - slots*8) &^ 15) - 8
	frame := make([]byte, slots*8)
	binary.LittleEndian.PutUint64(frame, uint64(req.Return))
	for i, a := range stackArgs {
		binary.LittleEndian.PutUint64(frame[8+i*8:], a.Value)
	}
	if err := b.MemWrite(emu.GuestAddr(newRSP), frame); err != nil {
		return fmt.Errorf("amd64: PrepareCall: write %d stack slots at RSP %#x: %w", slots, newRSP, err)
	}
	writes[n] = emu.RegWrite{Reg: RSP, Value: newRSP}
	n++
	writes[n] = emu.RegWrite{Reg: RIP, Value: uint64(req.Entry)}
	n++

	if bw, ok := b.(emu.RegBatchWriter); ok {
		if err := bw.WriteRegs(writes[:n]); err != nil {
			return fmt.Errorf("amd64: PrepareCall: batch write: %w", err)
		}
		return nil
	}
	for _, w := range writes[:n] {
		if err := b.RegWrite(w.Reg, w.Value); err != nil {
			return fmt.Errorf("amd64: PrepareCall: write %v=#x: %w", w.Reg, err)
		}
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

// ReadReturnAddress (P9 observation semantics): at function entry (before
// any prologue) the return address is the 8-byte little-endian word at
// [RSP] — x86-64 keeps it on the stack, not in a register (invariant 13).
func (sysV64) ReadReturnAddress(b emu.Backend) (emu.GuestAddr, error) {
	sp, err := b.RegRead(RSP)
	if err != nil {
		return 0, fmt.Errorf("ReadReturnAddress: RSP: %w", err)
	}
	raw, err := b.MemRead(emu.GuestAddr(sp), 8)
	if err != nil {
		return 0, fmt.Errorf("ReadReturnAddress: [RSP=%#x]: %w", sp, err)
	}
	if len(raw) != 8 {
		return 0, fmt.Errorf("ReadReturnAddress: [RSP=%#x]: short read %d", sp, len(raw))
	}
	return emu.GuestAddr(binary.LittleEndian.Uint64(raw)), nil
}

// InstallReturnContinuation (P10): re-aims the in-flight call's return at
// the post continuation — SysV keeps the return address ON THE STACK (the
// caller's `call` pushed it at [RSP]), so the slot is OVERWRITTEN IN PLACE:
// [RSP] ← post, RSP untouched. The original's `ret` then pops post with the
// stack exactly back at the caller's state — the post continuation resumes
// the caller with a plain RIP write, no pop. (A push here would leak 8 bytes
// per wrap: the original's `ret` consumes the pushed post, but the real
// return stays stranded below the caller's SP — found live, P10-2d.)
func (sysV64) InstallReturnContinuation(b emu.Backend, post emu.GuestAddr) error {
	sp, err := b.RegRead(RSP)
	if err != nil {
		return fmt.Errorf("InstallReturnContinuation: RSP: %w", err)
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(post))
	if err := b.MemWrite(emu.GuestAddr(sp), buf[:]); err != nil {
		return fmt.Errorf("InstallReturnContinuation: [RSP=%#x]: %w", sp, err)
	}
	return nil
}

// ReturnTo (P10): jump to an explicit address.
func (sysV64) ReturnTo(b emu.Backend, target emu.GuestAddr) error {
	return b.RegWrite(RIP, uint64(target))
}
