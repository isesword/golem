package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// aapcs64 is the AAPCS64 user-space function calling convention
// (arch.CallABI) for AArch64: integer arguments in X0..X7 (excess spilled to
// the stack), the result in X0, the return address in X30 (LR). The zero
// value is valid and stateless.
type aapcs64 struct{}

// numArgRegs is the number of integer argument registers (X0..X7); further
// arguments spill to the stack at [SP, #(i-8)*8] at function entry.
const numArgRegs = 8

// ArgReg names integer argument register i (X0+i), satisfying the optional
// arch.CallABIIntrospector capability for debugger / inline-hook
// introspection; ok is false outside the register portion [0,8).
func (aapcs64) ArgReg(i int) (emu.Reg, bool) {
	if i < 0 || i >= numArgRegs {
		return 0, false
	}
	return X0 + emu.Reg(i), true
}

// ResultReg names integer result register i (arch.CallABIIntrospector):
// 0 → X0; AAPCS64 has no second integer result register in use, so i>0 is
// ok=false.
func (aapcs64) ResultReg(i int) (emu.Reg, bool) {
	if i != 0 {
		return 0, false
	}
	return X0, true
}

// PrepareCall establishes an AAPCS64 call frame on the current stack: args
// 0..7 in X0..X7, args 8+ at [SP, #(i-8)*8] after decrementing SP by a
// 16-aligned spill area (AAPCS64 keeps SP 16-aligned at public interfaces),
// LR ← req.Return, PC ← req.Entry. Every ArgKind occupies one 64-bit slot
// (P6: AAPCS64 has no sub-word or paired placement).
func (aapcs64) PrepareCall(b emu.Backend, req arch.CallRequest) error {
	for i, a := range req.Args {
		if i >= numArgRegs {
			break
		}
		if err := b.RegWrite(X0+emu.Reg(i), a.Value); err != nil {
			return fmt.Errorf("arm64: PrepareCall: arg %d: %w", i, err)
		}
	}
	if len(req.Args) > numArgRegs {
		spill := req.Args[numArgRegs:]
		sp, err := b.RegRead(SP)
		if err != nil {
			return fmt.Errorf("arm64: PrepareCall: read SP: %w", err)
		}
		space := (uint64(len(spill))*8 + 15) &^ 15 // keep SP 16-aligned
		sp -= space
		raw := make([]byte, len(spill)*8)
		for i, a := range spill {
			binary.LittleEndian.PutUint64(raw[i*8:], a.Value)
		}
		if err := b.MemWrite(emu.GuestAddr(sp), raw); err != nil {
			return fmt.Errorf("arm64: PrepareCall: write %d stack args at SP %#x: %w", len(spill), sp, err)
		}
		if err := b.RegWrite(SP, sp); err != nil {
			return fmt.Errorf("arm64: PrepareCall: write SP: %w", err)
		}
	}
	if err := b.RegWrite(LR, uint64(req.Return)); err != nil {
		return fmt.Errorf("arm64: PrepareCall: write LR: %w", err)
	}
	if err := b.RegWrite(PC, uint64(req.Entry)); err != nil {
		return fmt.Errorf("arm64: PrepareCall: write PC: %w", err)
	}
	return nil
}

// ReadArgs reads integer arguments 0..n-1: args 0..7 from X0..X7, args 8+
// from the stack spill area at [SP, #(i-8)*8] (valid at function entry,
// before the callee moves SP).
func (aapcs64) ReadArgs(b emu.Backend, n int) ([]uint64, error) {
	if n < 0 {
		return nil, fmt.Errorf("arm64: ReadArgs(%d): negative count", n)
	}
	args := make([]uint64, n)
	reg := n
	if reg > numArgRegs {
		reg = numArgRegs
	}
	for i := 0; i < reg; i++ {
		v, err := b.RegRead(X0 + emu.Reg(i))
		if err != nil {
			return nil, fmt.Errorf("arm64: ReadArgs: arg %d: %w", i, err)
		}
		args[i] = v
	}
	if n > numArgRegs {
		sp, err := b.RegRead(SP)
		if err != nil {
			return nil, fmt.Errorf("arm64: ReadArgs: read SP: %w", err)
		}
		raw, err := b.MemRead(emu.GuestAddr(sp), uint64(n-numArgRegs)*8)
		if err != nil {
			return nil, fmt.Errorf("arm64: ReadArgs: read stack args at SP %#x: %w", sp, err)
		}
		for i := numArgRegs; i < n; i++ {
			args[i] = binary.LittleEndian.Uint64(raw[(i-numArgRegs)*8:])
		}
	}
	return args, nil
}

// WriteResult writes the call result: X0 ← Value. Value2 has no consumer on
// AAPCS64 today and is ignored.
func (aapcs64) WriteResult(b emu.Backend, r arch.CallResult) error {
	return b.RegWrite(X0, r.Value)
}

// ReadResult reads the call result: Value ← X0 (Value2 is always 0 — AAPCS64
// has no second integer result register in use).
func (aapcs64) ReadResult(b emu.Backend) (arch.CallResult, error) {
	v, err := b.RegRead(X0)
	if err != nil {
		return arch.CallResult{}, fmt.Errorf("arm64: ReadResult: %w", err)
	}
	return arch.CallResult{Value: v}, nil
}

// ReturnFromCall performs the AAPCS64 return: PC ← X30 (LR). The stack is
// untouched — the callee has already restored it per the convention.
func (aapcs64) ReturnFromCall(b emu.Backend) error {
	lr, err := b.RegRead(LR)
	if err != nil {
		return fmt.Errorf("arm64: ReturnFromCall: read LR: %w", err)
	}
	if err := b.RegWrite(PC, lr); err != nil {
		return fmt.Errorf("arm64: ReturnFromCall: write PC: %w", err)
	}
	return nil
}

// ReadReturnAddress (P9 observation semantics): at function entry the
// in-flight call returns to X30.
func (aapcs64) ReadReturnAddress(b emu.Backend) (emu.GuestAddr, error) {
	v, err := b.RegRead(LR)
	return emu.GuestAddr(v), err
}
