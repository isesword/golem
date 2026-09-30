package arm32

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// aapcs32 is the ARM32 (armv7 EABI) user-space function calling convention
// (arch.CallABI): integer arguments in r0..r3 with excess spilled to the
// stack, the result in r0 (a 64-bit result in r0:r1), and the return
// address in LR (r14) — interworking, so control transfers are BX
// semantics (bit0 of the target selects ARM/Thumb state via CPSR.T).
//
// The typed argument model (P6, Architecture Exception #1) is load-bearing
// here, unlike on the 64-bit conventions: ArgWord/ArgPtr occupy ONE 32-bit
// slot; ArgU64/ArgI64 occupy TWO slots and, per AAPCS32 stage C, must land
// in an EVEN-numbered register pair (r0:r1 or r2:r3) — skipping r1 when it
// would split a pair — or entirely on the stack at an 8-byte-aligned
// offset when they do not fit wholly in the remaining registers. This is
// why CallRequest.Args carries ArgKind: []uint64 could not express the
// difference between (uint32)1 and (uint64)1.
//
// SP is kept 8-byte aligned at the public interface (AAPCS32 §5.2.1.2).
type aapcs32 struct{}

// numArgRegs is the number of integer argument registers (r0..r3).
const numArgRegs = 4

// argRegs are the AAPCS32 integer argument registers in argument order.
var argRegs = [numArgRegs]emu.Reg{R0, R1, R2, R3}

// isWide reports whether the kind occupies two 32-bit slots (and therefore
// needs even-pair / 8-byte-stack alignment).
func isWide(k arch.ArgKind) bool { return k == arch.ArgU64 || k == arch.ArgI64 }

// placement is one argument's assigned location: a register (pair) or a
// byte offset within the stack spill area.
type placement struct {
	wide     bool
	regOK    bool   // in registers: first register is reg (even when wide)
	reg      int    // 0..3
	stackOff uint64 // valid when !regOK: byte offset in the spill area
}

// layout assigns every argument its registers or stack offset (AAPCS32
// stage C): the next-core-register number walks r0..r3, wide arguments
// round it up to even and go wholly to the stack when they no longer fit;
// once registers are exhausted everything spills, wide arguments 8-byte
// aligned. It also returns the spill area size in bytes.
func layout(args []arch.CallArg) ([]placement, uint64) {
	places := make([]placement, len(args))
	ncrn := 0       // next core register number (4 = exhausted)
	spOff := uint64(0) // stack cursor
	for i, a := range args {
		wide := isWide(a.Kind)
		if wide {
			if ncrn%2 == 1 {
				ncrn++ // even-pair alignment: a skipped register stays UNWRITTEN
			}
			if ncrn+1 < numArgRegs {
				places[i] = placement{wide: true, regOK: true, reg: ncrn}
				ncrn += 2
				continue
			}
			ncrn = numArgRegs // does not fit wholly in registers: whole arg spills
			spOff = (spOff + 7) &^ 7
			places[i] = placement{wide: true, stackOff: spOff}
			spOff += 8
			continue
		}
		if ncrn < numArgRegs {
			places[i] = placement{regOK: true, reg: ncrn}
			ncrn++
			continue
		}
		places[i] = placement{stackOff: spOff}
		spOff += 4
	}
	return places, spOff
}

// PrepareCall establishes an AAPCS32 call frame on the current stack: args
// per the layout above, LR ← req.Return (verbatim — its bit0 selects the
// caller's ISA state for the interworking return), SP dropped by the
// 8-aligned spill area, and PC ← req.Entry with BX semantics (bit0 into
// CPSR.T, PC even — Thumb functions work; see setPCBX).
func (aapcs32) PrepareCall(b emu.Backend, req arch.CallRequest) error {
	places, spill := layout(req.Args)
	for i, a := range req.Args {
		p := places[i]
		if !p.regOK {
			continue
		}
		lo := a.Value & 0xffffffff
		if err := b.RegWrite(argRegs[p.reg], lo); err != nil {
			return fmt.Errorf("arm32: PrepareCall: arg %d (r%d): %w", i, p.reg, err)
		}
		if p.wide {
			if err := b.RegWrite(argRegs[p.reg+1], a.Value>>32); err != nil {
				return fmt.Errorf("arm32: PrepareCall: arg %d high word (r%d): %w", i, p.reg+1, err)
			}
		}
	}
	if spill > 0 {
		sp, err := b.RegRead(SP)
		if err != nil {
			return fmt.Errorf("arm32: PrepareCall: read SP: %w", err)
		}
		sp = (sp - spill) &^ 7 // SP 8-aligned at the public interface
		raw := make([]byte, spill)
		for i, a := range req.Args {
			p := places[i]
			if p.regOK {
				continue
			}
			if p.wide {
				binary.LittleEndian.PutUint64(raw[p.stackOff:], a.Value)
			} else {
				binary.LittleEndian.PutUint32(raw[p.stackOff:], uint32(a.Value))
			}
		}
		if err := b.MemWrite(emu.GuestAddr(sp), raw); err != nil {
			return fmt.Errorf("arm32: PrepareCall: write %d spill bytes at SP %#x: %w", spill, sp, err)
		}
		if err := b.RegWrite(SP, sp); err != nil {
			return fmt.Errorf("arm32: PrepareCall: write SP: %w", err)
		}
	}
	if err := b.RegWrite(LR, uint64(req.Return)); err != nil {
		return fmt.Errorf("arm32: PrepareCall: write LR: %w", err)
	}
	if err := setPCBX(b, uint64(req.Entry)); err != nil {
		return fmt.Errorf("arm32: PrepareCall: set PC: %w", err)
	}
	return nil
}

// ReadArgs reads argument WORD slots 0..n-1 of the call currently in
// flight: slots 0..3 are r0..r3, slots 4+ are consecutive 32-bit stack
// words starting at SP (valid at function entry, before the callee moves
// SP). This is the raw SLOT view, not a typed-argument view: a 64-bit
// argument occupies two consecutive slots, a register skipped for
// even-pair alignment keeps whatever value it had, and 8-byte stack
// alignment padding appears as an ordinary (garbage) slot. Regrouping
// pairs into 64-bit values — and knowing which slots to skip — is the
// reader's business: it knows the callee's signature.
func (aapcs32) ReadArgs(b emu.Backend, n int) ([]uint64, error) {
	if n < 0 {
		return nil, fmt.Errorf("arm32: ReadArgs(%d): negative count", n)
	}
	args := make([]uint64, n)
	reg := n
	if reg > numArgRegs {
		reg = numArgRegs
	}
	for i := 0; i < reg; i++ {
		v, err := b.RegRead(argRegs[i])
		if err != nil {
			return nil, fmt.Errorf("arm32: ReadArgs: slot %d: %w", i, err)
		}
		args[i] = v & 0xffffffff
	}
	if n > numArgRegs {
		sp, err := b.RegRead(SP)
		if err != nil {
			return nil, fmt.Errorf("arm32: ReadArgs: read SP: %w", err)
		}
		raw, err := b.MemRead(emu.GuestAddr(sp), uint64(n-numArgRegs)*4)
		if err != nil {
			return nil, fmt.Errorf("arm32: ReadArgs: read stack slots at SP %#x: %w", sp, err)
		}
		for i := numArgRegs; i < n; i++ {
			args[i] = uint64(binary.LittleEndian.Uint32(raw[(i-numArgRegs)*4:]))
		}
	}
	return args, nil
}

// WriteResult writes the call's result per the convention: r0 = Value
// (low word), r1 = Value2 (the high half of a 64-bit result).
func (aapcs32) WriteResult(b emu.Backend, r arch.CallResult) error {
	if err := b.RegWrite(R0, r.Value&0xffffffff); err != nil {
		return fmt.Errorf("arm32: WriteResult: %w", err)
	}
	if err := b.RegWrite(R1, r.Value2&0xffffffff); err != nil {
		return fmt.Errorf("arm32: WriteResult: high word: %w", err)
	}
	return nil
}

// ReadResult reads the call's result registers — the exact inverse of
// WriteResult (Value = r0, Value2 = r1, the r0:r1 pair for 64-bit
// results).
func (aapcs32) ReadResult(b emu.Backend) (arch.CallResult, error) {
	v0, err := b.RegRead(R0)
	if err != nil {
		return arch.CallResult{}, fmt.Errorf("arm32: ReadResult: %w", err)
	}
	v1, err := b.RegRead(R1)
	if err != nil {
		return arch.CallResult{}, fmt.Errorf("arm32: ReadResult: high word: %w", err)
	}
	return arch.CallResult{Value: v0 & 0xffffffff, Value2: v1 & 0xffffffff}, nil
}

// ReturnFromCall performs one function return's register effect with
// interworking (BX LR) semantics: CPSR.T ← LR bit0, PC ← LR &^ 1.
// Function Interposition's host-function return path depends on this
// (DESIGN.md §3.8).
func (aapcs32) ReturnFromCall(b emu.Backend) error {
	lr, err := b.RegRead(LR)
	if err != nil {
		return fmt.Errorf("arm32: ReturnFromCall: read LR: %w", err)
	}
	if err := setPCBX(b, lr); err != nil {
		return fmt.Errorf("arm32: ReturnFromCall: %w", err)
	}
	return nil
}

// ArgReg names the register carrying argument SLOT i
// (arch.CallABIIntrospector): slots 0..3 are r0..r3; stack slots have no
// register to name.
func (aapcs32) ArgReg(i int) (emu.Reg, bool) {
	if i < 0 || i >= numArgRegs {
		return 0, false
	}
	return argRegs[i], true
}

// ResultReg names the register carrying integer result i
// (arch.CallABIIntrospector): 0 → r0, 1 → r1 (the r0:r1 pair carries a
// 64-bit result).
func (aapcs32) ResultReg(i int) (emu.Reg, bool) {
	switch i {
	case 0:
		return R0, true
	case 1:
		return R1, true
	}
	return 0, false
}

// cpsrT is the Thumb-state bit of CPSR.
const cpsrT = 1 << 5

// setPCBX performs an interworking (BX) control transfer to addr: bit0 of
// the target selects the ISA state (CPSR.T) and the PC becomes the even
// address. This is THE one place bit0-as-ISA-state is interpreted — the
// Arch.NormalizeCodeAddr documentation contrasts it with plain code-address
// canonicalization (bit0 stripped for MAPPING, not state).
func setPCBX(b emu.Backend, addr uint64) error {
	cpsr, err := b.RegRead(CPSR)
	if err != nil {
		return fmt.Errorf("read CPSR: %w", err)
	}
	if addr&1 != 0 {
		cpsr |= cpsrT
	} else {
		cpsr &^= cpsrT
	}
	if err := b.RegWrite(CPSR, cpsr); err != nil {
		return fmt.Errorf("write CPSR: %w", err)
	}
	if err := b.RegWrite(PC, addr&^1); err != nil {
		return fmt.Errorf("write PC: %w", err)
	}
	return nil
}

// ReadReturnAddress (P9 observation semantics): at function entry the
// in-flight call returns to R14 — verbatim, bit0 may carry the return
// site's Thumb state exactly as ReturnFromCall consumes it.
func (aapcs32) ReadReturnAddress(b emu.Backend) (emu.GuestAddr, error) {
	v, err := b.RegRead(LR)
	return emu.GuestAddr(v), err
}
