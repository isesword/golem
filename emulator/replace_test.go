package emulator

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// hookBE is a test double for the interposition paths: the emu.Backend
// core (nil embedded — unimplemented ops panic) plus the InstructionHooker
// capability, recording every HookCode range and injecting failures. RegRead/
// RegWrite serve a tiny register file so the entry-hook dispatch can run.
// MemWrite PANICS: interposition must never write guest memory, so any write
// attempt fails the test loudly.
type hookBE struct {
	emu.Backend
	hookErr error
	ranges  [][2]emu.GuestAddr
	cbs     []emu.CodeHookFunc
	regs    map[emu.Reg]uint64
}

type nopHookHandle struct{}

func (nopHookHandle) Remove() error { return nil }

func (b *hookBE) HookCode(start, end emu.GuestAddr, fn emu.CodeHookFunc) (emu.HookHandle, error) {
	if b.hookErr != nil {
		return nil, b.hookErr
	}
	b.ranges = append(b.ranges, [2]emu.GuestAddr{start, end})
	b.cbs = append(b.cbs, fn)
	return nopHookHandle{}, nil
}

func (b *hookBE) RegRead(r emu.Reg) (uint64, error) { return b.regs[r], nil }

func (b *hookBE) RegWrite(r emu.Reg, v uint64) error {
	if b.regs == nil {
		b.regs = map[emu.Reg]uint64{}
	}
	b.regs[r] = v
	return nil
}

func (b *hookBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	panic("hookBE: interposition must not write guest memory")
}

// The hookBE test double implements the InstructionHooker capability — the
// ReplaceE interposition tests depend on the probe SUCCEEDING for it.
func TestHookBESatisfiesInstructionHooker(t *testing.T) {
	var be emu.Backend = &hookBE{}
	if _, ok := be.(emu.InstructionHooker); !ok {
		t.Fatal("hookBE must satisfy emu.InstructionHooker")
	}
	if _, ok := be.(emu.CacheInvalidator); ok {
		t.Fatal("hookBE must NOT satisfy emu.CacheInvalidator")
	}
	if _, ok := be.(emu.CodeCacheController); ok {
		t.Fatal("hookBE must NOT satisfy emu.CodeCacheController (ReplaceE must tolerate its absence)")
	}
}

func TestReplaceInterposeSuccess(t *testing.T) {
	be := &hookBE{}
	e := newTestEmulator(t, be)
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 }); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.itab.LookupAddress(0x1000); !ok {
		t.Fatal("success must bind the entry in the InterposeTable")
	}
	// Performance constraint (DESIGN.md §8): exactly one hook, covering
	// exactly the one entry address — never a range.
	if len(be.ranges) != 1 || be.ranges[0] != [2]emu.GuestAddr{0x1000, 0x1000} {
		t.Fatalf("hook must cover exactly [entry, entry], got %v", be.ranges)
	}
}

func TestReplaceHookFailureLeavesNoState(t *testing.T) {
	be := &hookBE{hookErr: errors.New("hook refused")}
	e := newTestEmulator(t, be)
	err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 })
	if err == nil {
		t.Fatal("HookCode failure must surface as an error")
	}
	if e.poisonErr != nil {
		t.Fatalf("a refused hook is an ordinary failure, not poison: %v", e.poisonErr)
	}
	if _, ok := e.itab.LookupAddress(0x1000); ok {
		t.Fatal("failed ReplaceE must not stay bound")
	}
	// The emulator stays usable: a retry with a healthy engine succeeds.
	be.hookErr = nil
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 }); err != nil {
		t.Fatalf("retry after a failed ReplaceE: %v", err)
	}
}

func TestReplaceDuplicateAddressFails(t *testing.T) {
	be := &hookBE{}
	e := newTestEmulator(t, be)
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 1 }); err != nil {
		t.Fatal(err)
	}
	err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 2 })
	if err == nil {
		t.Fatal("replacing an already-interposed address must fail")
	}
	// The original binding is intact and no second hook was stacked on the
	// entry (two hooks would both fire).
	if len(be.ranges) != 1 {
		t.Fatalf("duplicate ReplaceE must not install another hook, ranges=%v", be.ranges)
	}
}

// TestInterposeDispatchWritesResultAndReturns drives the entry-hook dispatch
// exactly as the engine would: the hook fires at the entry address, the host
// function runs, the result lands in the return register per the CallABI, and
// ReturnFromCall sets PC ← LR (AAPCS64) — the guest function body is skipped.
func TestInterposeDispatchWritesResultAndReturns(t *testing.T) {
	be := &hookBE{}
	e := newTestEmulator(t, be)
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return mustArg(h, 0) + 41 }); err != nil {
		t.Fatal(err)
	}
	if len(be.cbs) != 1 {
		t.Fatalf("want 1 installed hook, got %d", len(be.cbs))
	}
	be.regs = map[emu.Reg]uint64{arm64.X0: 1, arm64.LR: 0x2000}
	be.cbs[0](be, 0x1000, 4) // the engine fires the entry hook
	if got := be.regs[arm64.X0]; got != 42 {
		t.Fatalf("WriteResult: X0 = %#x, want 42", got)
	}
	if got := be.regs[arm64.PC]; got != 0x2000 {
		t.Fatalf("ReturnFromCall: PC = %#x, want LR (0x2000)", got)
	}
}
