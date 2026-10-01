//go:build unicorn && (darwin || linux)

package emu

import (
	"os"
	"strings"
	"testing"
)

// HookCode contract acceptance, on the REAL loaded unicorn build (whichever
// GOLEM_UNICORN pins): half-open boundary exactness, the empty-range refusal,
// the installation-effect guarantee (hook after translation still fires),
// and the flush-failure rollback.

func arm64AddCode(t *testing.T, be Backend, base GuestAddr, n int) {
	t.Helper()
	if err := be.MemMap(base, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ { // n× ADD X0,X0,#1
		insn := uint32(0x91000400)
		var b [4]byte
		b[0], b[1], b[2], b[3] = byte(insn), byte(insn>>8), byte(insn>>16), byte(insn>>24)
		if err := be.MemWrite(base+GuestAddr(i*4), b[:]); err != nil {
			t.Fatal(err)
		}
	}
	ret := uint32(0xD65F03C0) // RET
	var rb [4]byte
	rb[0], rb[1], rb[2], rb[3] = byte(ret), byte(ret>>8), byte(ret>>16), byte(ret>>24)
	if err := be.MemWrite(base+GuestAddr(n*4), rb[:]); err != nil {
		t.Fatal(err)
	}
}

func TestHookCodeLibraryProvenance(t *testing.T) {
	if p := os.Getenv("GOLEM_UNICORN"); p != "" {
		if got := LoadedLibrary(); got != p {
			t.Fatalf("loaded library %q, but GOLEM_UNICORN pins %q — the run did not measure what it claims", got, p)
		}
	} else {
		t.Logf("GOLEM_UNICORN unset; loaded fallback library: %s", LoadedLibrary())
	}
}

// Half-open boundary: [base, base+4) watches exactly the FIRST instruction —
// the instruction starting exactly at end must NOT fire (the end-1 inclusive
// conversion).
func TestHookCodeHalfOpenBoundary(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	const base = GuestAddr(0x100000)
	arm64AddCode(t, be, base, 3)
	if err := be.RegWrite(regX0, 5); err != nil {
		t.Fatal(err)
	}

	ih := be.(InstructionHooker)
	var fired []GuestAddr
	h, err := ih.HookCode(base, base+4, func(b Backend, addr GuestAddr, size uint32) {
		fired = append(fired, addr)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()

	if err := be.Start(base, base+3*4); err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0] != base {
		t.Fatalf("fired=%v, want exactly [base]", fired)
	}
	if got, _ := be.RegRead(regX0); got != 8 {
		t.Fatalf("X0=%d, want 8 (all three ADDs ran)", got)
	}
}

// Empty range: start == end must error and install nothing (never handed to
// the engine).
func TestHookCodeEmptyRangeRefused(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	ih := be.(InstructionHooker)
	if _, err := ih.HookCode(0x1000, 0x1000, func(Backend, GuestAddr, uint32) {}); err == nil {
		t.Fatal("empty range must error")
	}
}

// Whole-space (1,0): a hook installed AFTER the code was translated still
// fires on the next execution (installation-effect guarantee).
func TestHookCodeWholeSpaceAfterTranslation(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	const base = GuestAddr(0x100000)
	arm64AddCode(t, be, base, 3)
	if err := be.RegWrite(regX0, 5); err != nil {
		t.Fatal(err)
	}
	// Translate first: run once with no hook.
	if err := be.Start(base, base+3*4); err != nil {
		t.Fatal(err)
	}

	ih := be.(InstructionHooker)
	fired := 0
	h, err := ih.HookCode(1, 0, func(b Backend, addr GuestAddr, size uint32) {
		fired++
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()

	if err := be.Start(base, base+3*4); err != nil {
		t.Fatal(err)
	}
	if fired != 3 { // the three ADDs; the until address stops before the RET
		t.Fatalf("whole-space hook fired %d times after translation, want 3", fired)
	}
}

// Flush failure: HookCode must return the error AND leave no hook behind —
// proven by re-installing the same hook after recovery and counting EXACTLY
// one fire per pass (every leaked attempt would add one).
func TestHookCodeFlushFailureRollsBack(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	const base = GuestAddr(0x100000)
	arm64AddCode(t, be, base, 3)
	if err := be.RegWrite(regX0, 5); err != nil {
		t.Fatal(err)
	}

	ih := be.(InstructionHooker)
	saved := pCtl
	pCtl = nil // simulate a build without uc_ctl: the flush cannot happen
	for i := 0; i < 3; i++ {
		_, err := ih.HookCode(base, base+4, func(Backend, GuestAddr, uint32) {})
		if err == nil {
			pCtl = saved
			t.Fatal("HookCode without flush capability must error")
		}
		if !strings.Contains(err.Error(), "flush") {
			pCtl = saved
			t.Fatalf("error should name the flush, got: %v", err)
		}
	}
	pCtl = saved

	fired := 0
	h, err := ih.HookCode(base, base+4, func(b Backend, addr GuestAddr, size uint32) {
		fired++
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()
	if err := be.Start(base, base+3*4); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("fired=%d after 3 failed attempts, want exactly 1 — a leak would fire more", fired)
	}
}
