//go:build unicorn && (darwin || linux)

// External test package: emu_test may import internal/arch/arm32 (which
// imports emu) — impossible for the package's own internal test files.
package emu_test

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm32"
	"github.com/isesword/golem/internal/emu"
)

func newARM32(t *testing.T) emu.Backend {
	t.Helper()
	be, err := emu.NewNamed("unicorn", emu.ArchARM)
	if err != nil {
		t.Skipf("no unicorn backend: %v", err)
	}
	t.Cleanup(func() { be.Close() })
	return be
}

// arm32Scratch maps a scratch page and returns its base.
func arm32Scratch(t *testing.T, be emu.Backend, code []byte) emu.GuestAddr {
	t.Helper()
	const base = 0x10000000
	if err := be.MemMap(base, 0x1000, emu.ProtAll); err != nil {
		t.Fatal(err)
	}
	if err := be.MemWrite(base, code); err != nil {
		t.Fatal(err)
	}
	return base
}

const arm32Sentinel = 0xFFFFFF00

// TestBackendRegTranslationViaArm32Consts drives the ARM32 backend with the
// real arm32.* constants and checks values land in the right engine
// registers — tying arch/arm32's frozen numbering (96..113) to the
// backend's regMapARM32 end to end.
func TestBackendRegTranslationViaArm32Consts(t *testing.T) {
	be := newARM32(t)
	check := func(reg emu.Reg, val uint64) {
		t.Helper()
		if err := be.RegWrite(reg, val); err != nil {
			t.Fatalf("RegWrite(%d): %v", reg, err)
		}
		if got, err := be.RegRead(reg); err != nil || got != val {
			t.Fatalf("RegRead(%d) = %#x, %v; want %#x", reg, got, err, val)
		}
	}
	check(arm32.R0, 0x11111111)
	check(arm32.R7, 0x77777777)
	check(arm32.R12, 0x12121212)
	check(arm32.SP, 0x5ACE00)
	check(arm32.LR, 0x1E1E1E1E)
	check(arm32.PC, 0x100000)
	check(arm32.CPSR, 0x60000010) // flags + a mode field, read back verbatim
	check(arm32.TPIDRURW, 0x715711DE)
}

// TestUnicornARM32ARMExec runs two ARM-state instructions end to end:
// mov r0,#7 ; bx lr — the LR sentinel stops the run exactly like on ARM64.
func TestUnicornARM32ARMExec(t *testing.T) {
	be := newARM32(t)
	base := arm32Scratch(t, be, []byte{
		0x07, 0x00, 0xa0, 0xe3, // mov r0, #7
		0x1e, 0xff, 0x2f, 0xe1, // bx lr
	})
	if err := be.RegWrite(arm32.LR, arm32Sentinel); err != nil {
		t.Fatal(err)
	}
	if err := be.RegWrite(arm32.PC, uint64(base)); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(base, arm32Sentinel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got, _ := be.RegRead(arm32.R0); got != 7 {
		t.Fatalf("r0 = %#x, want 7", got)
	}
}

// TestUnicornARM32ThumbEntry pins the unicorn Thumb contract: an ODD start
// address enters Thumb state (uc_emu_start begin bit0) — Thumb-2 code runs
// without any uc_open mode change.
func TestUnicornARM32ThumbEntry(t *testing.T) {
	be := newARM32(t)
	base := arm32Scratch(t, be, []byte{
		0x09, 0x20, // movs r0, #9
		0x70, 0x47, // bx lr
	})
	if err := be.RegWrite(arm32.LR, arm32Sentinel); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(base|1, arm32Sentinel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got, _ := be.RegRead(arm32.R0); got != 9 {
		t.Fatalf("r0 = %#x, want 9 (Thumb decode)", got)
	}
	cpsr, _ := be.RegRead(arm32.CPSR)
	t.Logf("CPSR after run = %#x (T bit %v)", cpsr, cpsr&(1<<5) != 0)
}

// TestUnicornARM32SvcTrapPC pins what the engine reports as PC when an svc
// traps, in BOTH ISA states — the StubEncoder.TrapStubAddr contract depends
// on it. Measured on the live engine; do not "fix" from architecture-manual
// intuition.
func TestUnicornARM32SvcTrapPC(t *testing.T) {
	measure := func(t *testing.T, code []byte, start emu.GuestAddr) (pc, cpsr uint64) {
		be := newARM32(t)
		arm32Scratch(t, be, code)
		ih, ok := be.(emu.InterruptHooker)
		if !ok {
			t.Fatal("backend lacks InterruptHooker")
		}
		if _, err := ih.HookInterrupt(func(b emu.Backend, _ uint32) {
			pc, _ = b.RegRead(arm32.PC)
			cpsr, _ = b.RegRead(arm32.CPSR)
			_ = b.Stop()
		}); err != nil {
			t.Fatal(err)
		}
		if err := be.Start(start, arm32Sentinel); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return pc, cpsr
	}
	t.Run("ARM state", func(t *testing.T) {
		base := emu.GuestAddr(0x10000000)
		pc, cpsr := measure(t, []byte{0x00, 0x00, 0x00, 0xef /* svc #0 */}, base)
		t.Logf("trap PC = %#x (svc at %#x), CPSR = %#x", pc, base, cpsr)
		if pc != uint64(base)+4 {
			t.Fatalf("ARM svc trap PC = %#x, want svc+4 (%#x)", pc, uint64(base)+4)
		}
		if cpsr&(1<<5) != 0 {
			t.Fatalf("CPSR = %#x, want Thumb bit CLEAR in ARM state", cpsr)
		}
	})
	t.Run("Thumb state", func(t *testing.T) {
		base := emu.GuestAddr(0x10000000)
		pc, cpsr := measure(t, []byte{0x00, 0xdf /* svc #0 */}, base|1)
		t.Logf("trap PC = %#x (svc at %#x), CPSR = %#x", pc, base, cpsr)
		if pc != uint64(base)+2 {
			t.Fatalf("Thumb svc trap PC = %#x, want svc+2 (%#x)", pc, uint64(base)+2)
		}
		if cpsr&(1<<5) == 0 {
			t.Fatalf("CPSR = %#x, want Thumb bit SET in Thumb state", cpsr)
		}
	})
}

// TestUnicornARM32TLS writes the CP15 thread-pointer register through the
// backend and reads it back from GUEST code (mrc p15,0,r0,c13,c0,3) — the
// path SetTLSBase (arch side) and bionic's TLS lookups both depend on.
func TestUnicornARM32TLS(t *testing.T) {
	be := newARM32(t)
	base := arm32Scratch(t, be, []byte{
		0x70, 0x0f, 0x1d, 0xee, // mrc p15, 0, r0, c13, c0, 3 (TPIDRURW)
		0x1e, 0xff, 0x2f, 0xe1, // bx lr
	})
	const tls = 0x12345000
	if err := be.RegWrite(arm32.TPIDRURW, tls); err != nil {
		t.Fatal(err)
	}
	if err := be.RegWrite(arm32.LR, arm32Sentinel); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(base, arm32Sentinel); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got, _ := be.RegRead(arm32.R0); got != tls {
		t.Fatalf("mrc read TPIDRURW = %#x, want %#x", got, tls)
	}
}
