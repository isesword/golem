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

// TestUnicornARM32ReadGPRegs pins the ARM32 RegFileReader dump (exposed
// by real-library validation): 17 entries in native file order
// (r0..r12, sp, lr, pc, cpsr), each agreeing with the individually-read
// register.
func TestUnicornARM32ReadGPRegs(t *testing.T) {
	be := newARM32(t)
	rr, ok := be.(emu.RegFileReader)
	if !ok {
		t.Fatal("the ARM32 unicorn backend must implement RegFileReader")
	}

	check := func(reg emu.Reg, gpIdx int, val uint64) {
		t.Helper()
		if err := be.RegWrite(reg, val); err != nil {
			t.Fatalf("RegWrite(%d): %v", reg, err)
		}
		if got, err := be.RegRead(reg); err != nil || got != val {
			t.Fatalf("RegRead(%d) = %#x, %v; want %#x", reg, got, err, val)
		}
		gp, err := rr.ReadGPRegs()
		if err != nil {
			t.Fatal(err)
		}
		if len(gp) != 17 {
			t.Fatalf("ReadGPRegs = %d entries, want 17 (r0..r12,sp,lr,pc,cpsr)", len(gp))
		}
		if gp[gpIdx] != val {
			t.Fatalf("ReadGPRegs()[%d] = %#x after writing reg %d, want %#x", gpIdx, gp[gpIdx], reg, val)
		}
	}

	check(arm32.R5, 5, 0x55555555)
	check(arm32.R12, 12, 0x1212121212121212&0xffffffff)
	check(arm32.SP, 13, 0x5ace00)
	check(arm32.LR, 14, 0x1e1e1e1e)
	check(arm32.PC, 15, 0x100000)

	// CPSR's low 5 bits are the CPU mode field, engine-managed (SVC=0x13) —
	// unicorn ORs them back on every read; compare above the mode bits.
	if err := be.RegWrite(arm32.CPSR, 0x60000000); err != nil {
		t.Fatal(err)
	}
	if got, _ := be.RegRead(arm32.CPSR); got&^0x1f != 0x60000000 {
		t.Fatalf("CPSR readback = %#x, want flags 0x60000000 above the mode bits", got)
	}
	if gp, err := rr.ReadGPRegs(); err != nil || gp[16]&^0x1f != 0x60000000 {
		t.Fatalf("ReadGPRegs()[16] = %#x, %v; want flags 0x60000000 above mode bits", gp[16], err)
	}
}

// TestUnicornARM32VFPEnabled pins the engine-creation CPACR write: an
// ARMv7 engine must execute VFP (cp10) instructions out of the box — real
// third-party libraries (Termux libsqlite3) use VLDR/NEON deep inside
// ordinary call paths, and the reset state disables cp10/cp11.
func TestUnicornARM32VFPEnabled(t *testing.T) {
	be := newARM32(t)
	// Thumb: vldr s0, [r0, #0]; movs r0, #0; bx lr
	code := []byte{0x90, 0xed, 0x00, 0x0a, 0x00, 0x20, 0x70, 0x47}
	base := arm32Scratch(t, be, code)
	if err := be.RegWrite(arm32.R0, uint64(base)); err != nil {
		t.Fatal(err)
	}
	if err := be.RegWrite(arm32.LR, arm32Sentinel); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(base|1, arm32Sentinel); err != nil {
		t.Fatalf("VFP probe: %v (CPACR must enable cp10/cp11 at engine creation)", err)
	}
}

// TestUnicornARM32WriteRegs pins the batch-write capability live:
// a single WriteRegs lands every value where individual RegReads see it.
func TestUnicornARM32WriteRegs(t *testing.T) {
	be := newARM32(t)
	bw, ok := be.(emu.RegBatchWriter)
	if !ok {
		t.Fatal("the ARM32 unicorn backend must implement RegBatchWriter")
	}
	if err := bw.WriteRegs([]emu.RegWrite{
		{Reg: arm32.R0, Value: 0x1111},
		{Reg: arm32.R5, Value: 0x5555},
		{Reg: arm32.SP, Value: 0x5ace00},
		{Reg: arm32.LR, Value: 0x1e1e1e1e},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reg  emu.Reg
		want uint64
	}{{arm32.R0, 0x1111}, {arm32.R5, 0x5555}, {arm32.SP, 0x5ace00}, {arm32.LR, 0x1e1e1e1e}} {
		if got, err := be.RegRead(tc.reg); err != nil || got != tc.want {
			t.Fatalf("RegRead(%d) = %#x, %v; want %#x", tc.reg, got, err, tc.want)
		}
	}
}
