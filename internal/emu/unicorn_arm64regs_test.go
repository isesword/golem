//go:build unicorn && (darwin || linux)

// External test package: emu_test may import internal/arch/arm64 (which
// imports emu) — impossible for the package's own internal test files.
package emu_test

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// TestBackendRegTranslationViaArm64Consts drives the backend with the real
// arm64.* constants and checks the values land in the right engine registers
// (cross-checked through ReadGPRegs' fixed layout: [0..30]=x0..x30, [31]=sp,
// [32]=pc, [33]=nzcv). This ties the arch/arm64 numbering to the unicorn
// backend's regMap end to end.
func TestBackendRegTranslationViaArm64Consts(t *testing.T) {
	be, err := emu.NewNamed("", emu.ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	check := func(reg emu.Reg, gpIdx int, val uint64) {
		t.Helper()
		if err := be.RegWrite(reg, val); err != nil {
			t.Fatalf("RegWrite(%d): %v", reg, err)
		}
		if got, err := be.RegRead(reg); err != nil || got != val {
			t.Fatalf("RegRead(%d) = %#x, %v; want %#x", reg, got, err, val)
		}
		if gpIdx >= 0 {
			gp, err := be.ReadGPRegs()
			if err != nil {
				t.Fatal(err)
			}
			if gp[gpIdx] != val {
				t.Fatalf("ReadGPRegs()[%d] = %#x after writing reg %d, want %#x", gpIdx, gp[gpIdx], reg, val)
			}
		}
	}

	check(arm64.X23, 23, 0x2323232323232323)
	check(arm64.SP, 31, 0x5ace00)
	check(arm64.PC, 32, 0x100000)
	check(arm64.LR, 30, 0x1e1e1e1e)
	check(arm64.NZCV, 33, 0x60000000)
	check(arm64.TPIDR_EL0, -1, 0x715711DEADBEEF) // not in the GP batch
	check(arm64.X16, 16, 0x1616161616161616)     // P5b: Darwin syscall-number reg
}
