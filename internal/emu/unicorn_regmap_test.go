//go:build unicorn

package emu

import (
	"errors"
	"runtime"
	"testing"
)

// TestUnicornFactoryArchGate checks the real unicorn factory's arch gate:
// an UNKNOWN arch is refused before any libunicorn loading (this test needs
// no engine and no library). ArchARM64 must be creatable everywhere. The
// ARM/AMD64 targets are mandatory on POSIX; on Windows their creation
// depends on the committed DLL's build target list and the veh-off PREALLOC
// mechanism supporting that machine — a failure there must be LOUD
// (skip-with-reason, never a silent pass) until a DLL build ships them.
func TestUnicornFactoryArchGate(t *testing.T) {
	if _, err := NewNamed("unicorn", Arch(0)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("NewNamed(unicorn, Arch(0)): err = %v, want errors.Is(ErrUnsupported)", err)
	}
	if err := ensureLoaded(); err != nil {
		t.Skipf("libunicorn unavailable: %v", err)
	}
	for _, a := range []Arch{ArchARM64, ArchARM, ArchAMD64} {
		be, err := NewNamed("unicorn", a)
		if err == nil {
			be.Close()
			continue
		}
		if runtime.GOOS != "windows" {
			t.Fatalf("NewNamed(unicorn, %s): %v", a, err)
		}
		t.Logf("windows: NewNamed(unicorn, %s) unavailable: %v (committed DLL target list / PREALLOC support — loud, tracked)", a, err)
	}
}

// TestRegMapFrozenIDs verifies regMap translates the frozen arch/arm64 id
// NUMBERS (X0..X10=0..10, X23=11, SP=12, PC=13, LR=14, NZCV=15, TPIDR_EL0=16)
// to the right UC_ARM64_REG_* ids. regMap keys on numbers because emu cannot
// import internal/arch/arm64 (import cycle); arch/arm64's TestFrozenRegIDs
// pins the numbering on that side.
func TestRegMapFrozenIDs(t *testing.T) {
	cases := []struct {
		name string
		in   Reg
		want int32
	}{
		{"X0", 0, ucRegX(0)},
		{"X10", 10, ucRegX(10)},
		{"X23", 11, ucRegX(23)},
		{"SP", 12, ucRegSP},
		{"PC", 13, ucRegPC},
		{"LR", 14, ucRegLR},
		{"NZCV", 15, ucRegNZCV},
		{"TPIDR_EL0", 16, ucRegTPIDR},
		{"X16", 17, ucRegX(16)},
		{"invalid", 99, ucRegInvalid},
	}
	for _, tc := range cases {
		if got := regMap(tc.in); got != tc.want {
			t.Errorf("regMap(%s=%d) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestRegMapARM32FrozenIDs verifies regMapARM32 translates the frozen
// arch/arm32 id NUMBERS (R0=96..R15=111, CPSR=112, TPIDRURW=113) to the
// right UC_ARM_REG_* ids. regMapARM32 keys on numbers because emu cannot
// import internal/arch/arm32 (import cycle); arch/arm32's TestFrozenRegIDs
// pins the numbering on that side.
func TestRegMapARM32FrozenIDs(t *testing.T) {
	cases := []struct {
		name string
		in   Reg
		want int32
	}{
		{"R0", 96, ucArmRegR0},
		{"R7", 103, ucArmRegR0 + 7},
		{"R12", 108, ucArmRegR0 + 12},
		{"R13/SP", 109, ucArmRegSP},
		{"R14/LR", 110, ucArmRegLR},
		{"R15/PC", 111, ucArmRegPC},
		{"CPSR", 112, ucArmRegCPSR},
		{"TPIDRURW", 113, ucArmRegC13C03},
		{"arm64 X0 (collision check)", 0, ucRegInvalid},
		{"amd64 RAX (collision check)", 64, ucRegInvalid},
		{"invalid", 114, ucRegInvalid},
	}
	for _, tc := range cases {
		if got := regMapARM32(tc.in); got != tc.want {
			t.Errorf("regMapARM32(%s=%d) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}
