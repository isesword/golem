//go:build unicorn

package emu

import (
	"errors"
	"testing"
)

// TestUnicornFactoryArchGate checks the real unicorn factory's arch gate:
// ArchARM is refused BEFORE any libunicorn loading (this test needs no engine
// and no library), while ArchARM64 and ArchAMD64 are both creatable (P5a —
// the AMD64 path needs the library, so it skips when libunicorn is absent).
func TestUnicornFactoryArchGate(t *testing.T) {
	if _, err := NewNamed("unicorn", ArchARM); !errors.Is(err, ErrUnsupported) {
		t.Errorf("NewNamed(unicorn, arm): err = %v, want errors.Is(ErrUnsupported)", err)
	}
	if err := ensureLoaded(); err != nil {
		t.Skipf("libunicorn unavailable: %v", err)
	}
	for _, a := range []Arch{ArchARM64, ArchAMD64} {
		be, err := NewNamed("unicorn", a)
		if err != nil {
			t.Fatalf("NewNamed(unicorn, %s): %v", a, err)
		}
		be.Close()
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
