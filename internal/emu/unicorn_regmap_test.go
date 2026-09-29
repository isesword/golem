//go:build unicorn

package emu

import (
	"errors"
	"testing"
)

// TestUnicornFactoryRejectsNonARM64 checks the real unicorn factory's arch
// gate — it must fire BEFORE any libunicorn loading, so this test needs no
// engine and no library.
func TestUnicornFactoryRejectsNonARM64(t *testing.T) {
	for _, a := range []Arch{ArchARM, ArchAMD64} {
		if _, err := NewNamed("unicorn", a); !errors.Is(err, ErrUnsupported) {
			t.Errorf("NewNamed(unicorn, %v): err = %v, want errors.Is(ErrUnsupported)", a, err)
		}
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
		{"invalid", 99, ucRegInvalid},
	}
	for _, tc := range cases {
		if got := regMap(tc.in); got != tc.want {
			t.Errorf("regMap(%s=%d) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}
