package arm32

import (
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// TestFrozenRegIDs pins the abstract emu.Reg numbers this package assigns.
// The unicorn backend's arm32 regMap will key on these NUMBERS (it cannot
// import this package — import cycle); any drift fails here loudly instead
// of corrupting registers.
func TestFrozenRegIDs(t *testing.T) {
	cases := []struct {
		name string
		got  emu.Reg
		want emu.Reg
	}{
		{"R0", R0, 96}, {"R1", R1, 97}, {"R2", R2, 98}, {"R3", R3, 99},
		{"R4", R4, 100}, {"R5", R5, 101}, {"R6", R6, 102}, {"R7", R7, 103},
		{"R8", R8, 104}, {"R9", R9, 105}, {"R10", R10, 106}, {"R11", R11, 107},
		{"R12", R12, 108}, {"R13", R13, 109}, {"R14", R14, 110}, {"R15", R15, 111},
		{"CPSR", CPSR, 112},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want frozen id %d", tc.name, tc.got, tc.want)
		}
	}
	// The role aliases must be the SAME ids as the bank registers — ARM32's
	// SP/LR/PC are r13/r14/r15, not separate registers.
	if SP != R13 || LR != R14 || PC != R15 {
		t.Errorf("aliases drifted: SP=%d LR=%d PC=%d, want %d/%d/%d", SP, LR, PC, R13, R14, R15)
	}
}

// TestRegBlockDisjoint pins the block-allocation invariant: the arm32 ids
// (96..112) must not collide with arm64's (0..17) or amd64's (64..83) —
// a wrong-arch register id must fail loudly in the backend mapping, never
// alias. Expressed without importing the sibling packages (numbers are the
// contract, per the frozen-id rule).
func TestRegBlockDisjoint(t *testing.T) {
	for r := R0; r <= CPSR; r++ {
		if r < 96 || r > 112 {
			t.Fatalf("reg %d escaped the arm32 block [96,112]", r)
		}
		if r >= 64 && r <= 83 {
			t.Fatalf("reg %d collides with the amd64 block [64,83]", r)
		}
		if r <= 17 {
			t.Fatalf("reg %d collides with the arm64 block [0,17]", r)
		}
	}
}
