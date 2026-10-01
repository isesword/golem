package arm64

import (
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// TestFrozenRegIDs pins the numeric values of the register ids. They are a
// frozen contract: internal/emu's unicorn backend (regMap) translates them by
// NUMBER — it cannot import this package (import cycle) — so a silent
// renumbering here would corrupt register access without any compile error.
// The values match the constants deleted from internal/emu, one for one.
func TestFrozenRegIDs(t *testing.T) {
	cases := []struct {
		name string
		got  emu.Reg
		want emu.Reg
	}{
		{"X0", X0, 0},
		{"X1", X1, 1},
		{"X2", X2, 2},
		{"X3", X3, 3},
		{"X4", X4, 4},
		{"X5", X5, 5},
		{"X6", X6, 6},
		{"X7", X7, 7},
		{"X8", X8, 8},
		{"X9", X9, 9},
		{"X10", X10, 10},
		{"X23", X23, 11},
		{"SP", SP, 12},
		{"PC", PC, 13},
		{"LR", LR, 14},
		{"NZCV", NZCV, 15},
		{"TPIDR_EL0", TPIDR_EL0, 16},
		{"X16", X16, 17}, // appended in; the preexisting ids above stay frozen
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (ids are frozen; see package doc)", tc.name, tc.got, tc.want)
		}
	}
}
