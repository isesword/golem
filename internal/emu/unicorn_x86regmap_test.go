//go:build unicorn

package emu

import "testing"

// TestAMD64RegMapFrozenIDs verifies regMapAMD64 translates the frozen
// arch/amd64 id NUMBERS (RAX=64 .. GS_BASE=83, NoLR=-1) to the right
// UC_X86_REG_* ids. regMapAMD64 keys on numbers because emu cannot import
// internal/arch/amd64 (import cycle); arch/amd64's TestFrozenRegIDs pins the
// numbering on that side. The UC_X86_REG_* targets are pinned against
// unicorn2's x86.h (see unicorn_amd64.go).
func TestAMD64RegMapFrozenIDs(t *testing.T) {
	cases := []struct {
		name string
		in   Reg
		want int32
	}{
		{"RAX", 64, ucX86RegRAX},
		{"RBX", 65, ucX86RegRBX},
		{"RCX", 66, ucX86RegRCX},
		{"RDX", 67, ucX86RegRDX},
		{"RSI", 68, ucX86RegRSI},
		{"RDI", 69, ucX86RegRDI},
		{"RBP", 70, ucX86RegRBP},
		{"RSP", 71, ucX86RegRSP},
		{"R8", 72, ucX86RegR8},
		{"R9", 73, ucX86RegR9},
		{"R10", 74, ucX86RegR10},
		{"R11", 75, ucX86RegR11},
		{"R12", 76, ucX86RegR12},
		{"R13", 77, ucX86RegR13},
		{"R14", 78, ucX86RegR14},
		{"R15", 79, ucX86RegR15},
		{"RIP", 80, ucX86RegRIP},
		{"EFLAGS", 81, ucX86RegEFLAGS},
		{"FS_BASE", 82, ucX86RegFSBase},
		{"GS_BASE", 83, ucX86RegGSBase},
		{"NoLR", -1, ucRegInvalid}, // stack-returning convention: no LR register
		{"invalid", 9999, ucRegInvalid},
		{"arm64.X0-in-amd64-map", 0, ucRegInvalid}, // cross-arch ids must not alias
	}
	for _, tc := range cases {
		if got := regMapAMD64(tc.in); got != tc.want {
			t.Errorf("regMapAMD64(%s=%d) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}
