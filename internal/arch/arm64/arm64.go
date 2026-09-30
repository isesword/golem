// Package arm64 assigns the abstract emu.Reg ids for the AArch64 register
// set. These ids are the single source of truth for register identity across
// golem: callers write arm64.X0 & co., and each CPU backend translates the
// abstract emu.Reg to its engine's own numbering (e.g. UC_ARM64_REG_*).
//
// The constants were carved out of internal/emu unchanged in P0 of the
// arch-platform abstraction — the iota order (and therefore the numeric
// values) is frozen; the unicorn backend's regMap keys on these NUMBERS (it
// cannot import this package: arm64 imports emu for emu.Reg, so the reverse
// would be an import cycle). TestFrozenRegIDs pins the values.
//
// Dependency direction: arm64 -> emu, never emu -> arm64.
package arm64

import "github.com/isesword/golem/internal/emu"

const (
	X0 emu.Reg = iota
	X1
	X2
	X3
	X4
	X5
	X6
	X7
	X8
	X9
	X10
	X23 // used by the crypto register-dump hook in the host app
	SP
	PC
	LR // X30
	NZCV
	TPIDR_EL0
	// X16 is the Darwin syscall-number register (P5b: the BSD syscall ABI
	// passes the number in x16, unlike Linux's x8). Appended AFTER the frozen
	// P0 set — every id above keeps its number; X16 is id 17.
	X16
)

// Compile-time type pin: the ids must stay emu.Reg so they can be passed to
// Backend.RegRead/RegWrite without conversion.
const _ emu.Reg = X0
