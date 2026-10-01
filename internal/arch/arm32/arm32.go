// Package arm32 assigns the abstract emu.Reg ids for the ARM32 (armv7
// EABI) register set — the third architecture of the arch/platform
// abstraction, mirroring internal/arch/arm64 and internal/arch/amd64.
//
// Like the other arch packages, these numbers are the single source of
// truth for register identity: callers write arm32.R0 & co., and each CPU
// backend translates the abstract emu.Reg to its engine's own numbering
// (e.g. UC_ARM_REG_*). The numbers are FROZEN once assigned
// (TestFrozenRegIDs pins them); the unicorn backend's arm32 regMap will
// key on them (it cannot import this package: arm32 imports emu for
// emu.Reg, so the reverse would be an import cycle).
//
// The block starts at 96, deliberately disjoint from arm64's 0..17 and
// amd64's 64..83: a register id handed to the wrong architecture's backend
// mapping fails loudly instead of silently aliasing another arch's
// register.
//
// SP/LR/PC are ALIASES of R13/R14/R15 — on ARM32 those are the same
// physical registers, unlike arm64 where SP/PC/LR are distinct from the
// X bank (and got their own ids). Aliasing keeps the backend mapping 1:1.
//
// Scope note: this package deliberately ships ONLY the register constants
// at this stage. The Arch/CallABI/StubEncoder/CPUFeatures quad and its
// registration are that port's work; the constants exist now so parallel agents
// (transport, P6d loader) can import them.
//
// Dependency direction: arm32 -> emu, never emu -> arm32.
package arm32

import "github.com/isesword/golem/internal/emu"

const (
	R0 emu.Reg = 96 + iota
	R1
	R2
	R3
	R4
	R5
	R6
	R7
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
	CPSR
	// TPIDRURW is the ARM32 Linux thread-pointer register (CP15 c13,c0,3 —
	// the user read/write thread ID register). Appended AFTER the frozen
	// set (the "unicorn mapping needs" the block doc reserves): every id
	// above keeps its number; TPIDRURW is id 113.
	TPIDRURW
)

// Conventional role names: the same ids as R13/R14/R15 (see the package
// doc — aliases, not separate registers).
const (
	SP = R13 // stack pointer
	LR = R14 // link register
	PC = R15 // program counter
)

// Compile-time type pin: the ids must stay emu.Reg so they can be passed to
// Backend.RegRead/RegWrite without conversion.
const _ emu.Reg = R0
