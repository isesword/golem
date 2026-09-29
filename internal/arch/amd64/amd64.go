// Package amd64 assigns the abstract emu.Reg ids for the AMD64 (x86-64)
// register set and registers the (Arch, CallABI, StubEncoder, CPUFeatures)
// quad for (IDAMD64, VariantGeneric) — the second architecture of the
// arch/platform abstraction (P5a), mirroring internal/arch/arm64.
//
// Like arm64's ids, these numbers are the single source of truth for register
// identity: callers write amd64.RAX & co., and each CPU backend translates
// the abstract emu.Reg to its engine's own numbering (e.g. UC_X86_REG_*).
// The numbers are FROZEN once assigned (TestFrozenRegIDs pins them); the
// unicorn backend's amd64 regMap keys on them (it cannot import this package:
// amd64 imports emu for emu.Reg, so the reverse would be an import cycle).
//
// The block starts at 64, deliberately disjoint from arm64's 0..16: a register
// id handed to the wrong architecture's backend mapping fails loudly
// (ucRegInvalid) instead of silently aliasing another arch's register.
//
// Dependency direction: amd64 -> emu, never emu -> amd64.
package amd64

import "github.com/isesword/golem/internal/emu"

const (
	RAX emu.Reg = 64 + iota
	RBX
	RCX
	RDX
	RSI
	RDI
	RBP
	RSP
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
	RIP
	EFLAGS
	FS_BASE // FS segment base — the x86-64 TLS base (arch_prctl ARCH_SET_FS)
	GS_BASE
)

// Compile-time type pin: the ids must stay emu.Reg so they can be passed to
// Backend.RegRead/RegWrite without conversion.
const _ emu.Reg = RAX
