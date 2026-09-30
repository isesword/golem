package arch

import (
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// This file is the P9 register-ROLE vocabulary: the Public Semantic API's
// answer to "which register holds the link register" without the caller
// naming X30/R14/[rsp] themselves. Roles are ABI concepts; per-arch names
// stay in the arch packages.

// RegisterRole names a register by its ABI ROLE. A role may be unsupported
// by an architecture (AMD64 has no link register) — unsupported is a loud
// ErrUnsupportedRole, never a silent zero.
type RegisterRole uint8

const (
	RolePC RegisterRole = iota // program counter (arm64 PC, arm32 R15, amd64 RIP)
	RoleSP                     // stack pointer (arm64 SP, arm32 R13, amd64 RSP)
	RoleFP                     // frame pointer (arm64 X29, arm32 R11, amd64 RBP)
	RoleLR                     // link register (arm64 X30, arm32 R14; AMD64: NONE)
	RoleTLS                    // thread-pointer base (arm64 TPIDR_EL0, arm32 TPIDRURW, amd64 FS base)
)

func (r RegisterRole) String() string {
	switch r {
	case RolePC:
		return "pc"
	case RoleSP:
		return "sp"
	case RoleFP:
		return "fp"
	case RoleLR:
		return "lr"
	case RoleTLS:
		return "tls"
	default:
		return fmt.Sprintf("role(%d)", uint8(r))
	}
}

// ErrUnsupportedRole reports that THIS architecture has no register for the
// requested role (e.g. RoleLR on AMD64 — the return address lives on the
// stack). Distinct from a context problem: a role read is CPU-state
// observation and is valid at any PC where the hook fires.
var ErrUnsupportedRole = errors.New("arch: register role not supported by this architecture")

// RoleReader is the OPTIONAL per-arch register-role observer (P9, invariant
// 14 style: the arch core does not grow for it — quads that can serve roles
// implement this small interface and consumers probe it). Role reads are
// CPU-state observation: valid at ANY hook kind, at any PC.
type RoleReader interface {
	ReadRole(b emu.Backend, role RegisterRole) (uint64, error)
}
