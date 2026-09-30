package emulator

// P9 Public Semantic API — register roles. Read a register by WHAT IT MEANS
// in the ABI (link register, frame pointer, TLS base), never by its
// per-architecture name. Role reads are CPU-state observation: valid at any
// hook kind, at any PC.

import (
	"github.com/isesword/golem/internal/arch"
)

// RegisterRole names a register by its ABI role (type alias — the role
// vocabulary lives in internal/arch, this is its public face).
type RegisterRole = arch.RegisterRole

const (
	RolePC RegisterRole = arch.RolePC // program counter
	RoleSP RegisterRole = arch.RoleSP // stack pointer
	RoleFP RegisterRole = arch.RoleFP // frame pointer (arm64 X29, arm32 R11, amd64 RBP)
	RoleLR RegisterRole = arch.RoleLR // link register (arm64 X30, arm32 R14; AMD64: unsupported)
	RoleTLS RegisterRole = arch.RoleTLS // thread-pointer base (TPIDR_EL0 / TPIDRURW / FS base)
)

// ErrUnsupportedRole reports that THIS architecture has no register for the
// requested role (e.g. RoleLR on AMD64). The distinction matters: it is an
// architecture fact, not a context problem.
var ErrUnsupportedRole = arch.ErrUnsupportedRole
