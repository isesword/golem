package emu

// This file holds the architecture/trap vocabulary introduced in P0 of the
// arch-platform abstraction: names only, no behavior change. Today the only
// compiled backend (unicorn) supports exactly ArchARM64; the rest of the enum
// reserves the design space for ARM32/AMD64 (see ARCHITECTURE.md).

// Arch identifies a guest CPU architecture. It is passed to a backend Factory
// at engine creation; a backend asked for an arch it does not implement
// returns an error wrapping ErrUnsupported.
type Arch uint8

const (
	ArchARM64 Arch = iota + 1
	ArchARM
	ArchAMD64
)

// String names the arch for logs and error messages.
func (a Arch) String() string {
	switch a {
	case ArchARM64:
		return "arm64"
	case ArchARM:
		return "arm"
	case ArchAMD64:
		return "amd64"
	default:
		return "unknown"
	}
}

// TrapKind classifies why guest execution trapped into the host.
type TrapKind uint8

const (
	// TrapHostCall is a guest→host function call (golem's patched stubs).
	TrapHostCall TrapKind = iota
	// TrapSyscall is a guest Linux syscall.
	TrapSyscall
	// TrapUnresolved is any trap the engine cannot classify.
	TrapUnresolved
)

// TrapHandler fires when guest execution traps into the host. The kind
// argument identifies the trap class. P0: the unicorn backend passes each
// handler the kind it was REGISTERED under (no runtime discrimination yet —
// see Backend.InstallTrap).
type TrapHandler func(b Backend, kind TrapKind)
