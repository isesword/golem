// Package arch is the CPU-architecture layer of golem's arch/platform
// abstraction (DESIGN.md §3.2): the user-space calling ABI (role registers,
// pointer size, TLS base) and the guest trampoline stub encoding, keyed by
// (ID, Variant). It deliberately contains NO syscall-transport knowledge
// (number register, -errno encoding — that is platform's SyscallABI, P2), no
// relocations (loader, P3), and no layout policy (platform, P4/P5).
//
// Dependency direction: arch -> emu, never emu -> arch.
package arch

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// ID abstracts the object-format machine identity (ELF e_machine /
// Mach-O cputype). Values follow ELF numbering where one exists.
type ID uint16

const (
	// IDARM64 is ELF EM_AARCH64.
	IDARM64 ID = 183
)

// Variant distinguishes ISA variants that share one engine architecture.
// ARM64E still runs on emu.ArchARM64; the variant matters to the loader
// (authenticated fixups) and platform, not to backend creation.
type Variant uint16

const (
	VariantGeneric Variant = iota
	VariantARM64E
)

// ABI is the user-space calling convention of one (ID, Variant): which
// registers carry arguments / the return value / PC / SP / LR, the pointer
// size, and how to set the TLS base. It is "the calling convention of the
// current target environment", not a pure CPU property — if a future target
// splits calling conventions on one CPU (e.g. Windows x64), that is a new
// seam, not a parameter to add now (YAGNI).
type ABI interface {
	// EngineArch reports the emu.Arch a backend must be created with.
	EngineArch() emu.Arch

	PC() emu.Reg
	SP() emu.Reg
	LR() emu.Reg

	// Arg returns the register carrying integer argument i of a plain
	// function call (AAPCS64: X0+i, i in [0,7]). An out-of-range i panics:
	// asking for a 9th integer argument register is a programming error,
	// not a guest condition.
	Arg(i int) emu.Reg
	// Ret returns the integer return-value register.
	Ret() emu.Reg

	// PtrSize is the guest pointer width in bytes (arm64: 8).
	PtrSize() int
	// ByteOrder is the guest byte order. All current targets are
	// little-endian; kept for codec completeness only.
	ByteOrder() binary.ByteOrder

	// SetTLSBase points the thread-pointer register (TPIDR_EL0 on arm64) at
	// the TLS slot array.
	SetTLSBase(b emu.Backend, addr uint64) error

	// NormalizeCodeAddr performs simple architectural address
	// canonicalization (Thumb-bit strip on ARM32; TBI on AArch64). It
	// explicitly does NOT recover PAC signatures — ARM64e authenticated
	// fixups are the Mach-O loader's explicit, Variant-gated job
	// (DESIGN.md invariant 9).
	NormalizeCodeAddr(addr uint64) uint64
}

// StubKind classifies a guest trampoline stub.
type StubKind uint8

const (
	// StubHostCall is a guest→host function-call trampoline: a
	// host-implemented function entry or an interop (JNI/JavaVM) table slot.
	StubHostCall StubKind = iota
	// StubUnresolved is the placeholder for an import no loaded module
	// exports (traps, logs, returns an optimistic 0).
	StubUnresolved
)

// StubEncoder emits the guest machine code of a trampoline stub. It is a
// capability separate from ABI on purpose: how a stub is ENCODED (a CPU
// instruction property), how it is CAPTURED (emu.TrapKind / backend hook,
// DESIGN.md §3.1), and how a syscall reaches the kernel (platform) are three
// different concerns and must not be merged.
//
// Trap identity is deliberately NOT carried in the stub bytes (e.g. an svc
// immediate encoding the kind): that would turn an encoding detail into a
// cross-architecture protocol that e.g. AMD64 (int3 trampolines) cannot
// honor. Classification is by trap-source address (inside the stub region)
// plus the emulator's stub metadata table.
type StubEncoder interface {
	EmitStub(kind StubKind) ([]byte, error)
}

// --- registry (same style as internal/emu/registry.go) -------------------

type regKey struct {
	id ID
	v  Variant
}

var registry = map[regKey]ABI{}

// Register makes an ABI available under (id, v); called from an
// implementation package's init(). As in emu.Register, a duplicate key
// overwrites — registration happens at init time, so the last linked
// implementation wins.
func Register(id ID, v Variant, a ABI) {
	if a == nil {
		return
	}
	registry[regKey{id, v}] = a
}

// Resolve returns the ABI registered for (id, v). An unknown pair is an
// error naming the missing implementation — the fix is to import the
// relevant arch/<name> package for its init().
func Resolve(id ID, v Variant) (ABI, error) {
	if a, ok := registry[regKey{id, v}]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("arch: no ABI registered for id=%d variant=%d (import the arch/<name> package for its init())", id, v)
}
