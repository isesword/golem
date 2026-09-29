// Package arch is the CPU-architecture layer of golem's arch/platform
// abstraction (DESIGN.md §3.2). It separates two concerns that the pre-P2.5b
// arch.ABI interface mixed (invariant 13):
//
//   - Arch    — pure CPU properties: role registers PC/SP, pointer size, byte
//     order, TLS base, address canonicalization. It knows NOTHING about how
//     functions are called.
//   - CallABI — the function calling convention (AAPCS64 / AAPCS32 / SysV
//     AMD64 / Win64): argument registers, result write-back, the return flow,
//     and the return-address concept (LR). One CPU can host several calling
//     conventions (AMD64 SysV vs Win64) without polluting the CPU layer.
//
// plus the guest trampoline StubEncoder (stub.go), an independent capability.
// A Target composes one of each, resolved together by (ID, Variant) from the
// registry (registry.go).
//
// This package deliberately contains NO syscall-transport knowledge (number
// register, -errno encoding — that is platform's SyscallTransport, P2), no
// relocations (loader, P3), and no layout policy (platform, P4/P5).
//
// Dependency direction: arch -> emu, never emu -> arch.
package arch

import (
	"encoding/binary"

	"github.com/isesword/golem/internal/emu"
)

// ID abstracts the object-format machine identity (ELF e_machine /
// Mach-O cputype). Values follow ELF numbering where one exists.
type ID uint16

const (
	// IDARM64 is ELF EM_AARCH64.
	IDARM64 ID = 183
	// IDAMD64 is ELF EM_X86_64.
	IDAMD64 ID = 62
)

// Variant distinguishes ISA variants that share one engine architecture.
// ARM64E still runs on emu.ArchARM64; the variant matters to the loader
// (authenticated fixups) and platform, not to backend creation.
type Variant uint16

const (
	VariantGeneric Variant = iota
	VariantARM64E
)

// AddressSpaceCaps are the CPU's address-space limits (DESIGN.md §3.2): the
// raw material a platform LayoutPolicy composes with its own conventions and
// user overrides to produce a memory.Layout. Pure data, no policy.
type AddressSpaceCaps struct {
	PointerBits int    // guest pointer width in bits (arm64: 64)
	VABits      int    // usable virtual-address bits (arm64 Linux 4K pages: 39)
	PageSize    uint64 // guest page granularity in bytes (0x1000)
	MaxUserVA   uint64 // first address above the user space (1 << VABits)
}

// Arch is the pure CPU property set of one (ID, Variant): which registers are
// PC/SP, the pointer size and byte order, how to set the TLS base, and simple
// architectural address canonicalization. It does NOT know how functions are
// called — arguments, results and the return flow belong to CallABI
// (DESIGN.md invariant 13).
type Arch interface {
	// EngineArch reports the emu.Arch a backend must be created with.
	EngineArch() emu.Arch

	PC() emu.Reg
	SP() emu.Reg

	// PtrSize is the guest pointer width in bytes (arm64: 8).
	PtrSize() int
	// ByteOrder is the guest byte order. All current targets are
	// little-endian; kept for codec completeness only.
	ByteOrder() binary.ByteOrder

	// Caps reports the address-space capabilities a platform LayoutPolicy
	// plans against (P4c).
	Caps() AddressSpaceCaps

	// SetTLSBase points the thread-pointer register (TPIDR_EL0 on arm64) at
	// the TLS slot array.
	SetTLSBase(b emu.Backend, addr emu.GuestAddr) error

	// NormalizeCodeAddr performs simple architectural address
	// canonicalization (Thumb-bit strip on ARM32; TBI on AArch64). It
	// explicitly does NOT recover PAC signatures — ARM64e authenticated
	// fixups are the Mach-O loader's explicit, Variant-gated job
	// (DESIGN.md invariant 9).
	NormalizeCodeAddr(addr emu.GuestAddr) emu.GuestAddr
}
