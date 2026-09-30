package amd64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// cpuArch is the AMD64 (x86-64) CPU property set (arch.Arch). The zero value
// is valid and stateless. It knows nothing about how functions are called —
// that is sysV64 (callabi.go); the trampoline encoding is stubEncoder
// (stub.go), and the CPU feature set is cpuFeatures (features.go). All four
// are registered together for (IDAMD64, VariantGeneric).
type cpuArch struct{}

func init() {
	arch.Register(arch.IDAMD64, arch.VariantGeneric, cpuArch{}, sysV64{}, stubEncoder{}, cpuFeatures{})
}

func (cpuArch) EngineArch() emu.Arch { return emu.ArchAMD64 }

func (cpuArch) PC() emu.Reg { return RIP }
func (cpuArch) SP() emu.Reg { return RSP }

func (cpuArch) PtrSize() int { return 8 }

// Caps reports the AMD64 address-space limits golem assumes: 64-bit pointers,
// 48-bit virtual addresses with the canonical user space below 2^47 (4-level
// paging, the only configuration Linux/Android x86-64 ships), 4 KiB pages.
// The platform LayoutPolicy validates against these before planning a
// memory.Layout — the Android layout constants sit far below 2^47, so the
// same plan serves both architectures.
func (cpuArch) Caps() arch.AddressSpaceCaps {
	return arch.AddressSpaceCaps{
		PointerBits: 64,
		VABits:      48,
		PageSize:    0x1000,
		MaxUserVA:   1 << 47,
	}
}

func (cpuArch) ByteOrder() binary.ByteOrder { return binary.LittleEndian }

// SetTLSBase sets the x86-64 TLS base: the FS segment base register (what
// arch_prctl(ARCH_SET_FS) programs on real Linux; guest TLS access is
// `mov reg, fs:[off]`). This is a REAL architectural mechanism, not a
// thread-pointer GPR like ARM64's TPIDR_EL0 — the backend must implement it
// (unicorn: UC_X86_REG_FS_BASE); a backend that cannot must fail loudly, a
// no-op would silently break every guest TLS read.
func (cpuArch) SetTLSBase(b emu.Backend, addr emu.GuestAddr) error {
	return b.RegWrite(FS_BASE, uint64(addr))
}

// NormalizeCodeAddr is the identity for golem's AMD64 guests: every address
// the loader produces is canonical (below 2^47), and golem never runs guest
// code through non-canonical aliases. Upper-bound canonicalization (LA57,
// 5-level paging) is out of scope — Caps pins 4-level paging.
func (cpuArch) NormalizeCodeAddr(addr emu.GuestAddr) emu.GuestAddr { return addr }

// ReadRole implements arch.RoleReader (P9): register roles by ABI meaning.
// CPU-state observation — valid at any PC. RoleLR is deliberately
// UNSUPPORTED: x86-64 has no link register (the return address lives on the
// stack — the ABI-level answer is CallABI.ReadReturnAddress, not a role).
func (cpuArch) ReadRole(b emu.Backend, role arch.RegisterRole) (uint64, error) {
	switch role {
	case arch.RolePC:
		return b.RegRead(RIP)
	case arch.RoleSP:
		return b.RegRead(RSP)
	case arch.RoleFP:
		return b.RegRead(RBP)
	case arch.RoleTLS:
		return b.RegRead(FS_BASE)
	default: // RoleLR and anything else: loud, never a silent zero
		return 0, fmt.Errorf("arch: role %v: %w", role, arch.ErrUnsupportedRole)
	}
}

// amd64 implements the P9 role observer.
var _ arch.RoleReader = cpuArch{}
