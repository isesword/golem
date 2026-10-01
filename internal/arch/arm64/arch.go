package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// cpuArch is the AArch64 CPU property set (arch.Arch). The zero value is
// valid and stateless. It knows nothing about how functions are called —
// that is aapcs64 (callabi.go); the trampoline encoding is stubEncoder
// (stub.go), and the CPU feature set is cpuFeatures (features.go). All four
// are registered together for (IDARM64, VariantGeneric) AND (IDARM64,
// VariantARM64E) —: ARM64E is the same engine architecture, calling
// convention, stub encoding and feature set; the variant difference
// (authenticated chained fixups) is the loader's business, so the quad is
// deliberately NOT forked.
type cpuArch struct{}

func init() {
	arch.Register(arch.IDARM64, arch.VariantGeneric, cpuArch{}, aapcs64{}, stubEncoder{}, cpuFeatures{})
	arch.Register(arch.IDARM64, arch.VariantARM64E, cpuArch{}, aapcs64{}, stubEncoder{}, cpuFeatures{})
}

func (cpuArch) EngineArch() emu.Arch { return emu.ArchARM64 }

func (cpuArch) PC() emu.Reg { return PC }
func (cpuArch) SP() emu.Reg { return SP }

func (cpuArch) PtrSize() int { return 8 }

// Caps reports the AArch64 address-space limits golem assumes: 64-bit
// pointers, the 39-bit user VA of the standard ARM64 Linux 4 KiB-page
// configuration. The platform LayoutPolicy validates against these before
// planning a memory.Layout .
func (cpuArch) Caps() arch.AddressSpaceCaps {
	return arch.AddressSpaceCaps{
		PointerBits: 64,
		VABits:      39,
		PageSize:    0x1000,
		MaxUserVA:   1 << 39,
	}
}

func (cpuArch) ByteOrder() binary.ByteOrder { return binary.LittleEndian }

// SetTLSBase writes the thread-pointer register TPIDR_EL0.
func (cpuArch) SetTLSBase(b emu.Backend, addr emu.GuestAddr) error {
	return b.RegWrite(TPIDR_EL0, uint64(addr))
}

// NormalizeCodeAddr is the identity on AArch64 as golem runs it: TBI
// (top-byte ignore) would strip addr[63:56], but golem never enables
// TCR_EL1.TBI, so guest code addresses are already canonical. PAC signature
// recovery is explicitly out of scope here (DESIGN.md invariant 9).
func (cpuArch) NormalizeCodeAddr(addr emu.GuestAddr) emu.GuestAddr { return addr }

// ReadRole implements arch.RoleReader register roles by ABI meaning.
// CPU-state observation — valid at any PC. RoleFP reads X29, which has no
// abstract id (the frozen set is sparse), through the register-file dump.
func (cpuArch) ReadRole(b emu.Backend, role arch.RegisterRole) (uint64, error) {
	switch role {
	case arch.RolePC:
		return b.RegRead(PC)
	case arch.RoleSP:
		return b.RegRead(SP)
	case arch.RoleLR:
		return b.RegRead(LR)
	case arch.RoleTLS:
		return b.RegRead(TPIDR_EL0)
	case arch.RoleFP:
		rr, ok := b.(emu.RegFileReader)
		if !ok {
			return 0, fmt.Errorf("arch: arm64 RoleFP (X29) needs the RegFileReader capability: %w", arch.ErrUnsupportedRole)
		}
		regs, err := rr.ReadGPRegs()
		if err != nil {
			return 0, err
		}
		const fpIdx = 29 // AArch64 file order: [0..30]=x0..x30 → x29 at 29
		if len(regs) <= fpIdx {
			return 0, fmt.Errorf("arch: arm64 register file too short for X29: %w", arch.ErrUnsupportedRole)
		}
		return regs[fpIdx], nil
	default:
		return 0, fmt.Errorf("arch: role %v: %w", role, arch.ErrUnsupportedRole)
	}
}

// arm64 implements the role observer.
var _ arch.RoleReader = cpuArch{}
