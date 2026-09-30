package arm32

import (
	"encoding/binary"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// cpuArch is the ARM32 (armv7 EABI) CPU property set (arch.Arch). The zero
// value is valid and stateless. It knows nothing about how functions are
// called — that is aapcs32 (callabi.go); the trampoline encoding is
// stubEncoder (stub.go), and the CPU feature set is cpuFeatures
// (features.go). All four are registered together for (IDARM,
// VariantGeneric).
type cpuArch struct{}

func init() {
	arch.Register(arch.IDARM, arch.VariantGeneric, cpuArch{}, aapcs32{}, stubEncoder{}, cpuFeatures{})
}

func (cpuArch) EngineArch() emu.Arch { return emu.ArchARM }

func (cpuArch) PC() emu.Reg { return PC } // r15
func (cpuArch) SP() emu.Reg { return SP } // r13

func (cpuArch) PtrSize() int { return 4 }

// Caps reports the ARM32 Linux address-space limits golem assumes: 32-bit
// pointers and the user-VA ceiling of the standard 3G/1G ARM Linux memory
// split — arch/arm's TASK_SIZE = PAGE_OFFSET(0xC0000000) - 16 MiB =
// 0xBF000000. That ceiling also keeps every mapping far below the vectors
// and kuser-helper pages at 0xFFFF0000+, which are kernel-owned. (The
// 2G/2G split's 0x7F000000 and LPAE layouts are NOT modeled — a platform
// needing one says so through its own LayoutPolicy.)
func (cpuArch) Caps() arch.AddressSpaceCaps {
	return arch.AddressSpaceCaps{
		PointerBits: 32,
		VABits:      32,
		PageSize:    0x1000,
		MaxUserVA:   0xBF000000,
	}
}

func (cpuArch) ByteOrder() binary.ByteOrder { return binary.LittleEndian }

// SetTLSBase writes the thread-pointer register TPIDRURW (CP15 c13,c0,3 —
// the user read/write thread ID register ARM32 Linux uses for TLS; bionic
// reads it via mrc).
func (cpuArch) SetTLSBase(b emu.Backend, addr emu.GuestAddr) error {
	return b.RegWrite(TPIDRURW, uint64(addr))
}

// NormalizeCodeAddr strips the Thumb interworking bit (addr &^ 1): the
// canonical form of a code ADDRESS for mapping, lookup, and comparison.
// This is deliberately an address operation only — bit0 also encodes the
// target ISA STATE at control transfers, and that meaning is interpreted
// exactly once, in the CallABI's setPCBX (CPSR.T ← bit0, PC ← addr&^1).
// Callers must not use NormalizeCodeAddr to decide execution state, and
// must not feed it an address whose bit0 they still need.
func (cpuArch) NormalizeCodeAddr(addr emu.GuestAddr) emu.GuestAddr { return addr &^ 1 }
