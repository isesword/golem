package arm64

import (
	"encoding/binary"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// cpuArch is the AArch64 CPU property set (arch.Arch). The zero value is
// valid and stateless. It knows nothing about how functions are called —
// that is aapcs64 (callabi.go); the trampoline encoding is stubEncoder
// (stub.go). All three are registered together for (IDARM64, VariantGeneric).
type cpuArch struct{}

func init() {
	arch.Register(arch.IDARM64, arch.VariantGeneric, cpuArch{}, aapcs64{}, stubEncoder{})
}

func (cpuArch) EngineArch() emu.Arch { return emu.ArchARM64 }

func (cpuArch) PC() emu.Reg { return PC }
func (cpuArch) SP() emu.Reg { return SP }

func (cpuArch) PtrSize() int { return 8 }

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
