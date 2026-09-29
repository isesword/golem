package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// abi is the AAPCS64 user-space calling convention for AArch64. The zero
// value is valid and stateless; one instance is registered for
// (IDARM64, VariantGeneric). It also implements arch.StubEncoder (stub.go).
type abi struct{}

func init() {
	arch.Register(arch.IDARM64, arch.VariantGeneric, abi{})
}

func (abi) EngineArch() emu.Arch { return emu.ArchARM64 }

func (abi) PC() emu.Reg { return PC }
func (abi) SP() emu.Reg { return SP }
func (abi) LR() emu.Reg { return LR }

// Arg implements AAPCS64: integer arguments 0..7 arrive in X0..X7.
func (abi) Arg(i int) emu.Reg {
	if i < 0 || i > 7 {
		panic(fmt.Sprintf("arm64: Arg(%d) out of range — AAPCS64 passes integer args 0..7 in X0..X7", i))
	}
	return X0 + emu.Reg(i)
}

func (abi) Ret() emu.Reg { return X0 }

func (abi) PtrSize() int { return 8 }

func (abi) ByteOrder() binary.ByteOrder { return binary.LittleEndian }

// SetTLSBase writes the thread-pointer register TPIDR_EL0.
func (abi) SetTLSBase(b emu.Backend, addr uint64) error {
	return b.RegWrite(TPIDR_EL0, addr)
}

// NormalizeCodeAddr is the identity on AArch64 as golem runs it: TBI
// (top-byte ignore) would strip addr[63:56], but golem never enables
// TCR_EL1.TBI, so guest code addresses are already canonical. PAC signature
// recovery is explicitly out of scope here (DESIGN.md invariant 9).
func (abi) NormalizeCodeAddr(addr uint64) uint64 { return addr }
