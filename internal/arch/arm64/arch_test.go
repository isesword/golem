package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// regRec is an emu.Backend test double with a programmable register file:
// RegRead serves preset values, RegWrite is recorded. Everything else panics
// via the nil embedded interface.
type regRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	regs        map[emu.Reg]uint64
	writes      map[emu.Reg]uint64
}

func (r *regRec) RegRead(reg emu.Reg) (uint64, error) { return r.regs[reg], nil }

func (r *regRec) RegWrite(reg emu.Reg, v uint64) error {
	if r.writes == nil {
		r.writes = map[emu.Reg]uint64{}
	}
	r.writes[reg] = v
	return nil
}

// resolveTriple resolves the registered (Arch, CallABI, StubEncoder) triple
// for (IDARM64, VariantGeneric); this package's init must have registered it.
func resolveTriple(t *testing.T) (arch.Arch, arch.CallABI, arch.StubEncoder) {
	t.Helper()
	a, c, s, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("arm64 target triple must be registered by this package's init: %v", err)
	}
	return a, c, s
}

func TestTripleRegistration(t *testing.T) {
	a, c, s := resolveTriple(t)
	if a == nil || c == nil || s == nil {
		t.Fatal("Resolve must return a non-nil Arch, CallABI and StubEncoder")
	}
	if a.EngineArch() != emu.ArchARM64 {
		t.Fatalf("EngineArch = %v, want ArchARM64", a.EngineArch())
	}
}

func TestArchCPUProperties(t *testing.T) {
	a, _, _ := resolveTriple(t)
	if a.PC() != PC || a.SP() != SP {
		t.Fatalf("role regs: PC=%v SP=%v", a.PC(), a.SP())
	}
	if a.PtrSize() != 8 {
		t.Fatalf("PtrSize = %d, want 8", a.PtrSize())
	}
	if a.ByteOrder() != binary.LittleEndian {
		t.Fatal("ByteOrder must be little-endian")
	}
}

func TestSetTLSBase(t *testing.T) {
	a, _, _ := resolveTriple(t)
	b := &regRec{}
	if err := a.SetTLSBase(b, 0xD0000000); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[TPIDR_EL0]; got != 0xD0000000 {
		t.Fatalf("SetTLSBase wrote reg TPIDR_EL0 = %#x, want 0xd0000000", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("SetTLSBase must write exactly one register, wrote %v", b.writes)
	}
}

func TestNormalizeCodeAddrIdentity(t *testing.T) {
	a, _, _ := resolveTriple(t)
	for _, addr := range []emu.GuestAddr{0, 0x1234, 0xffffff00, 0xff00000000001234} {
		if got := a.NormalizeCodeAddr(addr); got != addr {
			t.Fatalf("NormalizeCodeAddr(%#x) = %#x, want identity (TBI off)", addr, got)
		}
	}
}
