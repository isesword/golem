package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// regRec is an emu.Backend test double recording RegWrite calls.
type regRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	writes      map[emu.Reg]uint64
}

func (r *regRec) RegWrite(reg emu.Reg, v uint64) error {
	if r.writes == nil {
		r.writes = map[emu.Reg]uint64{}
	}
	r.writes[reg] = v
	return nil
}

func resolveABI(t *testing.T) arch.ABI {
	t.Helper()
	a, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("arm64 ABI must be registered by this package's init: %v", err)
	}
	return a
}

func TestABIRegistration(t *testing.T) {
	a := resolveABI(t)
	if a.EngineArch() != emu.ArchARM64 {
		t.Fatalf("EngineArch = %v, want ArchARM64", a.EngineArch())
	}
	if _, ok := a.(arch.StubEncoder); !ok {
		t.Fatal("the arm64 ABI instance must also implement arch.StubEncoder")
	}
}

func TestABIRoleRegisters(t *testing.T) {
	a := resolveABI(t)
	if a.PC() != PC || a.SP() != SP || a.LR() != LR || a.Ret() != X0 {
		t.Fatalf("role regs: PC=%v SP=%v LR=%v Ret=%v", a.PC(), a.SP(), a.LR(), a.Ret())
	}
	for i := 0; i < 8; i++ {
		if got, want := a.Arg(i), X0+emu.Reg(i); got != want {
			t.Fatalf("Arg(%d) = %v, want %v", i, got, want)
		}
	}
	if a.PtrSize() != 8 {
		t.Fatalf("PtrSize = %d, want 8", a.PtrSize())
	}
	if a.ByteOrder() != binary.LittleEndian {
		t.Fatal("ByteOrder must be little-endian")
	}
}

func TestArgOutOfRangePanics(t *testing.T) {
	a := resolveABI(t)
	for _, i := range []int{-1, 8, 100} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Arg(%d) must panic", i)
				}
				if s, ok := r.(string); !ok || s == "" {
					t.Fatalf("Arg(%d) panic must carry a message, got %v", i, r)
				}
			}()
			a.Arg(i)
		}()
	}
}

func TestSetTLSBase(t *testing.T) {
	a := resolveABI(t)
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
	a := resolveABI(t)
	for _, addr := range []uint64{0, 0x1234, 0xffffff00, 0xff00000000001234} {
		if got := a.NormalizeCodeAddr(addr); got != addr {
			t.Fatalf("NormalizeCodeAddr(%#x) = %#x, want identity (TBI off)", addr, got)
		}
	}
}

// TestEmitStubBytes pins the trampoline encoding byte-for-byte to the
// pre-P1 hardcoded `svc #0 ; ret` — both stub kinds intentionally emit the
// same bytes (classification is by address + metadata, not svc immediate).
func TestEmitStubBytes(t *testing.T) {
	a := resolveABI(t)
	enc := a.(arch.StubEncoder)
	want := []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6} // svc #0 ; ret
	for _, kind := range []arch.StubKind{arch.StubHostCall, arch.StubUnresolved} {
		got, err := enc.EmitStub(kind)
		if err != nil {
			t.Fatalf("EmitStub(%d): %v", kind, err)
		}
		if !bytesEqual(got, want) {
			t.Fatalf("EmitStub(%d) = % x, want % x (pre-P1 hardcoded bytes)", kind, got, want)
		}
		got[0] ^= 0xff // mutating the result must not corrupt later emissions
	}
	again, err := enc.EmitStub(arch.StubHostCall)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(again, want) {
		t.Fatalf("EmitStub returned aliased storage: % x", again)
	}
	if _, err := enc.EmitStub(arch.StubKind(99)); err == nil {
		t.Fatal("unknown stub kind must error")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
