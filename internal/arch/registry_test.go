package arch

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// fakes for registry tests, tagged so overwrite semantics are observable.

type fakeArch struct{ tag string }

func (f fakeArch) EngineArch() emu.Arch                        { return emu.ArchARM64 }
func (f fakeArch) PC() emu.Reg                                 { return 0 }
func (f fakeArch) SP() emu.Reg                                 { return 0 }
func (f fakeArch) PtrSize() int                                { return 8 }
func (f fakeArch) ByteOrder() binary.ByteOrder                 { return binary.LittleEndian }
func (f fakeArch) SetTLSBase(emu.Backend, emu.GuestAddr) error { return nil }
func (f fakeArch) Caps() AddressSpaceCaps {
	return AddressSpaceCaps{PointerBits: 64, VABits: 39, PageSize: 0x1000, MaxUserVA: 1 << 39}
}
func (f fakeArch) NormalizeCodeAddr(a emu.GuestAddr) emu.GuestAddr {
	return a
}

type fakeCallABI struct{ tag string }

func (f fakeCallABI) Arg(i int) emu.Reg { return emu.Reg(i) }
func (f fakeCallABI) Ret() emu.Reg      { return 0 }
func (f fakeCallABI) LR() emu.Reg       { return 0 }
func (f fakeCallABI) ArgReg(i int) (emu.Reg, bool) {
	return emu.Reg(i), true
}
func (f fakeCallABI) PrepareCall(emu.Backend, CallRequest) error { return nil }
func (f fakeCallABI) ReadArgs(emu.Backend, int) ([]uint64, error) {
	return nil, nil
}
func (f fakeCallABI) WriteResult(emu.Backend, CallResult) error  { return nil }
func (f fakeCallABI) ReadResult(emu.Backend) (CallResult, error) { return CallResult{}, nil }
func (f fakeCallABI) ReturnFromCall(emu.Backend) error           { return nil }

type fakeStubEnc struct{ tag string }

func (f fakeStubEnc) EmitStub(StubKind) ([]byte, error) { return nil, nil }

type fakeFeatures struct{ tag string }

func (f fakeFeatures) Has(Feature) bool        { return false }
func (f fakeFeatures) HWCAP() (uint64, uint64) { return 0, 0 }

func TestRegisterResolve(t *testing.T) {
	const id = ID(0xF00D) // test-only id, clear of ELF EM_AARCH64 (183)

	Register(id, VariantGeneric, fakeArch{"a1"}, fakeCallABI{"c1"}, fakeStubEnc{"s1"}, fakeFeatures{"f1"})
	a, c, s, feat, err := Resolve(id, VariantGeneric)
	if err != nil {
		t.Fatalf("Resolve after Register: %v", err)
	}
	if a.(fakeArch).tag != "a1" || c.(fakeCallABI).tag != "c1" || s.(fakeStubEnc).tag != "s1" || feat.(fakeFeatures).tag != "f1" {
		t.Fatalf("Resolve returned (%q,%q,%q,%q), want (a1,c1,s1,f1)",
			a.(fakeArch).tag, c.(fakeCallABI).tag, s.(fakeStubEnc).tag, feat.(fakeFeatures).tag)
	}

	// Duplicate registration overwrites (same style as emu.Register).
	Register(id, VariantGeneric, fakeArch{"a2"}, fakeCallABI{"c2"}, fakeStubEnc{"s2"}, fakeFeatures{"f2"})
	a, c, s, feat, err = Resolve(id, VariantGeneric)
	if err != nil {
		t.Fatalf("Resolve after duplicate Register: %v", err)
	}
	if a.(fakeArch).tag != "a2" || c.(fakeCallABI).tag != "c2" || s.(fakeStubEnc).tag != "s2" || feat.(fakeFeatures).tag != "f2" {
		t.Fatalf("duplicate Register must overwrite, got (%q,%q,%q,%q)",
			a.(fakeArch).tag, c.(fakeCallABI).tag, s.(fakeStubEnc).tag, feat.(fakeFeatures).tag)
	}
}

func TestRegisterNilComponentIgnored(t *testing.T) {
	// A registration with ANY nil component must not make the key resolvable:
	// a partial quad can never serve a Target.
	full := []struct {
		a Arch
		c CallABI
		s StubEncoder
		f CPUFeatures
	}{
		{nil, fakeCallABI{"c"}, fakeStubEnc{"s"}, fakeFeatures{"f"}},
		{fakeArch{"a"}, nil, fakeStubEnc{"s"}, fakeFeatures{"f"}},
		{fakeArch{"a"}, fakeCallABI{"c"}, nil, fakeFeatures{"f"}},
		{fakeArch{"a"}, fakeCallABI{"c"}, fakeStubEnc{"s"}, nil},
	}
	for i, tc := range full {
		id := ID(0xF100 + i)
		Register(id, VariantGeneric, tc.a, tc.c, tc.s, tc.f)
		if _, _, _, _, err := Resolve(id, VariantGeneric); err == nil {
			t.Fatalf("Register with nil component %d must not make the key resolvable", i)
		}
	}
}

func TestResolveUnknown(t *testing.T) {
	if _, _, _, _, err := Resolve(ID(0xBEEF), VariantGeneric); err == nil {
		t.Fatal("unknown ID must error")
	}
	// A registered ID with an unregistered variant is likewise unknown
	// (no silent variant fallback).
	Register(ID(0xF00F), VariantGeneric, fakeArch{"a"}, fakeCallABI{"c"}, fakeStubEnc{"s"}, fakeFeatures{"f"})
	if _, _, _, _, err := Resolve(ID(0xF00F), VariantARM64E); err == nil {
		t.Fatal("unknown variant must error")
	}
}
