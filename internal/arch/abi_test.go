package arch

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// fakeABI is a minimal ABI for registry tests, tagged so overwrite semantics
// are observable.
type fakeABI struct{ tag string }

func (f fakeABI) EngineArch() emu.Arch                 { return emu.ArchARM64 }
func (f fakeABI) PC() emu.Reg                          { return 0 }
func (f fakeABI) SP() emu.Reg                          { return 0 }
func (f fakeABI) LR() emu.Reg                          { return 0 }
func (f fakeABI) Arg(i int) emu.Reg                    { return emu.Reg(i) }
func (f fakeABI) Ret() emu.Reg                         { return 0 }
func (f fakeABI) PtrSize() int                         { return 8 }
func (f fakeABI) ByteOrder() binary.ByteOrder          { return binary.LittleEndian }
func (f fakeABI) SetTLSBase(emu.Backend, uint64) error { return nil }
func (f fakeABI) NormalizeCodeAddr(a uint64) uint64    { return a }

func TestRegisterResolve(t *testing.T) {
	const id = ID(0xF00D) // test-only id, clear of ELF EM_AARCH64 (183)

	Register(id, VariantGeneric, fakeABI{"first"})
	got, err := Resolve(id, VariantGeneric)
	if err != nil {
		t.Fatalf("Resolve after Register: %v", err)
	}
	if got.(fakeABI).tag != "first" {
		t.Fatalf("Resolve returned tag %q, want %q", got.(fakeABI).tag, "first")
	}

	// Duplicate registration overwrites (same style as emu.Register).
	Register(id, VariantGeneric, fakeABI{"second"})
	got, err = Resolve(id, VariantGeneric)
	if err != nil {
		t.Fatalf("Resolve after duplicate Register: %v", err)
	}
	if got.(fakeABI).tag != "second" {
		t.Fatalf("duplicate Register must overwrite, got tag %q", got.(fakeABI).tag)
	}

	// A nil ABI is ignored.
	Register(ID(0xF00E), VariantGeneric, nil)
	if _, err := Resolve(ID(0xF00E), VariantGeneric); err == nil {
		t.Fatal("Register(nil) must not make the key resolvable")
	}
}

func TestResolveUnknown(t *testing.T) {
	if _, err := Resolve(ID(0xBEEF), VariantGeneric); err == nil {
		t.Fatal("unknown ID must error")
	}
	// A registered ID with an unregistered variant is likewise unknown
	// (no silent variant fallback in P1).
	Register(ID(0xF00F), VariantGeneric, fakeABI{"x"})
	if _, err := Resolve(ID(0xF00F), VariantARM64E); err == nil {
		t.Fatal("unknown variant must error")
	}
}
