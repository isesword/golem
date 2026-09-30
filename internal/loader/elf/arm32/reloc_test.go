package arm32

import (
	"strings"
	"testing"

	debugelf "debug/elf"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// memBE is a guest-memory-only emu.Backend test double: the relocator only
// ever reads the REL addend word and writes the relocated u32, so everything
// else panics loudly via the nil embedded interface.
type memBE struct {
	emu.Backend
	m map[uint64]byte
}

func newMemBE() *memBE { return &memBE{m: map[uint64]byte{}} }

func (b *memBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	for i, v := range data {
		b.m[uint64(addr)+uint64(i)] = v
	}
	return nil
}

func (b *memBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		out[i] = b.m[uint64(addr)+uint64(i)]
	}
	return out, nil
}

func (b *memBE) put32(addr uint64, v uint32) {
	_ = b.MemWrite(emu.GuestAddr(addr), []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

func (b *memBE) u32(addr uint64) uint32 {
	d, _ := b.MemRead(emu.GuestAddr(addr), 4)
	return uint32(d[0]) | uint32(d[1])<<8 | uint32(d[2])<<16 | uint32(d[3])<<24
}

// fakeResolver answers every import with a fixed guest address.
type fakeResolver struct{ addr uint64 }

func (r fakeResolver) Resolve(loader.ResolveRequest) (loader.ResolvedSymbol, error) {
	return loader.ResolvedSymbol{Addr: emu.GuestAddr(r.addr)}, nil
}

const base = 0x10000000

// definedImg carries one defined data symbol (index 1) and one undefined
// import (index 2).
func definedImg() *loader.Image {
	return &loader.Image{
		Format: loader.FormatELF,
		Arch:   emu.ArchARM,
		Syms: []loader.Sym{
			{Name: ""},                       // index 0 (null)
			{Name: "g_local", Value: 0x2000}, // defined
			{Name: "g_import", Undef: true},  // index 2
		},
	}
}

// TestRelRelativeReadModifyWrite is the REL-semantics red line: the addend is
// the word ALREADY STORED at the target, and the result is bias + that word.
func TestRelRelativeReadModifyWrite(t *testing.T) {
	be := newMemBE()
	be.put32(base+0x400, 0x1234) // the implicit addend lives in the target word
	rc := relocator{}
	err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x400, Type: uint32(debugelf.R_ARM_RELATIVE)}, base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := be.u32(base+0x400), uint32(base+0x1234); got != want {
		t.Fatalf("RELATIVE wrote %#x, want %#x (B + stored word)", got, want)
	}
}

// TestRelSymTypes pins S + A for the symbol types, both for a defined symbol
// (base + st_value) and an import (resolver's guest address).
func TestRelSymTypes(t *testing.T) {
	types := []struct {
		name string
		code debugelf.R_ARM
	}{
		{"GLOB_DAT", debugelf.R_ARM_GLOB_DAT},
		{"JUMP_SLOT", debugelf.R_ARM_JUMP_SLOT},
		{"ABS32", debugelf.R_ARM_ABS32},
		{"TARGET1", debugelf.R_ARM_TARGET1},
	}
	for _, tc := range types {
		t.Run(tc.name+"/defined", func(t *testing.T) {
			be := newMemBE()
			be.put32(base+0x500, 0x10) // implicit addend
			rc := relocator{}
			if err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x500, Type: uint32(tc.code), Sym: 1}, base, nil); err != nil {
				t.Fatal(err)
			}
			// S = base + 0x2000, A = 0x10.
			if got, want := be.u32(base+0x500), uint32(base+0x2000+0x10); got != want {
				t.Fatalf("%s wrote %#x, want %#x (S + stored word)", tc.name, got, want)
			}
		})
		t.Run(tc.name+"/import", func(t *testing.T) {
			be := newMemBE()
			be.put32(base+0x500, 0) // JUMP_SLOT/GLOB_DAT slots usually store 0
			rc := relocator{}
			if err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x500, Type: uint32(tc.code), Sym: 2}, base, fakeResolver{addr: 0x60001000}); err != nil {
				t.Fatal(err)
			}
			if got, want := be.u32(base+0x500), uint32(0x60001000); got != want {
				t.Fatalf("%s wrote %#x, want %#x (resolver address)", tc.name, got, want)
			}
		})
	}
}

// TestRelUnresolvedImportErrors: an undef symbol with no resolver must error
// (the SymValue contract), not silently write the addend.
func TestRelUnresolvedImportErrors(t *testing.T) {
	be := newMemBE()
	rc := relocator{}
	if err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x500, Type: uint32(debugelf.R_ARM_ABS32), Sym: 2}, base, nil); err == nil {
		t.Fatal("unresolved import must error")
	}
}

// TestRelTLSAndUnknownError pins the loud-error policy: TLS relocation types
// name the deliberate gap; unknown types fail generically.
func TestRelTLSAndUnknownError(t *testing.T) {
	be := newMemBE()
	rc := relocator{}
	for _, code := range []debugelf.R_ARM{
		debugelf.R_ARM_TLS_DTPMOD32, debugelf.R_ARM_TLS_DTPOFF32, debugelf.R_ARM_TLS_TPOFF32,
	} {
		err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x100, Type: uint32(code)}, base, nil)
		if err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Fatalf("TLS reloc %s: err = %v, want a loud unimplemented-TLS error", code, err)
		}
	}
	if err := rc.Apply(be, definedImg(), loader.Reloc{Offset: 0x100, Type: uint32(debugelf.R_ARM_GOT32)}, base, nil); err == nil {
		t.Fatal("unknown reloc type must error")
	}
}

// TestRelRegistryRegistered: init() must have registered (FormatELF, ArchARM).
func TestRelRegistryRegistered(t *testing.T) {
	if _, err := loader.ResolveRelocator(loader.FormatELF, emu.ArchARM); err != nil {
		t.Fatalf("ARM32 relocator not registered: %v", err)
	}
}
