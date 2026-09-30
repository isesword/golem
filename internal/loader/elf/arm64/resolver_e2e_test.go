// P3.5 relocation-path tests: the (FormatELF, ArchARM64) Relocator now
// resolves every imported symbol through the loader.SymbolResolver contract,
// so guest symbols and host-interposed symbols are the SAME SHAPE to it — a
// guest address. These tests pin that: the GOT/reloc slot receives exactly
// the resolver's guest address (a StubManager stub for host symbols), a weak
// undefined symbol lands as 0, a missing strong symbol errors through a
// scope-only chain, and 20 references to one host symbol consume one stub.
package arm64_test

import (
	debugelf "debug/elf"
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	_ "github.com/isesword/golem/internal/arch/arm64" // register the ARM64 Arch/CallABI/StubEncoder triple
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
)

// synthLayout mirrors the emulator layout with tiny regions.
var synthLayout = memory.Layout{
	ModuleRegion: memory.Region{Addr: 0x12000000, Size: 0x1000000},
	StubBase:     0x60000000, StubSize: 0x10000,
	StackBase: 0xC0000000, StackSize: 0x1000,
	TLSBase: 0xD0000000, TLSSize: 0x1000,
}

// synthImage builds a minimal two-page image: RX .text at vaddr 0, RW
// .got/.data at vaddr 0x1000. relocs/syms are installed as given.
func synthImage(syms []loader.Sym, relocs []loader.Reloc) *loader.Image {
	raw := make([]byte, 0x2000)
	img := &loader.Image{
		Path: "synth.so", Format: loader.FormatELF, Arch: emu.ArchARM64,
		Segments: []loader.Segment{
			{Vaddr: 0x0, FileSz: 0x1000, MemSz: 0x1000, Off: 0, Flags: debugelf.PF_R | debugelf.PF_X},
			{Vaddr: 0x1000, FileSz: 0x1000, MemSz: 0x1000, Off: 0x1000, Flags: debugelf.PF_R | debugelf.PF_W},
		},
		Syms: syms, Relocs: relocs, Exports: map[string]uint64{}, LoadSpan: 0x2000,
	}
	img.SetRaw(raw)
	return img
}

func globDat(off uint64, sym uint32) loader.Reloc {
	return loader.Reloc{Offset: off, Type: uint32(debugelf.R_AARCH64_GLOB_DAT), Sym: sym}
}

func readU64(t *testing.T, be *memBE, addr uint64) uint64 {
	t.Helper()
	b, err := be.MemRead(emu.GuestAddr(addr), 8)
	if err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(b)
}

func newStubStack(t *testing.T) (*memory.AddressSpace, interpose.StubManager) {
	t.Helper()
	_, _, stubEnc, _, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatal(err)
	}
	as := memory.NewAddressSpace(synthLayout)
	return as, interpose.NewStubManager(as, stubEnc, newMemBE())
}

// Test ⑤+④ at the relocation layer: a host-interposed import's GLOB_DAT slot
// receives the HostResolver's STUB GUEST ADDRESS — the Relocator never sees
// anything but a guest VA (it cannot: ResolvedSymbol has no host callable).
func TestRelocToHostSymbolWritesStubGuestAddr(t *testing.T) {
	img := synthImage(
		[]loader.Sym{{}, {Name: "host_fn", Undef: true, Bind: debugelf.STB_GLOBAL}},
		[]loader.Reloc{globDat(0x1000, 1)},
	)
	as, stubs := newStubStack(t)
	tab := interpose.NewInterposeTable()
	tab.BindSymbol("host_fn", func(interpose.CallContext) uint64 { return 0 })
	hr := interpose.NewHostResolver(tab, stubs)

	want, err := hr.Resolve(loader.ResolveRequest{Name: "host_fn", Binding: loader.SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if want.Kind != loader.SymbolHostStub {
		t.Fatalf("kind = %s, want host-stub", want.Kind)
	}

	be := newMemBE()
	const base = uint64(0x12000000)
	if err := img.Apply(be, base, hr); err != nil { // same resolver instance: its dedup map owns the stub
		t.Fatal(err)
	}
	if got := readU64(t, be, base+0x1000); got != uint64(want.Addr) {
		t.Fatalf("GLOB_DAT slot = %#x, want the stub guest address %#x", got, uint64(want.Addr))
	}
	// The written value is inside the guest stub region — a guest address,
	// not anything host-side.
	if uint64(want.Addr) < synthLayout.StubBase || uint64(want.Addr) >= synthLayout.StubBase+synthLayout.StubSize {
		t.Fatalf("stub %#x outside the guest stub region", uint64(want.Addr))
	}
	_ = as
}

// Test ⑥ at the relocation layer: 20 relocation references to ONE host
// symbol all write the SAME stub address; the stub region grows by one slot.
func TestRelocHostSymbolStubReuse(t *testing.T) {
	relocs := make([]loader.Reloc, 0, 20)
	for i := 0; i < 20; i++ {
		relocs = append(relocs, globDat(0x1000+uint64(i)*8, 1))
	}
	img := synthImage(
		[]loader.Sym{{}, {Name: "hot", Undef: true, Bind: debugelf.STB_GLOBAL}},
		relocs,
	)
	as, stubs := newStubStack(t)
	tab := interpose.NewInterposeTable()
	tab.BindSymbol("hot", func(interpose.CallContext) uint64 { return 0 })

	be := newMemBE()
	const base = uint64(0x12000000)
	if err := img.Apply(be, base, interpose.NewHostResolver(tab, stubs)); err != nil {
		t.Fatal(err)
	}
	first := readU64(t, be, base+0x1000)
	for i := 1; i < 20; i++ {
		if got := readU64(t, be, base+0x1000+uint64(i)*8); got != first {
			t.Fatalf("slot %d = %#x, want the shared stub %#x", i, got, first)
		}
	}
	if used := as.Used(memory.PurposeStub); used != 8 {
		t.Fatalf("20 references to one host symbol consumed %d stub bytes, want 8", used)
	}
}

// Test ③ at the relocation layer: an unresolved WEAK undefined import lands
// as 0 in the GOT slot, with no error and no stub consumed; the same slot
// with a STRONG binding errors through a scope-only chain (no fallback).
func TestRelocWeakUndefinedWritesZero(t *testing.T) {
	_, stubs := newStubStack(t)
	fallback := interpose.NewUnresolvedStubResolver(stubs)
	chain := loader.ChainResolvers(loader.NewDynamicLinker().GlobalResolver(), fallback)

	img := synthImage(
		[]loader.Sym{{}, {Name: "weak_opt", Undef: true, Bind: debugelf.STB_WEAK}},
		[]loader.Reloc{globDat(0x1000, 1)},
	)
	be := newMemBE()
	const base = uint64(0x12000000)
	if err := img.Apply(be, base, chain); err != nil {
		t.Fatalf("weak undefined must not fail the link: %v", err)
	}
	if got := readU64(t, be, base+0x1000); got != 0 {
		t.Fatalf("weak undefined GOT slot = %#x, want 0 (ELF semantics)", got)
	}

	// Strong + scope-only chain (no fallback): hard error.
	strong := synthImage(
		[]loader.Sym{{}, {Name: "missing", Undef: true, Bind: debugelf.STB_GLOBAL}},
		[]loader.Reloc{globDat(0x1000, 1)},
	)
	err := strong.Apply(newMemBE(), base, loader.NewDynamicLinker().GlobalResolver())
	if err == nil {
		t.Fatal("missing strong symbol through a scope-only chain must fail")
	}
}
