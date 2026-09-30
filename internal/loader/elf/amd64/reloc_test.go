// P5a relocation-path tests for the (FormatELF, ArchAMD64) Relocator,
// mirroring the ARM64 resolver_e2e tests: RELATIVE lands base+addend,
// GLOB_DAT/JUMP_SLOT/R_X86_64_64 resolve through the SymbolResolver contract
// (a host-interposed symbol writes its STUB guest address), a weak undefined
// symbol lands as 0, and an unhandled type (e.g. TLS) errors loudly.
package amd64_test

import (
	debugelf "debug/elf"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/isesword/golem/internal/arch"
	_ "github.com/isesword/golem/internal/arch/amd64" // register the AMD64 quad (stub encoder for the HostResolver)
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
)

// memBE is an in-memory emu.Backend (sparse pages) for testing the relocator
// without a CPU engine — the same full fake the arm64 linker tests use
// (MemMapPtr aliases let Plan.Apply's image copies land in observable pages).
type memBE struct {
	pages map[uint64][]byte
	ptrs  []ptrRange
}

func newMemBE() *memBE { return &memBE{pages: map[uint64][]byte{}} }

func (m *memBE) page(a uint64) []byte {
	pg := a &^ 0xfff
	for _, pr := range m.ptrs { // aliased host buffers (uc_mem_map_ptr semantics)
		if pg >= pr.addr && pg+0x1000 <= pr.addr+pr.size {
			return pr.buf[pg-pr.addr : pg-pr.addr+0x1000]
		}
	}
	pgm := m.pages[pg]
	if pgm == nil {
		pgm = make([]byte, 0x1000)
		m.pages[pg] = pgm
	}
	return pgm
}
func (m *memBE) MemMap(addr emu.GuestAddr, size uint64, _ int) error {
	for a := uint64(addr) &^ 0xfff; a < uint64(addr)+size; a += 0x1000 {
		m.page(a)
	}
	return nil
}
func (m *memBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	for i, b := range data {
		a := uint64(addr) + uint64(i)
		m.page(a)[a&0xfff] = b
	}
	return nil
}
func (m *memBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		a := uint64(addr) + uint64(i)
		out[i] = m.page(a)[a&0xfff]
	}
	return out, nil
}
func (m *memBE) MemUnmap(emu.GuestAddr, uint64) error        { return nil }
func (m *memBE) MemProtect(emu.GuestAddr, uint64, int) error { return nil }

// ptrRange is one uc_mem_map_ptr-style alias: guest [addr, addr+size) reads
// and writes hit the caller's host buffer directly (zero-copy).
type ptrRange struct {
	addr, size uint64
	buf        []byte
}

// MemMapPtr registers an ALIAS to the caller's host buffer, so Plan.Apply
// memory images are observable through this stub just like real unicorn.
func (m *memBE) MemMapPtr(addr emu.GuestAddr, size uint64, prot int, host unsafe.Pointer) error {
	buf := unsafe.Slice((*byte)(host), size)
	m.ptrs = append(m.ptrs, ptrRange{uint64(addr), size, buf})
	return nil
}

func (m *memBE) RegRead(emu.Reg) (uint64, error) { return 0, nil }
func (m *memBE) RegWrite(emu.Reg, uint64) error  { return nil }
func (m *memBE) Start(emu.GuestAddr, emu.GuestAddr) error {
	return nil
}
func (m *memBE) StartCount(emu.GuestAddr, emu.GuestAddr, uint64) error { return nil }
func (m *memBE) Stop() error                                           { return nil }
func (m *memBE) Close() error                                          { return nil }
func (m *memBE) InstallTrap(emu.TrapKind, emu.TrapHandler) (emu.HookHandle, error) {
	return nil, nil
}

func readU64(t *testing.T, be *memBE, addr uint64) uint64 {
	t.Helper()
	b, err := be.MemRead(emu.GuestAddr(addr), 8)
	if err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(b)
}

// synthImage builds a minimal two-page AMD64 image. relocs/syms installed as given.
func synthImage(syms []loader.Sym, relocs []loader.Reloc) *loader.Image {
	raw := make([]byte, 0x2000)
	img := &loader.Image{
		Path: "synth-amd64.so", Format: loader.FormatELF, Arch: emu.ArchAMD64,
		Segments: []loader.Segment{
			{Vaddr: 0x0, FileSz: 0x1000, MemSz: 0x1000, Off: 0, Flags: debugelf.PF_R | debugelf.PF_X},
			{Vaddr: 0x1000, FileSz: 0x1000, MemSz: 0x1000, Off: 0x1000, Flags: debugelf.PF_R | debugelf.PF_W},
		},
		Syms: syms, Relocs: relocs, Exports: map[string]uint64{}, LoadSpan: 0x2000,
	}
	img.SetRaw(raw)
	return img
}

var synthLayout = memory.Layout{
	ModuleRegion: memory.Region{Addr: 0x12000000, Size: 0x1000000},
	StubBase:     0x60000000, StubSize: 0x10000,
	StackBase: 0xC0000000, StackSize: 0x1000,
	TLSBase: 0xD0000000, TLSSize: 0x1000,
}

const base = uint64(0x12000000)

// TestAMD64RelocRelative pins R_X86_64_RELATIVE: the slot receives B+A.
func TestAMD64RelocRelative(t *testing.T) {
	img := synthImage(
		[]loader.Sym{{}},
		[]loader.Reloc{{Offset: 0x1000, Type: uint32(debugelf.R_X86_64_RELATIVE), Addend: 0x40}},
	)
	be := newMemBE()
	if err := img.Apply(be, base, loader.NewDynamicLinker().GlobalResolver()); err != nil {
		t.Fatal(err)
	}
	if got := readU64(t, be, base+0x1000); got != base+0x40 {
		t.Fatalf("RELATIVE slot = %#x, want %#x (base+addend)", got, base+0x40)
	}
}

// TestAMD64RelocGlobDatJumpSlotAbs64 pins the S+A trio: GLOB_DAT, JUMP_SLOT
// and R_X86_64_64 all write symbolValue+addend resolved through the resolver.
func TestAMD64RelocGlobDatJumpSlotAbs64(t *testing.T) {
	syms := []loader.Sym{{}, {Name: "host_fn", Undef: true, Bind: debugelf.STB_GLOBAL}}
	types := []debugelf.R_X86_64{debugelf.R_X86_64_GLOB_DAT, debugelf.R_X86_64_JMP_SLOT, debugelf.R_X86_64_64}
	relocs := make([]loader.Reloc, 0, len(types))
	for i, ty := range types {
		relocs = append(relocs, loader.Reloc{Offset: 0x1000 + uint64(i)*8, Type: uint32(ty), Sym: 1})
	}
	img := synthImage(syms, relocs)

	_, _, stubEnc, _, err := arch.Resolve(arch.IDAMD64, arch.VariantGeneric)
	if err != nil {
		t.Fatal(err)
	}
	as := memory.NewAddressSpace(synthLayout)
	stubs := interpose.NewStubManager(as, stubEnc, newMemBE())
	tab := interpose.NewInterposeTable()
	tab.BindSymbol("host_fn", func(interpose.CallContext) uint64 { return 0 })
	hr := interpose.NewHostResolver(tab, stubs)

	want, err := hr.Resolve(loader.ResolveRequest{Name: "host_fn", Binding: loader.SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	be := newMemBE()
	if err := img.Apply(be, base, hr); err != nil {
		t.Fatal(err)
	}
	for i := range types {
		if got := readU64(t, be, base+0x1000+uint64(i)*8); got != uint64(want.Addr) {
			t.Fatalf("%s slot = %#x, want the stub guest address %#x", types[i], got, uint64(want.Addr))
		}
	}
}

// TestAMD64RelocWeakUndefinedWritesZero pins ELF weak-undefined semantics.
func TestAMD64RelocWeakUndefinedWritesZero(t *testing.T) {
	_, _, stubEnc, _, err := arch.Resolve(arch.IDAMD64, arch.VariantGeneric)
	if err != nil {
		t.Fatal(err)
	}
	as := memory.NewAddressSpace(synthLayout)
	stubs := interpose.NewStubManager(as, stubEnc, newMemBE())
	chain := loader.ChainResolvers(
		loader.NewDynamicLinker().GlobalResolver(),
		interpose.NewUnresolvedStubResolver(stubs),
	)
	img := synthImage(
		[]loader.Sym{{}, {Name: "weak_opt", Undef: true, Bind: debugelf.STB_WEAK}},
		[]loader.Reloc{{Offset: 0x1000, Type: uint32(debugelf.R_X86_64_GLOB_DAT), Sym: 1}},
	)
	be := newMemBE()
	if err := img.Apply(be, base, chain); err != nil {
		t.Fatalf("weak undefined must not fail the link: %v", err)
	}
	if got := readU64(t, be, base+0x1000); got != 0 {
		t.Fatalf("weak undefined GOT slot = %#x, want 0 (ELF semantics)", got)
	}
}

// TestAMD64RelocUnhandledTypeErrors pins that types outside the supported set
// (e.g. the deliberately unimplemented TLS relocations) fail loudly.
func TestAMD64RelocUnhandledTypeErrors(t *testing.T) {
	img := synthImage(
		[]loader.Sym{{}},
		[]loader.Reloc{{Offset: 0x1000, Type: uint32(debugelf.R_X86_64_TPOFF64)}},
	)
	err := img.Apply(newMemBE(), base, loader.NewDynamicLinker().GlobalResolver())
	if err == nil {
		t.Fatal("R_X86_64_TPOFF64 must error — TLS relocations are deliberately unimplemented")
	}
}
