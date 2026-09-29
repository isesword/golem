// Relocation-semantics tests for the Mach-O/ARM64 Relocator, driven through
// the full loader facade: parse the committed fixture → Plan → Apply against
// an in-memory backend → the rebased/bound slots are read back from guest
// memory. Symbol resolution goes through a ResolverFunc probe, so the
// SymbolResolver contract (guest address out, nothing else in) is pinned.
package arm64_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"unsafe"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/loader/macho"
	_ "github.com/isesword/golem/internal/loader/macho/arm64" // the relocator under test
)

const fixture = "../../../examples/native/hello_darwin_arm64.dylib"
const testBase = 0x40000000

// memBE is an in-memory emu.Backend (sparse pages + MemMapPtr aliases) for
// link tests without a CPU engine — the same shape as loader/elf/arm64's.
type memBE struct {
	pages map[uint64][]byte
	ptrs  []ptrRange
}

type ptrRange struct {
	addr, size uint64
	buf        []byte
}

func newMemBE() *memBE { return &memBE{pages: map[uint64][]byte{}} }

func (m *memBE) page(a uint64) []byte {
	pg := a &^ 0xfff
	for _, pr := range m.ptrs {
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

func (m *memBE) MemMapPtr(addr emu.GuestAddr, size uint64, _ int, host unsafe.Pointer) error {
	buf := unsafe.Slice((*byte)(host), size)
	m.ptrs = append(m.ptrs, ptrRange{uint64(addr), size, buf})
	return nil
}

// P2.5a: Backend's core interface is frozen — hooks/context/cache are
// capability interfaces the linker never touches, so the fake carries none.
func (m *memBE) RegRead(emu.Reg) (uint64, error) { return 0, nil }
func (m *memBE) RegWrite(emu.Reg, uint64) error  { return nil }
func (m *memBE) ReadGPRegs() ([34]uint64, error) { return [34]uint64{}, nil }
func (m *memBE) Start(emu.GuestAddr, emu.GuestAddr) error {
	return nil
}
func (m *memBE) StartCount(emu.GuestAddr, emu.GuestAddr, uint64) error { return nil }
func (m *memBE) Stop() error                                           { return nil }
func (m *memBE) Close() error                                          { return nil }
func (m *memBE) InstallTrap(emu.TrapKind, emu.TrapHandler) (emu.HookHandle, error) {
	return nil, nil
}

func read64(t *testing.T, be *memBE, addr uint64) uint64 {
	t.Helper()
	b, err := be.MemRead(emu.GuestAddr(addr), 8)
	if err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(b)
}

// TestApplyFixtureBindRebase pins map → rebase → bind against the real
// fixture: the internal function pointer is rebased by the load bias; the
// imported symbol's slot is bound to the address the SymbolResolver answers.
func TestApplyFixtureBindRebase(t *testing.T) {
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	img, err := macho.Parse(fixture)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plan, err := img.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// The resolver probe: host_magic answers with a stub-like guest address;
	// anything else fails the test (the fixture binds nothing else).
	var gotReq loader.ResolveRequest
	res := loader.ResolverFunc(func(req loader.ResolveRequest) (loader.ResolvedSymbol, error) {
		gotReq = req
		if req.Name != "host_magic" {
			return loader.ResolvedSymbol{}, fmt.Errorf("unexpected resolve of %q", req.Name)
		}
		return loader.ResolvedSymbol{Addr: 0x60000000, Kind: loader.SymbolHostStub}, nil
	})

	be := newMemBE()
	if err := plan.Apply(be, testBase, res); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The bind saw the SymbolResolver contract: the importing image as
	// requester, the undecorated name, the global binding.
	if gotReq.Name != "host_magic" || gotReq.Binding != loader.SymbolBindingGlobal || gotReq.Requester != img {
		t.Fatalf("resolve request = %+v, want host_magic/global/this image", gotReq)
	}
	// host_fp (bind): the resolver's guest address, addend 0.
	if got := read64(t, be, testBase+0x4000); got != 0x60000000 {
		t.Fatalf("host_fp slot = %#x, want 0x60000000 (bound host_magic)", got)
	}
	// fptr_table[0] (rebase): file value 0x3c0 (seven) + load bias.
	if got := read64(t, be, testBase+0x4008); got != testBase+0x3c0 {
		t.Fatalf("fptr_table[0] = %#x, want %#x (rebased seven)", got, testBase+0x3c0)
	}
	// The code bytes of add() survived the map (segment content + FinalizeImage
	// re-protection ran).
	if got := read64(t, be, testBase+0x398); got == 0 {
		t.Fatal("__TEXT.__text content missing after Apply")
	}
}

// TestRelocUnknownType: an unknown Mach-O reloc code fails loudly.
func TestRelocUnknownType(t *testing.T) {
	rc, err := loader.ResolveRelocator(loader.FormatMachO, emu.ArchARM64)
	if err != nil {
		t.Fatal(err)
	}
	img := &loader.Image{Syms: []loader.Sym{{Name: ""}}}
	err = rc.Apply(newMemBE(), img, loader.Reloc{Offset: 0x100, Type: 0xEE}, testBase, nil)
	if err == nil {
		t.Fatal("unknown reloc type must error")
	}
}
