// End-to-end linker test, moved from internal/loader in: parses a real
// AArch64 ELF via the loader facade (parser registered by loader/elf) and
// applies it through the (FormatELF, ArchARM64) Relocator registered by this
// package. Assertions are unchanged from the legacy test.
package arm64_test

import (
	debugelf "debug/elf"
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
	_ "github.com/isesword/golem/internal/loader/elf" // FormatELF parser registration
)

// memBE is an in-memory emu.Backend (sparse pages) for testing the linker
// without a CPU engine. It exercises MemMap/MemWrite/MemRead/MemProtect.
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
	a0 := uint64(addr) // GuestAddr→raw：fake 的页表算术用 uint64
	for a := a0 &^ 0xfff; a < a0+size; a += 0x1000 {
		m.page(a)
	}
	return nil
}
func (m *memBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	a0 := uint64(addr) // GuestAddr→raw
	for i, b := range data {
		a := a0 + uint64(i)
		m.page(a)[a&0xfff] = b
	}
	return nil
}
func (m *memBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	a0 := uint64(addr) // GuestAddr→raw
	out := make([]byte, size)
	for i := range out {
		a := a0 + uint64(i)
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
	m.ptrs = append(m.ptrs, ptrRange{uint64(addr), size, buf}) // GuestAddr→raw for the alias range
	return nil
}

func (m *memBE) ptrPage(pg uint64) ([]byte, bool) {
	for _, pr := range m.ptrs {
		if pg >= pr.addr && pg+0x1000 <= pr.addr+pr.size {
			return pr.buf[pg-pr.addr : pg-pr.addr+0x1000], true
		}
	}
	return nil, false
}

// (page() consults m.ptrs directly; ptrPage kept for direct range probes in tests.)
//
// Backend's core interface is frozen — hooks/context/cache are
// capability interfaces the linker never touches, so the fake carries none.
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

// A real AArch64 shared object bundled with the repo (AOSP bionic), so the
// linker is exercised against genuine RELATIVE/JUMP_SLOT/GLOB_DAT relocations
// and libc imports — no proprietary target needed.
const targetSO = "../../../../assets/android/sdk23/lib64/libz.so"

func TestLinkerAppliesRealSo(t *testing.T) {
	if _, err := os.Stat(targetSO); err != nil {
		t.Skipf("bundled .so not present: %v", err)
	}
	img, err := loader.Parse(targetSO)
	if err != nil {
		t.Fatal(err)
	}
	be := newMemBE()
	const base = uint64(0x12340000)
	stub := uint64(0xee0000)
	resolve := loader.ResolverFunc(func(req loader.ResolveRequest) (loader.ResolvedSymbol, error) {
		stub += 0x10
		return loader.ResolvedSymbol{Addr: emu.GuestAddr(stub), Kind: loader.SymbolUnresolvedStub}, nil
	})
	if err := img.Apply(be, base, resolve); err != nil {
		t.Fatal(err)
	}

	// (a) segment content landed: ELF magic at base+0.
	hdr, _ := be.MemRead(emu.GuestAddr(base), 4)
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		t.Fatalf("ELF magic not mapped at base: %x", hdr)
	}

	// (b) a RELATIVE reloc resolved to base+addend.
	checked := 0
	for _, r := range img.Relocs {
		if debugelf.R_AARCH64(r.Type) == debugelf.R_AARCH64_RELATIVE {
			got, _ := be.MemRead(emu.GuestAddr(base+r.Offset), 8)
			want := base + uint64(r.Addend)
			if binary.LittleEndian.Uint64(got) != want {
				t.Fatalf("RELATIVE @0x%x = 0x%x, want 0x%x",
					r.Offset, binary.LittleEndian.Uint64(got), want)
			}
			checked++
			if checked >= 100 {
				break
			}
		}
	}
	if checked == 0 {
		t.Fatal("no RELATIVE relocs checked")
	}
	t.Logf("verified ELF magic + %d RELATIVE relocs applied into backend", checked)

	// (c) a JUMP_SLOT import points at a resolver-provided stub (non-zero).
	for _, r := range img.Relocs {
		if debugelf.R_AARCH64(r.Type) == debugelf.R_AARCH64_JUMP_SLOT {
			got, _ := be.MemRead(emu.GuestAddr(base+r.Offset), 8)
			if binary.LittleEndian.Uint64(got) == 0 {
				t.Fatalf("JUMP_SLOT @0x%x not resolved", r.Offset)
			}
			t.Logf("JUMP_SLOT @0x%x -> 0x%x (%s)",
				r.Offset, binary.LittleEndian.Uint64(got), img.Syms[r.Sym].Name)
			break
		}
	}
}
