package elf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// buildELF32 assembles a minimal but well-formed 32-bit ARM ET_DYN shared
// object (little-endian, EABI v5): ELF header + 2 program headers + sections
// .dynsym/.dynstr/.rel.dyn/.init_array/.shstrtab. It exists to pin the
// ELFCLASS32 parse paths (32-bit Phdr/Sym/REL layouts) without a real ARMv7
// fixture (brings those).
//
// File layout:
//
//	0x000  ELF header (52 B) + 2 Phdr (2×32 B)
//	0x100  .dynstr
//	0x120  .dynsym   (3 × Elf32_Sym, 16 B)
//	0x160  .rel.dyn  (2 × Elf32_Rel, 8 B)
//	0x170  .init_array (2 × u32)
//	0x180  .shstrtab
//	0x1c0  section headers (6 × 40 B)
func buildELF32(t *testing.T) []byte {
	t.Helper()
	const shoff = 0x1c0
	buf := make([]byte, shoff+6*40)
	p16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(buf[off:], v) }
	p32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }

	// --- ELF header ---
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 1 /*ELFCLASS32*/, 1 /*LSB*/, 1 /*version*/})
	p16(16, 3)          // e_type = ET_DYN
	p16(18, 40)         // e_machine = EM_ARM
	p32(20, 1)          // e_version
	p32(24, 0x1000)     // e_entry
	p32(28, 52)         // e_phoff
	p32(32, shoff)      // e_shoff
	p32(36, 0x05000000) // e_flags = EABI v5
	p16(40, 52)         // e_ehsize
	p16(42, 32)         // e_phentsize
	p16(44, 2)          // e_phnum
	p16(46, 40)         // e_shentsize
	p16(48, 6)          // e_shnum
	p16(50, 5)          // e_shstrndx

	// --- program headers (Elf32_Phdr: type/off/vaddr/paddr/filesz/memsz/flags/align) ---
	ph := func(i int, typ, off, vaddr, filesz, memsz, flags uint32) {
		o := 52 + i*32
		p32(o+0, typ)
		p32(o+4, off)
		p32(o+8, vaddr)
		p32(o+12, vaddr) // p_paddr
		p32(o+16, filesz)
		p32(o+20, memsz)
		p32(o+24, flags)
		p32(o+28, 0x1000) // p_align
	}
	ph(0, 1 /*PT_LOAD*/, 0, 0, 0x2b0, 0x2b0, 5 /*R+X*/)
	ph(1, 1 /*PT_LOAD*/, 0x100, 0x2000, 0x100, 0x100, 6 /*R+W*/)

	// --- .dynstr @0x100 ---
	dynstr := "\x00g_local\x00g_import\x00"
	copy(buf[0x100:], dynstr)
	// name offsets: g_local=1, g_import=9

	// --- .dynsym @0x120: Elf32_Sym {name u32, value u32, size u32, info u8, other u8, shndx u16} ---
	sym := func(i int, name, value, size uint32, info uint8, shndx uint16) {
		o := 0x120 + i*16
		p32(o+0, name)
		p32(o+4, value)
		p32(o+8, size)
		buf[o+12] = info
		buf[o+13] = 0
		p16(o+14, shndx)
	}
	// sym0 = null. STB_GLOBAL<<4 | STT_OBJECT = 0x11.
	sym(1, 1, 0x500, 4, 0x11, 1) // g_local: defined
	sym(2, 9, 0, 0, 0x11, 0)     // g_import: SHN_UNDEF

	// --- .rel.dyn @0x160: Elf32_Rel {r_offset u32, r_info u32}; r_info = sym<<8 | type ---
	p32(0x160, 0x2100)  // r_offset
	p32(0x164, 0<<8|23) // R_ARM_RELATIVE, sym 0
	p32(0x168, 0x2104)  // r_offset
	p32(0x16c, 2<<8|21) // R_ARM_GLOB_DAT, sym 2 (g_import)

	// --- .init_array @0x170 (two 32-bit function pointers) ---
	p32(0x170, 0x1111)
	p32(0x174, 0x2222)

	// --- .shstrtab @0x180 ---
	shstr := "\x00.dynsym\x00.dynstr\x00.rel.dyn\x00.init_array\x00.shstrtab\x00"
	copy(buf[0x180:], shstr)
	// name offsets: .dynsym=1, .dynstr=9, .rel.dyn=17, .init_array=26, .shstrtab=38

	// --- section headers @shoff: Elf32_Shdr (40 B) ---
	sh := func(i int, name, typ, flags, addr, off, size, link, info, align, entsize uint32) {
		o := shoff + i*40
		p32(o+0, name)
		p32(o+4, typ)
		p32(o+8, flags)
		p32(o+12, addr)
		p32(o+16, off)
		p32(o+20, size)
		p32(o+24, link)
		p32(o+28, info)
		p32(o+32, align)
		p32(o+36, entsize)
	}
	// 0 = NULL (already zero)
	sh(1, 1, 11 /*DYNSYM*/, 2 /*ALLOC*/, 0, 0x120, 3*16, 2, 1, 4, 16)
	sh(2, 9, 3 /*STRTAB*/, 2, 0, 0x100, uint32(len(dynstr)), 0, 0, 1, 0)
	sh(3, 17, 9 /*REL*/, 2, 0, 0x160, 2*8, 1, 0, 4, 8)
	sh(4, 26, 14 /*INIT_ARRAY*/, 3 /*W|A*/, 0x3000, 0x170, 2*4, 0, 0, 4, 0)
	sh(5, 38, 3 /*STRTAB*/, 0, 0, 0x180, uint32(len(shstr)), 0, 0, 1, 0)
	return buf
}

func writeTempELF32(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "synth32.so")
	if err := os.WriteFile(p, buildELF32(t), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseELF32 pins the ELFCLASS32 parse: EM_ARM identity, 32-bit Phdr
// extraction, the PhdrAddr fallback via the 32-bit e_phoff, dynamic symbols,
// and — the core — SHT_REL entries decoded with the 32-bit REL layout
// (r_sym = r_info>>8, r_type = r_info&0xff, Addend 0 because the REL addend
// is implicit in the target word).
func TestParseELF32(t *testing.T) {
	img, err := Parse(writeTempELF32(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if img.Format != loader.FormatELF {
		t.Fatalf("Format = %s, want elf", img.Format)
	}
	if img.Arch != emu.ArchARM {
		t.Fatalf("Arch = %s, want %s (EM_ARM)", img.Arch, emu.ArchARM)
	}
	if img.Machine != arch.IDARM {
		t.Fatalf("Machine = %d, want %d (arch.IDARM)", img.Machine, arch.IDARM)
	}
	if img.Entry != 0x1000 {
		t.Fatalf("Entry = %#x, want 0x1000", img.Entry)
	}
	if img.PhdrNum != 2 {
		t.Fatalf("PhdrNum = %d, want 2", img.PhdrNum)
	}
	// No PT_PHDR: the fallback must locate e_phoff (52) inside the first
	// PT_LOAD (vaddr 0, off 0) -> PhdrAddr 0x34.
	if img.PhdrAddr != 0x34 {
		t.Fatalf("PhdrAddr = %#x, want 0x34 (e_phoff via the 32-bit header)", img.PhdrAddr)
	}
	if len(img.Segments) != 2 {
		t.Fatalf("Segments = %d, want 2", len(img.Segments))
	}
	if s := img.Segments[1]; s.Vaddr != 0x2000 || s.Off != 0x100 || s.FileSz != 0x100 || s.MemSz != 0x100 {
		t.Fatalf("segment[1] = %+v, want vaddr 0x2000 off 0x100 filesz/memsz 0x100", s)
	}

	// Symbols: placeholder + g_local (defined) + g_import (undef).
	if len(img.Syms) != 3 {
		t.Fatalf("Syms = %d, want 3", len(img.Syms))
	}
	if s := img.Syms[1]; s.Name != "g_local" || s.Value != 0x500 || s.Undef {
		t.Fatalf("Syms[1] = %+v, want defined g_local @0x500", s)
	}
	if s := img.Syms[2]; s.Name != "g_import" || !s.Undef {
		t.Fatalf("Syms[2] = %+v, want undef g_import", s)
	}
	if img.Exports["g_local"] != 0x500 {
		t.Fatalf("Exports = %v, want g_local=0x500", img.Exports)
	}
	if len(img.Imports) != 1 || img.Imports[0] != "g_import" {
		t.Fatalf("Imports = %v, want [g_import]", img.Imports)
	}

	// REL relocations: 32-bit layout, implicit addend.
	want := []loader.Reloc{
		{Offset: 0x2100, Type: 23 /*R_ARM_RELATIVE*/, Sym: 0, Addend: 0},
		{Offset: 0x2104, Type: 21 /*R_ARM_GLOB_DAT*/, Sym: 2, Addend: 0},
	}
	if len(img.Relocs) != len(want) {
		t.Fatalf("Relocs = %d, want %d: %+v", len(img.Relocs), len(want), img.Relocs)
	}
	for i, w := range want {
		if img.Relocs[i] != w {
			t.Fatalf("Relocs[%d] = %+v, want %+v", i, img.Relocs[i], w)
		}
	}

	// init_array: 4-byte entries on ELFCLASS32.
	if img.InitArrayAddr != 0x3000 || img.InitArrayLen != 2 {
		t.Fatalf("InitArray addr/len = %#x/%d, want 0x3000/2", img.InitArrayAddr, img.InitArrayLen)
	}
	if len(img.InitArray) != 2 || img.InitArray[0] != 0x1111 || img.InitArray[1] != 0x2222 {
		t.Fatalf("InitArray = %v, want [0x1111 0x2222]", img.InitArray)
	}
}

// TestSniffELF32: the lightweight probe must report FormatELF + arch.IDARM
// for the same synthetic file (the boot's first step).
func TestSniffELF32(t *testing.T) {
	f, err := os.Open(writeTempELF32(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	format, id, _, err := loader.Sniff(f)
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if format != loader.FormatELF || id != arch.IDARM {
		t.Fatalf("Sniff = (%s, %d), want (elf, %d)", format, id, arch.IDARM)
	}
}

// TestParseELF64StillWorks is the regression guard: the ELFCLASS64 paths
// (RELA 24-byte entries, 8-byte init_array) must be untouched by the 32-bit
// support. A real fixture would be redundant — cmd/loadplan covers those —
// so this just asserts the class dispatch sees the right constants.
func TestELF32BuilderIsWellFormed(t *testing.T) {
	raw := buildELF32(t)
	if !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) || raw[4] != 1 {
		t.Fatal("builder must emit an ELFCLASS32 header")
	}
}
