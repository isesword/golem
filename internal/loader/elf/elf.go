// Package elf parses an ELF shared object (ELFCLASS64 or ELFCLASS32 —)
// into a format-agnostic loader.Image: PT_LOAD segments, dynamic symbols,
// RELA relocations (64-bit targets), REL relocations (32-bit targets such as
// ARM32 — the addend is implicit, the word stored at the target), and Android
// packed relative relocations (SHT_RELR "address+bitmap", expanded to
// explicit relative entries). Pure stdlib (debug/elf), no cgo.
//
// The package registers itself as the FormatELF Parser via init(); import it
// (blank) from the composition root. Relocation SEMANTICS are not here —
// they live in loader/elf/<arch> (e.g. loader/elf/arm64).
package elf

import (
	debugelf "debug/elf"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

func init() { loader.RegisterParser(loader.FormatELF, Parse) }

// machineArch maps ELF e_machine to the engine architecture. An unmapped
// machine leaves Image.Arch zero, and the load fails at relocator resolution
// with an explicit "no relocator registered" error (legacy behavior also
// failed unsupported machines, at apply time).
var machineArch = map[debugelf.Machine]emu.Arch{
	debugelf.EM_AARCH64: emu.ArchARM64,
	debugelf.EM_X86_64:  emu.ArchAMD64,
	debugelf.EM_ARM:     emu.ArchARM, // (ELFCLASS32)
}

// Parse reads the ELF at path and builds the loader.Image. base is not
// applied here; all addresses are image-relative (load bias added at map
// time).
func Parse(path string) (*loader.Image, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := debugelf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img := &loader.Image{
		Path:    path,
		Format:  loader.FormatELF,
		Arch:    machineArch[f.Machine], // 0 when unsupported — see machineArch
		Machine: arch.ID(f.Machine),
		Exports: map[string]uint64{},
	}
	img.SetRaw(raw)
	img.Needed, _ = f.DynString(debugelf.DT_NEEDED)

	var maxEnd uint64
	for _, p := range f.Progs {
		if p.Type != debugelf.PT_LOAD {
			continue
		}
		// a segment claiming more file bytes than the file HAS is a
		// corrupt/truncated image — refuse here with a parse error, never
		// slice out of range later in Plan (the loader rejects malformed
		// binaries, it does not read as much as it can).
		if p.Off > uint64(len(raw)) || p.Filesz > uint64(len(raw))-p.Off {
			return nil, fmt.Errorf("elf %s: PT_LOAD file range [%#x,%#x) exceeds file size %#x (corrupt image)",
				path, p.Off, p.Off+p.Filesz, len(raw))
		}
		seg := loader.Segment{
			Vaddr: p.Vaddr, FileSz: p.Filesz, MemSz: p.Memsz,
			Off: p.Off, Flags: p.Flags, Aligned: pageUp(p.Vaddr+p.Memsz) - pageDown(p.Vaddr),
		}
		img.Segments = append(img.Segments, seg)
		if end := p.Vaddr + p.Memsz; end > maxEnd {
			maxEnd = end
		}
	}
	img.LoadSpan = pageUp(maxEnd)

	// Startup metadata for platform.StartupABI entry point and the
	// in-image address of the program-header table. PT_PHDR is authoritative;
	// otherwise locate the phdr file range inside a PT_LOAD segment.
	img.Entry = f.Entry
	img.PhdrNum = len(f.Progs)
	for _, p := range f.Progs {
		if p.Type == debugelf.PT_PHDR {
			img.PhdrAddr = p.Vaddr
			break
		}
	}
	if img.PhdrAddr == 0 {
		// e_phoff: u64 @0x20 (ELFCLASS64, 64-byte header) / u32 @0x1C
		// (ELFCLASS32, 52-byte header).
		var phoff uint64
		switch {
		case f.Class == debugelf.ELFCLASS64 && len(raw) >= 64:
			phoff = binary.LittleEndian.Uint64(raw[0x20:])
		case f.Class == debugelf.ELFCLASS32 && len(raw) >= 52:
			phoff = uint64(binary.LittleEndian.Uint32(raw[0x1c:]))
		}
		if phoff > 0 {
			for _, sgm := range img.Segments {
				if phoff >= sgm.Off && phoff < sgm.Off+sgm.FileSz {
					img.PhdrAddr = sgm.Vaddr + (phoff - sgm.Off)
					break
				}
			}
		}
	}

	// Dynamic symbols (index-aligned with relocation r_sym).
	dyn, err := f.DynamicSymbols()
	if err == nil {
		// debug/elf drops the null symbol at index 0; r_sym indexes the real
		// table, so prepend a placeholder to realign.
		img.Syms = append(img.Syms, loader.Sym{Name: ""})
		for _, s := range dyn {
			undef := s.Section == debugelf.SHN_UNDEF
			img.Syms = append(img.Syms, loader.Sym{
				Name: s.Name, Value: s.Value, Size: s.Size, Undef: undef,
				Bind: debugelf.ST_BIND(s.Info), Type: debugelf.ST_TYPE(s.Info),
				Visibility: loader.SymbolVisibility(s.Other & 0x3), // ST_VISIBILITY
			})
			if undef {
				if s.Name != "" {
					img.Imports = append(img.Imports, s.Name)
				}
			} else if s.Name != "" {
				img.Exports[s.Name] = s.Value
			}
		}
	}

	// Relocations: parse SHT_RELA/SHT_REL sections manually (we need r_sym +
	// type). The raw type code is stored format-natively; interpretation is
	// the Relocator's job (loader/elf/<arch>).
	//
	// Entry layout is class-dependent:
	//   - ELFCLASS64 RELA: {u64 r_offset, u64 r_info, s64 r_addend} (24 B),
	//     r_sym = r_info>>32, r_type = r_info&0xffffffff.
	//   - ELFCLASS32 REL:  {u32 r_offset, u32 r_info} (8 B),
	//     r_sym = r_info>>8, r_type = r_info&0xff — ARM32 uses REL (DT_REL):
	//     there is NO explicit addend; the addend is the word already stored
	//     at the relocation target, read at apply time by the Relocator
	//     (read-modify-write). Addend stays 0 here.
	//   - ELFCLASS32 RELA: {u32 r_offset, u32 r_info, s32 r_addend} (12 B);
	//     parsed for completeness (ARM does not emit it).
	for _, sec := range f.Sections {
		isRela := sec.Type == debugelf.SHT_RELA
		isRel := sec.Type == debugelf.SHT_REL
		if !isRela && !isRel {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sec.Name, err)
		}
		// a relocation section whose byte length is not a whole
		// number of entries is malformed — reject loudly instead of
		// silently dropping a ragged tail (the loader rejects; it does not
		// read as much as it can). entrySz 0 = class/kind not parsed here
		// (ELFCLASS64 SHT_REL), nothing to validate.
		entrySz := 0
		switch {
		case f.Class == debugelf.ELFCLASS64 && isRela:
			entrySz = 24
		case f.Class == debugelf.ELFCLASS32 && isRel:
			entrySz = 8
		case f.Class == debugelf.ELFCLASS32 && isRela:
			entrySz = 12
		}
		if entrySz != 0 && len(data)%entrySz != 0 {
			return nil, fmt.Errorf("elf %s: relocation section %s: length %d is not a multiple of the %d-byte entry (malformed)",
				path, sec.Name, len(data), entrySz)
		}
		switch {
		case f.Class == debugelf.ELFCLASS64 && isRela:
			for off := 0; off+24 <= len(data); off += 24 {
				rOff := binary.LittleEndian.Uint64(data[off:])
				rInfo := binary.LittleEndian.Uint64(data[off+8:])
				rAdd := int64(binary.LittleEndian.Uint64(data[off+16:]))
				img.Relocs = append(img.Relocs, loader.Reloc{
					Offset: rOff,
					Type:   uint32(rInfo & 0xffffffff),
					Sym:    uint32(rInfo >> 32),
					Addend: rAdd,
				})
			}
		case f.Class == debugelf.ELFCLASS32 && isRel:
			for off := 0; off+8 <= len(data); off += 8 {
				rOff := binary.LittleEndian.Uint32(data[off:])
				rInfo := binary.LittleEndian.Uint32(data[off+4:])
				img.Relocs = append(img.Relocs, loader.Reloc{
					Offset: uint64(rOff),
					Type:   rInfo & 0xff,
					Sym:    rInfo >> 8,
					// Addend 0: the REL addend is implicit (the stored
					// target word); the Relocator reads it from memory.
				})
			}
		case f.Class == debugelf.ELFCLASS32 && isRela:
			for off := 0; off+12 <= len(data); off += 12 {
				rOff := binary.LittleEndian.Uint32(data[off:])
				rInfo := binary.LittleEndian.Uint32(data[off+4:])
				rAdd := int32(binary.LittleEndian.Uint32(data[off+8:]))
				img.Relocs = append(img.Relocs, loader.Reloc{
					Offset: uint64(rOff),
					Type:   rInfo & 0xff,
					Sym:    rInfo >> 8,
					Addend: int64(rAdd),
				})
			}
		}
		// ELFCLASS64 SHT_REL: not parsed (no current 64-bit target uses REL).
	}

	// Android packed relative relocations (SHT_RELR / DT_RELR): decode the
	// address+bitmap stream and expand to explicit relative-reloc entries
	// (the machine's R_*_RELATIVE code). The addend is the value already
	// stored at the target in the file image (RELR carries no addends); map
	// vaddr -> file offset via PT_LOAD segments. Entry width follows the ELF
	// class: Elf64_Addr/Elf32_Addr.
	relrType, relrOK := relrRelocType(f.Machine)
	wordSize := 8
	if f.Class == debugelf.ELFCLASS32 {
		wordSize = 4
	}
	for _, sec := range f.Sections {
		if sec.Type != debugelf.SectionType(0x13) /* SHT_RELR */ || !relrOK {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sec.Name, err)
		}
		va2off := func(va uint64) (int, bool) {
			for _, sgm := range img.Segments {
				if va >= sgm.Vaddr && va < sgm.Vaddr+sgm.FileSz {
					return int(sgm.Off + (va - sgm.Vaddr)), true
				}
			}
			return 0, false
		}
		addRelr := func(va uint64) {
			fo, ok := va2off(va)
			if !ok || fo+wordSize > len(raw) {
				return
			}
			var addend int64
			if wordSize == 8 {
				addend = int64(binary.LittleEndian.Uint64(raw[fo:]))
			} else {
				addend = int64(binary.LittleEndian.Uint32(raw[fo:]))
			}
			img.Relocs = append(img.Relocs, loader.Reloc{
				Offset: va,
				Type:   relrType,
				Addend: addend,
			})
		}
		var where uint64
		for off := 0; off+wordSize <= len(data); off += wordSize {
			var word uint64
			if wordSize == 8 {
				word = binary.LittleEndian.Uint64(data[off:])
			} else {
				word = uint64(binary.LittleEndian.Uint32(data[off:]))
			}
			if word&1 == 0 {
				where = word
				addRelr(where)
				where += uint64(wordSize)
			} else {
				for i := 1; i < wordSize*8; i++ {
					if word&(1<<uint(i)) != 0 {
						addRelr(where)
					}
					where += uint64(wordSize)
				}
			}
		}
	}

	// init_array. Function-pointer width follows the ELF class: 8 bytes on
	// ELFCLASS64, 4 on ELFCLASS32 (ARM32 .init_array holds 32-bit pointers).
	if v, err := f.DynValue(debugelf.DT_INIT); err == nil && len(v) > 0 {
		img.Init = v[0]
	}
	entSize := uint64(8)
	if f.Class == debugelf.ELFCLASS32 {
		entSize = 4
	}
	for _, sec := range f.Sections {
		if sec.Type != debugelf.SHT_INIT_ARRAY {
			continue
		}
		img.InitArrayAddr = sec.Addr
		img.InitArrayLen = int(sec.Size / entSize)
		data, err := sec.Data()
		if err != nil {
			return nil, err
		}
		for off := uint64(0); off+entSize <= uint64(len(data)); off += entSize {
			if entSize == 4 {
				img.InitArray = append(img.InitArray, uint64(binary.LittleEndian.Uint32(data[off:])))
			} else {
				img.InitArray = append(img.InitArray, binary.LittleEndian.Uint64(data[off:]))
			}
		}
	}
	return img, nil
}

// relrRelocType maps an ELF machine to the R_*_RELATIVE relocation type code
// SHT_RELR entries expand to. Machines without RELR support report ok=false
// (their SHT_RELR sections, should any appear, are skipped — the same
// behavior as before RELR support existed).
func relrRelocType(m debugelf.Machine) (uint32, bool) {
	switch m {
	case debugelf.EM_AARCH64:
		return uint32(debugelf.R_AARCH64_RELATIVE), true
	case debugelf.EM_X86_64:
		return uint32(debugelf.R_X86_64_RELATIVE), true
	case debugelf.EM_ARM:
		return uint32(debugelf.R_ARM_RELATIVE), true
	}
	return 0, false
}

func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }
func pageDown(x uint64) uint64 { return x &^ 0xfff }
