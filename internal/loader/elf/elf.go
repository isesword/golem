// Package elf parses an ELF shared object into a format-agnostic
// loader.Image: PT_LOAD segments, dynamic symbols, RELA relocations, and
// Android packed relative relocations (SHT_RELR "address+bitmap", expanded
// to explicit relative entries). Pure stdlib (debug/elf), no cgo.
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

// machineArch maps ELF e_machine to the engine architecture. Only AArch64 is
// supported today; an unmapped machine leaves Image.Arch zero, and the load
// fails at relocator resolution with an explicit "no relocator registered"
// error (pre-P3 behavior also failed unsupported machines, at apply time).
var machineArch = map[debugelf.Machine]emu.Arch{
	debugelf.EM_AARCH64: emu.ArchARM64,
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

	// Startup metadata for platform.StartupABI (P4): entry point and the
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
	if img.PhdrAddr == 0 && f.Class == debugelf.ELFCLASS64 && len(raw) >= 64 {
		phoff := binary.LittleEndian.Uint64(raw[0x20:])
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

	// Relocations: parse SHT_RELA sections manually (we need r_sym + type).
	// The raw type code is stored format-natively; interpretation is the
	// Relocator's job (loader/elf/<arch>).
	for _, sec := range f.Sections {
		if sec.Type != debugelf.SHT_RELA {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", sec.Name, err)
		}
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
	}

	// Android packed relative relocations (SHT_RELR / DT_RELR): decode the
	// address+bitmap stream and expand to explicit relative-reloc entries
	// (R_AARCH64_RELATIVE code on AArch64). The addend is the value already
	// stored at the target in the file image (RELR carries no addends); map
	// vaddr -> file offset via PT_LOAD segments.
	for _, sec := range f.Sections {
		if sec.Type != debugelf.SectionType(0x13) /* SHT_RELR */ {
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
			if !ok || fo+8 > len(raw) {
				return
			}
			img.Relocs = append(img.Relocs, loader.Reloc{
				Offset: va,
				Type:   uint32(debugelf.R_AARCH64_RELATIVE),
				Addend: int64(binary.LittleEndian.Uint64(raw[fo:])),
			})
		}
		var where uint64
		for off := 0; off+8 <= len(data); off += 8 {
			word := binary.LittleEndian.Uint64(data[off:])
			if word&1 == 0 {
				where = word
				addRelr(where)
				where += 8
			} else {
				for i := 1; i < 64; i++ {
					if word&(1<<uint(i)) != 0 {
						addRelr(where)
					}
					where += 8
				}
			}
		}
	}

	// init_array
	if v, err := f.DynValue(debugelf.DT_INIT); err == nil && len(v) > 0 {
		img.Init = v[0]
	}
	for _, sec := range f.Sections {
		if sec.Type == debugelf.SHT_INIT_ARRAY {
			img.InitArrayAddr = sec.Addr
			img.InitArrayLen = int(sec.Size / 8)
			data, err := sec.Data()
			if err != nil {
				return nil, err
			}
			for off := 0; off+8 <= len(data); off += 8 {
				img.InitArray = append(img.InitArray, binary.LittleEndian.Uint64(data[off:]))
			}
		}
	}
	return img, nil
}

func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }
func pageDown(x uint64) uint64 { return x &^ 0xfff }
