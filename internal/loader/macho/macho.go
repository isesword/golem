// Package macho parses a Mach-O object into a format-agnostic loader.Image
// (P5b): LC_SEGMENT_64 load segments, the LC_SYMTAB symbol table, and the
// classic LC_DYLD_INFO(_ONLY) rebase/bind opcode streams expanded into
// loader.Reloc entries. Pure stdlib (debug/macho) for the container; the
// dyld opcode streams are decoded here byte by byte (debug/macho does not
// expose them).
//
// The package registers itself as the FormatMachO Parser via init(); import
// it (blank) from the composition root. Relocation SEMANTICS (what a rebase
// or bind writes into guest memory) are not here — they live in
// loader/macho/<arch> (e.g. loader/macho/arm64), registered per
// (FormatMachO, emu.Arch) like the ELF relocators.
//
// Deliberately out of scope (loud errors, never silent mis-loads):
// fat/universal binaries (Sniff rejects them), big-endian/32-bit Mach-O,
// ARM64e authenticated CHAINED FIXUPS (LC_DYLD_CHAINED_FIXUPS — the P5c PAC
// world; rebuild fixtures with -Wl,-no_fixup_chains), lazy/weak bind streams
// (dyld's stub-binder runtime is not emulated — fixtures must produce
// non-lazy binds, e.g. through an initialized function-pointer global).
//
// Name decoration: Mach-O C symbols carry a leading underscore ("_add"); the
// parser strips exactly one so the format-agnostic namespace matches ELF's
// ("add") — SymbolResolvers and ReplaceFns keys stay format-neutral.
package macho

import (
	"debug/elf"
	debugmacho "debug/macho"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

func init() { loader.RegisterParser(loader.FormatMachO, Parse) }

// Mach-O relocation type codes carried in loader.Reloc.Type (the "raw
// format-specific code" slot — Mach-O has no ELF-style numbered relocation
// set for dynamic linking, so the dyld opcode semantics get their own codes
// here). Interpreted only by the (FormatMachO, Arch) Relocator.
const (
	// RelocRebasePointer is REBASE_TYPE_POINTER: the image-relative pointer
	// at Offset is relocated to base+value (Addend carries the unrelocated
	// value read from the file image, same convention as ELF SHT_RELR).
	RelocRebasePointer uint32 = 1
	// RelocBindPointer is BIND_TYPE_POINTER: the slot at Offset is bound to
	// the resolved guest address of Syms[Sym] plus Addend.
	RelocBindPointer uint32 = 2
)

// Load-command and opcode constants (dyld's mach-o/loader.h / dyldinfo).
const (
	lcDyldInfo          = 0x22
	lcDyldInfoOnly      = 0x80000022
	lcDyldChainedFixups = 0x34 // LC_DYLD_CHAINED_FIXUPS — unsupported (P5c)
	lcMain              = 0x80000028

	rebaseOpDone             = 0x00
	rebaseOpSetTypeImm       = 0x10
	rebaseOpSetSegOffsetUleb = 0x20
	rebaseOpAddAddrUleb      = 0x30
	rebaseOpAddAddrImmScaled = 0x40
	rebaseOpDoImmTimes       = 0x50
	rebaseOpDoUlebTimes      = 0x60
	rebaseOpDoAddAddrUleb    = 0x70
	rebaseOpDoImmTimesSkip   = 0x80

	bindOpDone                 = 0x00
	bindOpSetDylibOrdinalImm   = 0x10
	bindOpSetDylibOrdinalUleb  = 0x20
	bindOpSetDylibSpecialImm   = 0x30
	bindOpSetSymbolTrailingImm = 0x40
	bindOpSetTypeImm           = 0x50
	bindOpSetAddendSleb        = 0x60
	bindOpSetSegOffsetUleb     = 0x70
	bindOpAddAddrUleb          = 0x80
	bindOpDo                   = 0x90
	bindOpDoAddAddrUleb        = 0xa0
	bindOpDoAddAddrImmScaled   = 0xb0
	bindOpDoUlebTimesSkipUleb  = 0xc0

	rebaseTypePointer = 1
	bindTypePointer   = 1
)

// nlist64 type/desc bits (mach-o/nlist.h).
const (
	nTypeMask = 0x0e
	nUndef    = 0x00
	nSect     = 0x0e
	nExt      = 0x01
	nWeakRef  = 0x40 // n_desc N_WEAK_REF
)

// Parse reads the Mach-O at path and builds the loader.Image. Addresses are
// image-relative: dylib segments are linked at vmaddr 0, so vmaddr IS the
// image-relative address (the load bias is added at map time, as with ELF).
func Parse(path string) (*loader.Image, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := debugmacho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img := &loader.Image{
		Path:    path,
		Format:  loader.FormatMachO,
		Exports: map[string]uint64{},
	}
	switch f.Cpu {
	case debugmacho.CpuArm64:
		img.Arch, img.Machine = emu.ArchARM64, arch.IDARM64
	case debugmacho.CpuAmd64:
		img.Arch, img.Machine = emu.ArchAMD64, arch.IDAMD64
	default:
		return nil, fmt.Errorf("macho: unsupported cpu %v", f.Cpu)
	}
	img.SetRaw(raw)

	// Load commands: segments, dylib dependencies, dyld info, entry point.
	// allSegs tracks EVERY LC_SEGMENT_64 in load order — rebase/bind opcodes
	// address by that ordinal, so segments skipped for mapping (__PAGEZERO)
	// must still count here.
	var allSegs []loader.Segment
	var dyldInfo machoDyldInfo
	var haveDyldInfo bool
	for _, l := range f.Loads {
		switch lc := l.(type) {
		case *debugmacho.Segment:
			seg := loader.Segment{
				Vaddr: lc.Addr, FileSz: lc.Filesz, MemSz: lc.Memsz,
				Off: lc.Offset, Flags: protToELF(lc.Prot),
				Aligned: pageUp(lc.Addr+lc.Memsz) - pageDown(lc.Addr),
			}
			allSegs = append(allSegs, seg)
			if lc.Memsz == 0 || lc.Name == "__PAGEZERO" {
				continue // no payload / the null-page reservation of executables
			}
			img.Segments = append(img.Segments, seg)
		case *debugmacho.Dylib:
			// LC_ID_DYLIB names this image; only load commands are dependencies.
			if c := binary.LittleEndian.Uint32(lc.LoadBytes); c == 0xc || c == 0x1c || c == 0x8000001f { // LOAD / LOAD_WEAK / REEXPORT
				img.Needed = append(img.Needed, lc.Name)
			}
		case debugmacho.LoadBytes:
			cmd := binary.LittleEndian.Uint32(lc)
			switch cmd {
			case lcDyldChainedFixups:
				return nil, fmt.Errorf("macho: %s uses chained fixups (ARM64e/PAC, P5c); rebuild with -Wl,-no_fixup_chains", path)
			case lcDyldInfo, lcDyldInfoOnly:
				dyldInfo, haveDyldInfo = parseDyldInfo(lc), true
			case lcMain:
				img.Entry = binary.LittleEndian.Uint64(lc[8:]) // entryoff (file offset)
			}
		}
	}
	// LC_MAIN's entryoff is a FILE offset; convert to image-relative vaddr.
	if img.Entry != 0 {
		img.Entry = fileOffToVaddr(allSegs, img.Entry)
	}

	var maxEnd uint64
	for _, s := range img.Segments {
		if end := s.Vaddr + s.MemSz; end > maxEnd {
			maxEnd = end
		}
	}
	img.LoadSpan = pageUp(maxEnd)

	// Symbols: index 0 is the null placeholder (reloc Sym indexes align with
	// img.Syms, same convention as the ELF parser). Defined-external symbols
	// are exports; undefined-externals are imports.
	img.Syms = append(img.Syms, loader.Sym{Name: ""})
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			undef := s.Type&nTypeMask == nUndef
			bind := elf.STB_GLOBAL
			if s.Desc&nWeakRef != 0 {
				bind = elf.STB_WEAK
			}
			name := strings.TrimPrefix(s.Name, "_")
			img.Syms = append(img.Syms, loader.Sym{
				Name: name, Value: s.Value, Undef: undef, Bind: bind,
			})
			if undef {
				if name != "" {
					img.Imports = append(img.Imports, name)
				}
			} else if s.Type&nExt != 0 && name != "" {
				img.Exports[name] = s.Value
			}
		}
	}

	// Classic dyld info: rebase + bind opcode streams become explicit
	// loader.Reloc entries. Lazy/weak bind streams need dyld's stub binder —
	// not emulated; fail loudly rather than half-binding the image.
	if haveDyldInfo {
		if dyldInfo.lazyBindSize > 0 || dyldInfo.weakBindSize > 0 {
			return nil, fmt.Errorf("macho: %s carries lazy/weak bind streams (unsupported — use non-lazy binds, e.g. an initialized function pointer)", path)
		}
		rels, err := parseRebase(raw, dyldInfo, allSegs)
		if err != nil {
			return nil, fmt.Errorf("macho: %s rebase: %w", path, err)
		}
		img.Relocs = append(img.Relocs, rels...)
		binds, err := parseBind(raw, dyldInfo, allSegs, img)
		if err != nil {
			return nil, fmt.Errorf("macho: %s bind: %w", path, err)
		}
		img.Relocs = append(img.Relocs, binds...)
	}

	// __mod_init_func is the Mach-O init array (same raw-contents convention
	// as ELF .init_array: read post-relocation from guest memory).
	if sec := f.Section("__mod_init_func"); sec != nil {
		img.InitArrayAddr = sec.Addr
		img.InitArrayLen = int(sec.Size / 8)
	}
	return img, nil
}

// machoDyldInfo mirrors the LC_DYLD_INFO(_ONLY) payload (only the fields P5b
// consumes).
type machoDyldInfo struct {
	rebaseOff, rebaseSize uint32
	bindOff, bindSize     uint32
	lazyBindSize          uint32
	weakBindSize          uint32
}

// parseDyldInfo decodes the LoadBytes of an LC_DYLD_INFO(_ONLY) command:
// cmd/cmdsize then ten uint32 offset/size pairs.
func parseDyldInfo(lc debugmacho.LoadBytes) machoDyldInfo {
	u32 := func(off int) uint32 {
		if off+4 > len(lc) {
			return 0
		}
		return binary.LittleEndian.Uint32(lc[off:])
	}
	return machoDyldInfo{
		rebaseOff: u32(8), rebaseSize: u32(12),
		bindOff: u32(16), bindSize: u32(20),
		weakBindSize: u32(28), lazyBindSize: u32(36),
	}
}

// parseRebase decodes the rebase opcode stream into RelocRebasePointer
// entries. Only REBASE_TYPE_POINTER is supported (arm64 uses nothing else
// under classic fixups). The Addend is the unrelocated pointer value read
// from the file image — the relocator adds base to it.
func parseRebase(raw []byte, di machoDyldInfo, segs []loader.Segment) ([]loader.Reloc, error) {
	stream, err := sliceStream(raw, di.rebaseOff, di.rebaseSize)
	if err != nil || len(stream) == 0 {
		return nil, err
	}
	var (
		out       []loader.Reloc
		typ       uint8
		segIdx    uint32
		segOff    uint64
		skip, cnt uint64
	)
	emit := func() error {
		va, err := segAddr(segs, segIdx, segOff)
		if err != nil {
			return err
		}
		fo := vaddrToFileOff(segs, va)
		if fo < 0 || fo+8 > len(raw) {
			return fmt.Errorf("rebase target %#x outside the file image", va)
		}
		out = append(out, loader.Reloc{
			Offset: va, Type: RelocRebasePointer,
			Addend: int64(binary.LittleEndian.Uint64(raw[fo:])),
		})
		return nil
	}
	for i := 0; i < len(stream); {
		op, imm := stream[i]&0xf0, stream[i]&0x0f
		i++
		switch op {
		case rebaseOpDone:
			// 0x00 with imm>0 is alignment padding; imm==0 terminates.
			if imm == 0 {
				return out, nil
			}
		case rebaseOpSetTypeImm:
			typ = imm
			if typ != rebaseTypePointer {
				return nil, fmt.Errorf("unsupported rebase type %d (only POINTER)", typ)
			}
		case rebaseOpSetSegOffsetUleb:
			segIdx = uint32(imm)
			segOff, i = uleb(stream, i)
		case rebaseOpAddAddrUleb:
			var v uint64
			v, i = uleb(stream, i)
			segOff += v
		case rebaseOpAddAddrImmScaled:
			segOff += uint64(imm) * 8
		case rebaseOpDoImmTimes:
			for j := 0; j < int(imm); j++ {
				if err := emit(); err != nil {
					return nil, err
				}
				segOff += 8
			}
		case rebaseOpDoUlebTimes:
			cnt, i = uleb(stream, i)
			for ; cnt > 0; cnt-- {
				if err := emit(); err != nil {
					return nil, err
				}
				segOff += 8
			}
		case rebaseOpDoAddAddrUleb:
			if err := emit(); err != nil {
				return nil, err
			}
			var v uint64
			v, i = uleb(stream, i)
			segOff += v + 8
		case rebaseOpDoImmTimesSkip:
			cnt = uint64(imm)
			skip, i = uleb(stream, i)
			for ; cnt > 0; cnt-- {
				if err := emit(); err != nil {
					return nil, err
				}
				segOff += skip + 8
			}
		default:
			return nil, fmt.Errorf("unknown rebase opcode %#x", op)
		}
	}
	return out, nil
}

// parseBind decodes the (non-lazy) bind opcode stream into RelocBindPointer
// entries. Symbols arrive by NAME (trailing NUL-terminated string); each is
// mapped to its img.Syms index so the relocator sees the same Sym-indexed
// contract as ELF. Dylib ordinals are ignored: symbol resolution is the
// SymbolResolver chain's job (host interposition is indistinguishable from a
// guest export to the loader by design).
func parseBind(raw []byte, di machoDyldInfo, segs []loader.Segment, img *loader.Image) ([]loader.Reloc, error) {
	stream, err := sliceStream(raw, di.bindOff, di.bindSize)
	if err != nil || len(stream) == 0 {
		return nil, err
	}
	symIdx := map[string]uint32{}
	for i, s := range img.Syms {
		if _, ok := symIdx[s.Name]; !ok {
			symIdx[s.Name] = uint32(i)
		}
	}
	var (
		out    []loader.Reloc
		typ    uint8
		name   string
		addend int64
		segIdx uint32
		segOff uint64
	)
	emit := func() error {
		va, err := segAddr(segs, segIdx, segOff)
		if err != nil {
			return err
		}
		idx, ok := symIdx[name]
		if !ok {
			// A bound symbol missing from the symtab would silently resolve
			// to the null symbol — never guess; fail loudly.
			return fmt.Errorf("bind symbol %q not in the symbol table", name)
		}
		out = append(out, loader.Reloc{
			Offset: va, Type: RelocBindPointer, Sym: idx, Addend: addend,
		})
		return nil
	}
	for i := 0; i < len(stream); {
		op, imm := stream[i]&0xf0, stream[i]&0x0f
		i++
		switch op {
		case bindOpDone:
			if imm == 0 {
				return out, nil
			}
		case bindOpSetDylibOrdinalImm, bindOpSetDylibSpecialImm:
			// Ordinal (incl. special: -2 dynamic_lookup) — resolution is by
			// name through the SymbolResolver; the ordinal is ignored.
		case bindOpSetDylibOrdinalUleb:
			_, i = uleb(stream, i)
		case bindOpSetSymbolTrailingImm:
			end := i
			for end < len(stream) && stream[end] != 0 {
				end++
			}
			name = strings.TrimPrefix(string(stream[i:end]), "_")
			i = end + 1
		case bindOpSetTypeImm:
			typ = imm
			if typ != bindTypePointer {
				return nil, fmt.Errorf("unsupported bind type %d (only POINTER)", typ)
			}
		case bindOpSetAddendSleb:
			addend, i = sleb(stream, i)
		case bindOpSetSegOffsetUleb:
			segIdx = uint32(imm)
			segOff, i = uleb(stream, i)
		case bindOpAddAddrUleb:
			var v uint64
			v, i = uleb(stream, i)
			segOff += v
		case bindOpDo:
			if err := emit(); err != nil {
				return nil, err
			}
			segOff += 8
		case bindOpDoAddAddrUleb:
			if err := emit(); err != nil {
				return nil, err
			}
			var v uint64
			v, i = uleb(stream, i)
			segOff += v + 8
		case bindOpDoAddAddrImmScaled:
			if err := emit(); err != nil {
				return nil, err
			}
			segOff += uint64(imm)*8 + 8
		case bindOpDoUlebTimesSkipUleb:
			cnt, ni := uleb(stream, i)
			skip, ni2 := uleb(stream, ni)
			i = ni2
			for ; cnt > 0; cnt-- {
				if err := emit(); err != nil {
					return nil, err
				}
				segOff += skip + 8
			}
		default:
			return nil, fmt.Errorf("unknown bind opcode %#x", op)
		}
	}
	return out, nil
}

// --- byte-stream helpers -----------------------------------------------------

func sliceStream(raw []byte, off, size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if uint64(off)+uint64(size) > uint64(len(raw)) {
		return nil, fmt.Errorf("opcode stream %#x+%#x out of file bounds (%#x)", off, size, len(raw))
	}
	return raw[off : off+size], nil
}

// segAddr maps a (segment index, segment offset) pair — the addressing of
// rebase/bind opcodes — to an image-relative virtual address.
func segAddr(segs []loader.Segment, idx uint32, off uint64) (uint64, error) {
	if int(idx) >= len(segs) {
		return 0, fmt.Errorf("opcode references segment %d, image has %d", idx, len(segs))
	}
	return segs[idx].Vaddr + off, nil
}

// vaddrToFileOff maps an image-relative vaddr to a file offset, -1 when no
// segment's file range covers it.
func vaddrToFileOff(segs []loader.Segment, va uint64) int {
	for _, s := range segs {
		if va >= s.Vaddr && va+8 <= s.Vaddr+s.FileSz {
			return int(s.Off + (va - s.Vaddr))
		}
	}
	return -1
}

// fileOffToVaddr maps a file offset (e.g. LC_MAIN's entryoff) to an
// image-relative vaddr, 0 when unmapped.
func fileOffToVaddr(segs []loader.Segment, off uint64) uint64 {
	for _, s := range segs {
		if off >= s.Off && off < s.Off+s.FileSz {
			return s.Vaddr + (off - s.Off)
		}
	}
	return 0
}

// protToELF maps Mach-O VM_PROT bits (read=1, write=2, execute=4) onto the
// loader's ELF program-flag vocabulary (PF_X=1, PF_W=2, PF_R=4).
func protToELF(vmprot uint32) elf.ProgFlag {
	var f elf.ProgFlag
	if vmprot&1 != 0 {
		f |= elf.PF_R
	}
	if vmprot&2 != 0 {
		f |= elf.PF_W
	}
	if vmprot&4 != 0 {
		f |= elf.PF_X
	}
	return f
}

// uleb decodes a ULEB128 at stream[i], returning the value and the next index.
func uleb(stream []byte, i int) (uint64, int) {
	var v uint64
	var shift uint
	for i < len(stream) {
		b := stream[i]
		i++
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return v, i
}

// sleb decodes a SLEB128 at stream[i].
func sleb(stream []byte, i int) (int64, int) {
	var v int64
	var shift uint
	var b byte
	for i < len(stream) {
		b = stream[i]
		i++
		v |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}
	if shift < 64 && b&0x40 != 0 {
		v |= -1 << shift
	}
	return v, i
}

func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }
func pageDown(x uint64) uint64 { return x &^ 0xfff }
