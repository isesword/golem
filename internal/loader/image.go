// Package loader holds the format-agnostic view of a loadable guest module
// (DESIGN.md §3.3): segments to map, relocations to apply, symbols to
// export/import, init functions to run, plus startup metadata (PHDR/ENTRY)
// for platform's StartupABI. Object-format parsing lives in the format
// subpackages (loader/elf, ...) which register a Parser per Format;
// relocation semantics live in loader/<format>/<arch> packages which
// register a Relocator per (Format, emu.Arch). The work is split compile/
// instantiate style: Parse+Image+Plan describe one load completely (the
// compile step, done once per .so), and Plan.Apply/ApplyPrivate execute the
// plan against guest memory (the instantiate step, one per engine —
// read-only pages can be shared across engines via host-backed mappings).
package loader

import (
	"debug/elf"
	"sync"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// Segment is one loadable region copied into guest memory at Vaddr+base.
type Segment struct {
	Vaddr   uint64
	FileSz  uint64
	MemSz   uint64 // MemSz>FileSz => zero-fill (.bss)
	Off     uint64
	Flags   elf.ProgFlag // R/W/X (ELF program-header bits; Mach-O maps onto the same R/W/X vocabulary)
	Aligned uint64       // page-aligned size
}

// Reloc is one dynamic relocation entry, format-agnostic: Type is the raw
// format-and-arch-specific relocation code (ELF: r_info&0xffffffff, i.e.
// elf.R_AARCH64_* / elf.R_X86_64_* values) and is interpreted only by the
// Relocator registered for the image's (Format, Arch).
type Reloc struct {
	Offset uint64 // where to patch (image-relative)
	Type   uint32 // raw format-specific relocation type code
	Sym    uint32 // index into dynamic symbol table (0 = none)
	Addend int64
}

// Sym is a dynamic symbol (imported when Undef, else exported). Bind/Type
// keep the ELF vocabulary; other formats map onto the closest equivalent.
// Visibility uses the format-agnostic SymbolVisibility (P3.5; ELF STV_*).
type Sym struct {
	Name       string
	Value      uint64
	Size       uint64
	Undef      bool
	Bind       elf.SymBind
	Type       elf.SymType
	Visibility SymbolVisibility
}

// Image is the parsed, ready-to-map representation of one module. It is
// immutable once the format parser returns it (all fields are fixed; segment
// contents are sliced from the captured file bytes), and stays reusable:
// per-base/per-resolver derivations live in Plan, not here.
//
// Image carries startup METADATA (Format/Arch/Machine, Entry, PhdrAddr,
// PhdrNum) for platform's StartupABI to consume — the loader only produces
// data; it never builds auxv, the initial stack, or HWCAP (DESIGN.md §3.3,
// invariant: Format does not own Startup ABI).
type Image struct {
	Path    string
	Format  Format
	Arch    emu.Arch // engine architecture a backend must be created with (0 = unknown/unsupported)
	Machine arch.ID  // raw object-format machine identity (ELF e_machine)

	Segments      []Segment
	Relocs        []Reloc
	Syms          []Sym // indexed identically to the format's dynamic symbol table
	Imports       []string
	Exports       map[string]uint64 // name -> image-relative addr
	InitArray     []uint64          // RAW .init_array contents (often all 0 on AArch64 — RELA addends hold the real pointers; read post-relocation from memory instead)
	InitArrayAddr uint64            // image-relative vaddr of .init_array
	InitArrayLen  int               // number of entries
	Init          uint64            // DT_INIT (0 if none)
	Needed        []string
	LoadSpan      uint64 // total virtual span to reserve

	// Startup metadata (ELF program-header table + entry point). The format
	// parser fills these; platform.StartupABI consumes them when building
	// the process initial state (P4).
	Entry    uint64 // image-relative entry address (e_entry)
	PhdrAddr uint64 // image-relative vaddr of the program-header table (0 if not mapped)
	PhdrNum  int    // number of program-header entries

	// raw is the whole object file image captured at Parse time, so segment
	// contents can be sliced (sharing the backing array, no copy) without
	// re-reading the file at plan/apply time. Unexported: the Image is
	// immutable after Parse. Format parsers set it via SetRaw.
	raw []byte

	// plan caches the compiled instantiation plan (write-once, guarded by
	// planMu). Caching is what makes cross-engine page sharing real: every
	// engine instantiating this Image maps the SAME host buffers.
	planMu sync.Mutex
	plan   *Plan
}

// SetRaw captures the whole object file image at parse time. Called exactly
// once by the format parser; the Image is immutable afterwards.
func (img *Image) SetRaw(raw []byte) { img.raw = raw }

// RelocHistogram counts relocations by raw type code — the linker only needs
// to implement the types that actually appear. Interpret the codes through
// the image's (Format, Arch), e.g. elf.R_AARCH64(code) for ELF/AArch64.
func (img *Image) RelocHistogram() map[uint32]int {
	h := map[uint32]int{}
	for _, r := range img.Relocs {
		h[r.Type]++
	}
	return h
}

// SymbolRelocCount reports relocations that require resolving an imported
// symbol (e.g. GLOB_DAT/JUMP_SLOT/ABS64 with a named undef symbol). These
// are the only ones whose count is bounded by the import surface.
func (img *Image) SymbolRelocCount() int {
	n := 0
	for _, r := range img.Relocs {
		if r.Sym != 0 && int(r.Sym) < len(img.Syms) && img.Syms[r.Sym].Undef {
			n++
		}
	}
	return n
}

func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }
func pageDown(x uint64) uint64 { return x &^ 0xfff }
