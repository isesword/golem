package macho

// Chained fixups (LC_DYLD_CHAINED_FIXUPS) — the P5c decoder. ALL bit
// layouts below are taken from the SDK's <mach-o/fixup-chains.h> (the
// authoritative source; never from memory):
//
//	dyld_chained_fixups_header        — payload header (version/offsets)
//	dyld_chained_starts_in_image      — per-segment chain-start directory
//	dyld_chained_starts_in_segment    — page starts for one segment
//	dyld_chained_ptr_arm64e_{rebase,bind}           — DYLD_CHAINED_PTR_ARM64E
//	dyld_chained_import{,_addend,_addend64}         — the imports table
//
// Coverage policy (loud errors, never silent mis-loads):
//   - pointer formats: DYLD_CHAINED_PTR_ARM64E (1, P5c) and
//     DYLD_CHAINED_PTR_64 (2, P5d — the format current toolchains emit for
//     plain arm64 under -fixup_chains). KERNEL/FIRMWARE/32/64_OFFSET/
//     USERLAND24/SHARED_CACHE and every other format is a loud
//     "unsupported pointer format" error naming the value. The two formats
//     differ in chain stride (8- vs 4-byte next units) and entry layout —
//     see the decode functions.
//   - imports: DYLD_CHAINED_IMPORT (1) only (both formats carry it); the
//     ADDEND variants are loud errors. symbols_format must be 0
//     (uncompressed).
//   - page starts: single start per page; DYLD_CHAINED_PTR_START_MULTI
//     (a 32-bit-format facility) is a loud error.
//   - authenticated entries (auth bit set, format 1 only): P5c materializes
//     them under the explicit PACPolicyStrip (see below) — decoded fully,
//     never masked. Format 2 has no auth bit; a rebase with high8 != 0 is
//     a tagged pointer outside the guest address model — a loud error.

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/isesword/golem/internal/loader"
)

// Pointer-format and chain-start constants (fixup-chains.h).
const (
	chainedPtrARM64E = 1 // DYLD_CHAINED_PTR_ARM64E — stride 8, unauth target is vmaddr
	chainedPtr64     = 2 // DYLD_CHAINED_PTR_64 — stride 4, rebase target is vmaddr (plain arm64)

	chainedPtrStartNone  = 0xFFFF // DYLD_CHAINED_PTR_START_NONE
	chainedPtrStartMulti = 0x8000 // DYLD_CHAINED_PTR_START_MULTI
)

// Imports-table formats (fixup-chains.h).
const (
	chainedImport         = 1 // DYLD_CHAINED_IMPORT
	chainedImportAddend   = 2 // DYLD_CHAINED_IMPORT_ADDEND
	chainedImportAddend64 = 3 // DYLD_CHAINED_IMPORT_ADDEND64
)

// chainedHeader mirrors dyld_chained_fixups_header.
type chainedHeader struct {
	startsOff  uint32
	importsOff uint32
	symbolsOff uint32
	importsCnt uint32
	importsFmt uint32
	symbolsFmt uint32
}

// chainedSegStarts mirrors dyld_chained_starts_in_segment (page_start
// length-prefixed by page_count).
type chainedSegStarts struct {
	pageSize      uint16
	pointerFormat uint16
	segmentOffset uint64
	pageStart     []uint16
}

// parseChainedFixups decodes the LC_DYLD_CHAINED_FIXUPS payload at
// [dataoff, dataoff+datasize) of the file image into loader.Reloc entries —
// the same contract the classic rebase/bind opcode expansion produces, so
// the registered (FormatMachO, Arch) Relocator applies chained fixups
// unchanged. segs is the load-command segment list (rebase/bind addressing
// goes through the existing segment abstraction); img supplies the symbol
// namespace (bind ordinals index the imports table, whose names map onto
// img.Syms exactly like the classic bind stream).
func parseChainedFixups(raw []byte, dataoff, datasize uint32, segs []loader.Segment, img *loader.Image) ([]loader.Reloc, error) {
	if uint64(dataoff)+uint64(datasize) > uint64(len(raw)) {
		return nil, fmt.Errorf("payload %#x+%#x out of file bounds (%#x)", dataoff, datasize, len(raw))
	}
	payload := raw[dataoff : dataoff+datasize]
	hdr, err := parseChainedHeader(payload)
	if err != nil {
		return nil, err
	}
	imports, err := parseChainedImports(payload, hdr)
	if err != nil {
		return nil, err
	}
	symIdx := map[string]uint32{}
	for i, s := range img.Syms {
		if _, ok := symIdx[s.Name]; !ok {
			symIdx[s.Name] = uint32(i)
		}
	}

	// dyld_chained_starts_in_image: seg_count + that many u32 offsets into
	// the starts struct (0 = this segment has no chains).
	if hdr.startsOff+8 > uint32(len(payload)) {
		return nil, fmt.Errorf("starts_in_image at %#x out of payload bounds (%#x)", hdr.startsOff, len(payload))
	}
	segCount := binary.LittleEndian.Uint32(payload[hdr.startsOff:])
	if int(segCount) > len(segs) {
		return nil, fmt.Errorf("starts_in_image covers %d segments, image has %d", segCount, len(segs))
	}
	if hdr.startsOff+4+segCount*4 > uint32(len(payload)) {
		return nil, fmt.Errorf("starts_in_image seg_info_offset[%d] out of payload bounds (%#x)", segCount, len(payload))
	}

	var out []loader.Reloc
	for i := uint32(0); i < segCount; i++ {
		off := binary.LittleEndian.Uint32(payload[hdr.startsOff+4+i*4:])
		if off == 0 {
			continue
		}
		if hdr.startsOff+off >= uint32(len(payload)) {
			return nil, fmt.Errorf("segment %d starts at %#x out of payload bounds (%#x)", i, hdr.startsOff+off, len(payload))
		}
		ss, err := parseChainedSegStarts(payload[hdr.startsOff+off:])
		if err != nil {
			return nil, fmt.Errorf("segment %d starts: %w", i, err)
		}
		if ss.pointerFormat != chainedPtrARM64E && ss.pointerFormat != chainedPtr64 {
			return nil, fmt.Errorf("segment %d: unsupported chained pointer format %d (only DYLD_CHAINED_PTR_ARM64E=1 / DYLD_CHAINED_PTR_64=2)", i, ss.pointerFormat)
		}
		// The starts' segment_offset addresses MEMORY (vmaddr space); it
		// must be exactly this segment's image-relative vaddr — chained
		// addressing never leaves the image/segment abstraction.
		if ss.segmentOffset != segs[i].Vaddr {
			return nil, fmt.Errorf("segment %d: chain segment_offset %#x != segment vaddr %#x", i, ss.segmentOffset, segs[i].Vaddr)
		}
		rels, err := walkChainedSegment(raw, payload, segs, i, ss, imports, symIdx)
		if err != nil {
			return nil, fmt.Errorf("segment %d: %w", i, err)
		}
		out = append(out, rels...)
	}
	return out, nil
}

// parseChainedHeader decodes and validates dyld_chained_fixups_header.
func parseChainedHeader(payload []byte) (chainedHeader, error) {
	if len(payload) < 28 {
		return chainedHeader{}, fmt.Errorf("chained fixups header truncated (%d bytes < 28)", len(payload))
	}
	u32 := func(off uint32) uint32 { return binary.LittleEndian.Uint32(payload[off:]) }
	if v := u32(0); v != 0 {
		return chainedHeader{}, fmt.Errorf("unsupported chained fixups version %d (only 0)", v)
	}
	hdr := chainedHeader{
		startsOff: u32(4), importsOff: u32(8), symbolsOff: u32(12),
		importsCnt: u32(16), importsFmt: u32(20), symbolsFmt: u32(24),
	}
	if hdr.importsFmt != chainedImport {
		return chainedHeader{}, fmt.Errorf("unsupported chained imports format %d (only DYLD_CHAINED_IMPORT=1)", hdr.importsFmt)
	}
	if hdr.symbolsFmt != 0 {
		return chainedHeader{}, fmt.Errorf("unsupported chained symbols format %d (only 0 = uncompressed)", hdr.symbolsFmt)
	}
	return hdr, nil
}

// parseChainedImports decodes the imports table (DYLD_CHAINED_IMPORT: one
// u32 per entry — lib_ordinal:8, weak_import:1, name_offset:23) into symbol
// names, leading "_" stripped like every other Mach-O symbol. Lib ordinals
// are ignored: resolution is by name through the SymbolResolver, same as the
// classic bind stream.
func parseChainedImports(payload []byte, hdr chainedHeader) ([]string, error) {
	if hdr.importsCnt == 0 {
		return nil, nil
	}
	if uint64(hdr.importsOff)+uint64(hdr.importsCnt)*4 > uint64(len(payload)) {
		return nil, fmt.Errorf("imports table %#x+%d*4 out of payload bounds (%#x)", hdr.importsOff, hdr.importsCnt, len(payload))
	}
	if hdr.symbolsOff >= uint32(len(payload)) {
		return nil, fmt.Errorf("symbols pool at %#x out of payload bounds (%#x)", hdr.symbolsOff, len(payload))
	}
	imports := make([]string, 0, hdr.importsCnt)
	for i := uint32(0); i < hdr.importsCnt; i++ {
		ent := binary.LittleEndian.Uint32(payload[hdr.importsOff+i*4:])
		nameOff := hdr.symbolsOff + (ent >> 9) // name_offset:23
		if nameOff >= uint32(len(payload)) {
			return nil, fmt.Errorf("import %d name at %#x out of payload bounds (%#x)", i, nameOff, len(payload))
		}
		end := nameOff
		for end < uint32(len(payload)) && payload[end] != 0 {
			end++
		}
		name := strings.TrimPrefix(string(payload[nameOff:end]), "_")
		if name == "" {
			return nil, fmt.Errorf("import %d has an empty name", i)
		}
		imports = append(imports, name)
	}
	return imports, nil
}

// parseChainedSegStarts decodes dyld_chained_starts_in_segment.
func parseChainedSegStarts(b []byte) (chainedSegStarts, error) {
	if len(b) < 22 { // size(4) page_size(2) pointer_format(2) segment_offset(8) max_valid_pointer(4) page_count(2)
		return chainedSegStarts{}, fmt.Errorf("starts_in_segment truncated (%d bytes < 22)", len(b))
	}
	pageCount := binary.LittleEndian.Uint16(b[20:])
	if 22+int(pageCount)*2 > len(b) {
		return chainedSegStarts{}, fmt.Errorf("page_start[%d] out of bounds (%d bytes)", pageCount, len(b))
	}
	ss := chainedSegStarts{
		pageSize:      binary.LittleEndian.Uint16(b[4:]),
		pointerFormat: binary.LittleEndian.Uint16(b[6:]),
		segmentOffset: binary.LittleEndian.Uint64(b[8:]),
	}
	if ss.pageSize != 0x1000 && ss.pageSize != 0x4000 {
		return chainedSegStarts{}, fmt.Errorf("unsupported chain page size %#x (only 0x1000/0x4000)", ss.pageSize)
	}
	for i := 0; i < int(pageCount); i++ {
		ss.pageStart = append(ss.pageStart, binary.LittleEndian.Uint16(b[22+i*2:]))
	}
	return ss, nil
}

// walkChainedSegment walks every page's chain in one segment and decodes
// each entry. Stride and entry layout are per pointer format: format
// DYLD_CHAINED_PTR_ARM64E (1) counts next in 8-byte units, format
// DYLD_CHAINED_PTR_64 (2) in 4-byte units. A chain may cross page
// boundaries (its page is then marked START_NONE); the walk tracks the
// absolute in-segment offset, so crossing needs no special case — only
// termination and bounds guards.
func walkChainedSegment(raw, payload []byte, segs []loader.Segment, segIdx uint32, ss chainedSegStarts, imports []string, symIdx map[string]uint32) ([]loader.Reloc, error) {
	seg := segs[segIdx]
	var out []loader.Reloc
	// Termination guard: a valid chain never revisits a slot, and slots are
	// at most one per 4 bytes of segment memory (the smallest stride).
	maxSteps := int(seg.MemSz/4) + 1
	stride := uint64(8) // format 1: 8-byte next units
	if ss.pointerFormat == chainedPtr64 {
		stride = 4 // format 2: 4-byte next units
	}
	for page, start := range ss.pageStart {
		if start == chainedPtrStartNone {
			continue
		}
		if start&chainedPtrStartMulti != 0 {
			return nil, fmt.Errorf("page %d: unsupported multi-start chains (DYLD_CHAINED_PTR_START_MULTI)", page)
		}
		off := uint64(page)*uint64(ss.pageSize) + uint64(start)
		if off >= seg.MemSz {
			return nil, fmt.Errorf("page %d: chain start %#x past segment end (%#x bytes)", page, off, seg.MemSz)
		}
		for steps := 0; ; steps++ {
			if steps > maxSteps {
				return nil, fmt.Errorf("chain starting at page %d does not terminate (>%d steps — corrupt fixups?)", page, maxSteps)
			}
			slotVA := ss.segmentOffset + off
			fo := vaddrToFileOff(segs, slotVA)
			if fo < 0 || fo+8 > len(raw) {
				return nil, fmt.Errorf("chain slot %#x outside the file image", slotVA)
			}
			r, next, err := decodeChainedEntry(ss.pointerFormat, binary.LittleEndian.Uint64(raw[fo:]), slotVA, imports, symIdx)
			if err != nil {
				return nil, err
			}
			if r != nil {
				out = append(out, *r)
			}
			if next == 0 {
				break
			}
			off += uint64(next) * stride
			if off >= seg.MemSz {
				return nil, fmt.Errorf("chain walks past segment end (offset %#x, segment %#x+%#x)", off, ss.segmentOffset, seg.MemSz)
			}
		}
	}
	return out, nil
}

// decodeChainedEntry dispatches one chain entry to the pointer format's
// decoder. next is returned in the format's stride units (0 = chain end).
func decodeChainedEntry(ptrFormat uint16, v, slotVA uint64, imports []string, symIdx map[string]uint32) (*loader.Reloc, uint16, error) {
	if ptrFormat == chainedPtr64 {
		return decodeChainedEntry64(v, slotVA, imports, symIdx)
	}
	return decodeChainedEntryARM64E(v, slotVA, imports, symIdx)
}

// decodeChainedEntry64 decodes one DYLD_CHAINED_PTR_64 chain entry (P5d;
// fixup-chains.h: next:12 from bit 51 in 4-BYTE units, bind:1 bit 63 — no
// auth bit, plain arm64 carries no signed pointers) into a Reloc.
func decodeChainedEntry64(v, slotVA uint64, imports []string, symIdx map[string]uint32) (*loader.Reloc, uint16, error) {
	next := uint16(v >> 51 & 0xfff)
	if v>>63&1 == 0 {
		// dyld_chained_ptr_64_rebase: target:36 (the unrelocated VMADDR —
		// unlike the arm64e auth rebase's runtimeOffset), high8:8,
		// reserved:7. The relocator adds the load bias, exactly the classic
		// REBASE_TYPE_POINTER contract.
		if r := v >> 44 & 0x7f; r != 0 {
			return nil, 0, fmt.Errorf("rebase at %#x: reserved bits %#x != 0 (corrupt fixup?)", slotVA, r)
		}
		if h := v >> 36 & 0xff; h != 0 {
			// "top 8 bits set to this (after slide added)" — a tagged
			// pointer. The guest address model covers 48-bit canonical
			// addresses only; tagging is the authenticated-pointer world,
			// which plain arm64 never carries. Loud, never a silent mask.
			return nil, 0, fmt.Errorf("rebase at %#x: high8 %#x != 0 (tagged pointer outside the guest address model)", slotVA, h)
		}
		return &loader.Reloc{Offset: slotVA, Type: RelocRebasePointer, Addend: int64(v & 0xfffffffff)}, next, nil
	}
	// dyld_chained_ptr_64_bind: ordinal:24, addend:8 UNSIGNED (0..255 —
	// unlike format 1's signed 19-bit), reserved:19.
	if r := v >> 32 & 0x7ffff; r != 0 {
		return nil, 0, fmt.Errorf("bind at %#x: reserved bits %#x != 0 (corrupt fixup?)", slotVA, r)
	}
	sym, err := chainedBindSym(uint32(v&0xffffff), slotVA, imports, symIdx)
	if err != nil {
		return nil, 0, err
	}
	return &loader.Reloc{Offset: slotVA, Type: RelocBindPointer, Sym: sym, Addend: int64(v >> 24 & 0xff)}, next, nil
}

// decodeChainedEntryARM64E decodes one DYLD_CHAINED_PTR_ARM64E chain entry
// (fixup-chains.h: next:11 from bit 51, bind:1 bit 62, auth:1 bit 63) into
// a Reloc. next is returned in stride units (0 = chain end).
func decodeChainedEntryARM64E(v, slotVA uint64, imports []string, symIdx map[string]uint32) (*loader.Reloc, uint16, error) {
	next := uint16(v >> 51 & 0x7ff)
	bind := v>>62&1 != 0
	auth := v>>63&1 != 0
	switch {
	case !bind && !auth:
		// dyld_chained_ptr_arm64e_rebase: target:43 | high8:8 << 43 — the
		// unrelocated vmaddr; the relocator adds the load bias, exactly the
		// classic REBASE_TYPE_POINTER contract.
		target := v&0x7ffffffffff | (v>>43&0xff)<<43
		return &loader.Reloc{Offset: slotVA, Type: RelocRebasePointer, Addend: int64(target)}, next, nil
	case bind && !auth:
		// dyld_chained_ptr_arm64e_bind: ordinal:16, addend:19 SIGNED
		// (±256K — sign-extended), symbol via the imports table.
		sym, err := chainedBindSym(uint32(v&0xffff), slotVA, imports, symIdx)
		if err != nil {
			return nil, 0, err
		}
		addend := int64(v >> 32 & 0x7ffff)
		if addend&0x40000 != 0 {
			addend |= ^int64(0x7ffff) // 19-bit sign extension
		}
		return &loader.Reloc{Offset: slotVA, Type: RelocBindPointer, Sym: sym, Addend: addend}, next, nil
	case !bind && auth:
		// dyld_chained_ptr_arm64e_auth_rebase: target:32 is a RUNTIME
		// OFFSET (image-relative), diversity:16, addrDiv:1, key:2. Under
		// PACPolicyStrip the slot materializes the bare image-relative
		// target — the relocator adds the load bias, producing the
		// unsigned guest address a real dyld would have signed.
		if err := pacStrip(uint16(v>>32&0xffff), uint8(v>>48&1), uint8(v>>49&3), "rebase", slotVA); err != nil {
			return nil, 0, err
		}
		return &loader.Reloc{Offset: slotVA, Type: RelocRebasePointer, Addend: int64(v & 0xffffffff)}, next, nil
	default: // bind && auth
		// dyld_chained_ptr_arm64e_auth_bind: ordinal:16, diversity:16,
		// addrDiv:1, key:2 — NO addend field. Under PACPolicyStrip the slot
		// binds to the SymbolResolver's bare guest address.
		sym, err := chainedBindSym(uint32(v&0xffff), slotVA, imports, symIdx)
		if err != nil {
			return nil, 0, err
		}
		if err := pacStrip(uint16(v>>32&0xffff), uint8(v>>48&1), uint8(v>>49&3), "bind", slotVA); err != nil {
			return nil, 0, err
		}
		return &loader.Reloc{Offset: slotVA, Type: RelocBindPointer, Sym: sym}, next, nil
	}
}

// --- PACPolicyStrip: the P5c authenticated-pointer policy --------------------
//
// PACPolicyStrip is golem's materialization policy for authenticated chained
// fixups: the value written to guest memory is the UNSIGNED, bare address —
// an auth rebase materializes image-base + runtimeOffset (the relocator
// adds the load bias, as for every rebase), an auth bind materializes the
// SymbolResolver's guest address. This is a deliberate POLICY CHOICE, not
// an omission:
//
//   - golem models no PAC signing keys, and Freeze invariant 9 forbids
//     silently masking signature bits off a pointer via NormalizeCodeAddr —
//     the strip therefore happens HERE, at fixup decode time, where the
//     chain entry's authentication metadata (diversity/addrDiv/key) is
//     still explicit and validated.
//   - PAC INSTRUCTION semantics (braa/autia/...) are NOT emulated; fixture
//     code contains no PAC instructions at all — calls through signed
//     slots use explicit `blr` asm (clang cannot be talked out of blraaz),
//     and -fno-ptrauth-returns drops the ABI-forced pac-ret pair (this
//     unicorn build treats retab as an undefined instruction).
//
// Combinations the policy does NOT cover are loud errors, never silent
// strips: addrDiv=1 (the signature depends on address division — a
// diversity the bare-address materialization makes no statement about) and
// any key outside the architecturally assigned IA/IB/DA/DB set.

// pacStrip validates one authenticated entry's diversity metadata against
// PACPolicyStrip (see the policy block above). diversity and key are fully
// decoded — recorded for the error surface and future policy — addrDiv is
// the hard gate.
func pacStrip(diversity uint16, addrDiv, key uint8, what string, slotVA uint64) error {
	if addrDiv != 0 {
		return fmt.Errorf("authenticated chained %s at %#x uses addrDiv=1 (address-divided diversity) — unsupported by PACPolicyStrip", what, slotVA)
	}
	if key > 3 { // IA/IB/DA/DB fill the 2-bit field today; a future widening must fail loudly
		return fmt.Errorf("authenticated chained %s at %#x uses unknown PAC key %d — unsupported by PACPolicyStrip", what, slotVA, key)
	}
	// diversity is a salt only (addrDiv=0): the bare-address strip makes it
	// irrelevant. It stays decoded — never dropped unread.
	_ = diversity
	return nil
}

// chainedBindSym maps a bind ordinal through the imports table to the
// img.Syms index — a bound symbol missing from the symtab would silently
// resolve to the null symbol, so fail loudly instead (same rule as the
// classic bind stream). The ordinal is uint32 because the format 2 field
// is 24 bits wide (format 1's is 16) — truncating it could wrap an
// out-of-range value back INTO range.
func chainedBindSym(ordinal uint32, slotVA uint64, imports []string, symIdx map[string]uint32) (uint32, error) {
	if int(ordinal) >= len(imports) {
		return 0, fmt.Errorf("bind at %#x: ordinal %d out of imports table (%d entries)", slotVA, ordinal, len(imports))
	}
	name := imports[ordinal]
	idx, ok := symIdx[name]
	if !ok {
		return 0, fmt.Errorf("bind at %#x: symbol %q not in the symbol table", slotVA, name)
	}
	return idx, nil
}
