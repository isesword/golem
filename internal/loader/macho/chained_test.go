package macho

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/isesword/golem/internal/loader"
)

// Chained-fixups tests (P5c). Bit layouts follow the SDK's
// mach-o/fixup-chains.h; the synthetic payloads below are built field by
// field so a layout drift fails loudly here.

// --- entry encoders (test-side mirror of the fixup-chains.h layouts) -------

func chainedRebaseEntry(target43, high8 uint64, next uint16) uint64 {
	return target43&0x7ffffffffff | (high8&0xff)<<43 | uint64(next)<<51
}

func chainedBindEntry(ordinal uint16, addend int64, next uint16) uint64 {
	return uint64(ordinal) | (uint64(addend)&0x7ffff)<<32 | uint64(next)<<51 | 1<<62
}

func chainedAuthRebaseEntry(target32 uint64, diversity uint16, addrDiv, key uint8, next uint16) uint64 {
	return target32&0xffffffff | uint64(diversity)<<32 | uint64(addrDiv&1)<<48 | uint64(key&3)<<49 | uint64(next)<<51 | 1<<63
}

func chainedAuthBindEntry(ordinal uint16, diversity uint16, addrDiv, key uint8, next uint16) uint64 {
	return uint64(ordinal) | uint64(diversity)<<32 | uint64(addrDiv&1)<<48 | uint64(key&3)<<49 | uint64(next)<<51 | 1<<62 | 1<<63
}

// --- synthetic payload builder ----------------------------------------------

// chainedSynth assembles a one-segment file image plus an
// LC_DYLD_CHAINED_FIXUPS payload for parseChainedFixups.
type chainedSynth struct {
	version    uint32
	importsFmt uint32
	symbolsFmt uint32
	ptrFormat  uint16
	pageSize   uint16
	pageStarts []uint16
	entries    map[uint64]uint64 // image-relative vaddr -> chain entry
	imports    []string
	segCount   uint32 // seg_count in starts_in_image
	segOffset  uint64 // starts segment_offset (0 = the segment's vaddr)
}

func (s *chainedSynth) build() (raw []byte, dataoff, datasize uint32, segs []loader.Segment) {
	seg := loader.Segment{Vaddr: 0x4000, Off: 0x4000, FileSz: 0x3000, MemSz: 0x3000}
	ptrFormat := s.ptrFormat
	if ptrFormat == 0 {
		ptrFormat = chainedPtrARM64E
	}
	pageSize := s.pageSize
	if pageSize == 0 {
		pageSize = 0x1000
	}
	segCount := s.segCount
	if segCount == 0 {
		segCount = 1
	}
	segOffset := s.segOffset
	if segOffset == 0 {
		segOffset = seg.Vaddr
	}
	importsFmt := s.importsFmt
	if importsFmt == 0 {
		importsFmt = chainedImport
	}

	var payload []byte
	u16 := func(v uint16) { payload = append(payload, byte(v), byte(v>>8)) }
	u32 := func(v uint32) { payload = append(payload, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	u64 := func(v uint64) {
		for i := 0; i < 8; i++ {
			payload = append(payload, byte(v>>(8*i)))
		}
	}

	// dyld_chained_fixups_header (offsets patched after layout).
	u32(s.version)
	u32(0) // starts_offset
	u32(0) // imports_offset
	u32(0) // symbols_offset
	u32(uint32(len(s.imports)))
	u32(importsFmt)
	u32(s.symbolsFmt)
	// dyld_chained_starts_in_image: seg_count + offsets; segment 0's
	// starts_in_segment immediately follows the offsets array.
	startsOff := uint32(len(payload))
	u32(segCount)
	for i := uint32(0); i < segCount; i++ {
		if i == 0 {
			u32(4 + 4*segCount)
		} else {
			u32(0)
		}
	}
	// dyld_chained_starts_in_segment.
	u32(uint32(22 + 2*len(s.pageStarts))) // size
	u16(pageSize)
	u16(ptrFormat)
	u64(segOffset)
	u32(0) // max_valid_pointer
	u16(uint16(len(s.pageStarts)))
	for _, ps := range s.pageStarts {
		u16(ps)
	}
	// imports table (DYLD_CHAINED_IMPORT: ordinal 0xFE = flat namespace,
	// weak 0, name_offset into the symbols pool) + symbols pool.
	importsOff := uint32(len(payload))
	symbolsOff := importsOff + 4*uint32(len(s.imports))
	pool := []byte{0} // real payloads lead with a NUL
	nameOffsets := make([]uint32, len(s.imports))
	for i, n := range s.imports {
		nameOffsets[i] = uint32(len(pool))
		pool = append(pool, []byte("_"+n)...)
		pool = append(pool, 0)
	}
	for _, no := range nameOffsets {
		u32(0xFE | no<<9)
	}
	payload = append(payload, pool...)
	binary.LittleEndian.PutUint32(payload[4:], startsOff)
	binary.LittleEndian.PutUint32(payload[8:], importsOff)
	binary.LittleEndian.PutUint32(payload[12:], symbolsOff)

	dataoff = uint32(seg.Off + seg.FileSz)
	raw = make([]byte, int(dataoff)+len(payload))
	for va, entry := range s.entries {
		fo := int(seg.Off + (va - seg.Vaddr))
		binary.LittleEndian.PutUint64(raw[fo:], entry)
	}
	copy(raw[dataoff:], payload)
	return raw, dataoff, uint32(len(payload)), []loader.Segment{seg}
}

// synthImg is the symbol namespace the walk tests bind against: index 0 is
// the null placeholder, index 1 the single import.
func synthImg() *loader.Image {
	return &loader.Image{
		Syms: []loader.Sym{
			{Name: ""},
			{Name: "host_magic", Undef: true},
		},
	}
}

// TestChainedWalkRebaseBind pins the core walk: page starts, per-entry
// decode, the 19-bit signed bind addend, and a chain CROSSING a page
// boundary (the next page carries START_NONE — continuation needs no start).
func TestChainedWalkRebaseBind(t *testing.T) {
	raw, off, size, segs := (&chainedSynth{
		pageStarts: []uint16{0x10, chainedPtrStartNone},
		imports:    []string{"host_magic"},
		entries: map[uint64]uint64{
			0x4010: chainedRebaseEntry(0x1234, 0x5, 1), // -> 0x4018
			0x4018: chainedBindEntry(0, -8, 0x201),     // -> 0x4018+0x1008 = 0x5020 (cross-page)
			0x5020: chainedRebaseEntry(0x777, 0, 0),    // end
		},
	}).build()
	rels, err := parseChainedFixups(raw, off, size, segs, synthImg())
	if err != nil {
		t.Fatalf("parseChainedFixups: %v", err)
	}
	if len(rels) != 3 {
		t.Fatalf("relocs = %v, want exactly 3", rels)
	}
	// Walk order is chain order.
	wantRebase1 := loader.Reloc{Offset: 0x4010, Type: RelocRebasePointer, Addend: 0x1234 | 0x5<<43}
	if rels[0] != wantRebase1 {
		t.Errorf("relocs[0] = %+v, want %+v (target43 | high8<<43)", rels[0], wantRebase1)
	}
	wantBind := loader.Reloc{Offset: 0x4018, Type: RelocBindPointer, Sym: 1, Addend: -8}
	if rels[1] != wantBind {
		t.Errorf("relocs[1] = %+v, want %+v (19-bit addend sign-extended)", rels[1], wantBind)
	}
	wantRebase2 := loader.Reloc{Offset: 0x5020, Type: RelocRebasePointer, Addend: 0x777}
	if rels[2] != wantRebase2 {
		t.Errorf("relocs[2] = %+v, want %+v (cross-page continuation)", rels[2], wantRebase2)
	}
}

// TestChainedBindAddendSignExtension pins the 19-bit signed addend edges:
// +0x3FFFF (max) and -0x40000 (min).
func TestChainedBindAddendSignExtension(t *testing.T) {
	raw, off, size, segs := (&chainedSynth{
		pageStarts: []uint16{0},
		imports:    []string{"host_magic"},
		entries: map[uint64]uint64{
			0x4000: chainedBindEntry(0, 0x3ffff, 1),
			0x4008: chainedBindEntry(0, -0x40000, 0),
		},
	}).build()
	rels, err := parseChainedFixups(raw, off, size, segs, synthImg())
	if err != nil {
		t.Fatalf("parseChainedFixups: %v", err)
	}
	if len(rels) != 2 || rels[0].Addend != 0x3ffff || rels[1].Addend != -0x40000 {
		t.Fatalf("addends = (%d, %d), want (262143, -262144)", rels[0].Addend, rels[1].Addend)
	}
}

// TestChainedLoudErrors: every unsupported or malformed shape fails loudly —
// never a silent mis-load.
func TestChainedLoudErrors(t *testing.T) {
	okEntries := map[uint64]uint64{0x4000: chainedRebaseEntry(0x42, 0, 0)}
	cases := []struct {
		name    string
		mutate  func(*chainedSynth)
		wantErr string
	}{
		{"version", func(s *chainedSynth) { s.version = 1 }, "version"},
		{"imports format", func(s *chainedSynth) { s.importsFmt = chainedImportAddend }, "imports format"},
		{"symbols format", func(s *chainedSynth) { s.symbolsFmt = 1 }, "symbols format"},
		{"kernel pointer format", func(s *chainedSynth) { s.ptrFormat = 7 }, "pointer format 7"},
		{"userland-offset pointer format", func(s *chainedSynth) { s.ptrFormat = 9 }, "pointer format 9"},
		{"multi-start page", func(s *chainedSynth) { s.pageStarts = []uint16{chainedPtrStartMulti} }, "multi-start"},
		{"seg_count overflow", func(s *chainedSynth) { s.segCount = 2 }, "covers 2 segments"},
		{"segment_offset mismatch", func(s *chainedSynth) { s.segOffset = 0x5000 }, "segment_offset"},
		{"page size", func(s *chainedSynth) { s.pageSize = 0x2000 }, "page size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &chainedSynth{pageStarts: []uint16{0}, entries: okEntries}
			tc.mutate(s)
			raw, off, size, segs := s.build()
			if _, err := parseChainedFixups(raw, off, size, segs, synthImg()); err == nil {
				t.Fatalf("want a loud error containing %q", tc.wantErr)
			} else if !contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q must contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestChainedMalformedChains: structural corruption in the walk itself.
func TestChainedMalformedChains(t *testing.T) {
	t.Run("walk past segment end", func(t *testing.T) {
		raw, off, size, segs := (&chainedSynth{
			pageStarts: []uint16{0x2ff8},                                       // last 8-byte slot of the segment
			entries:    map[uint64]uint64{0x6ff8: chainedRebaseEntry(1, 0, 1)}, // next walks out
		}).build()
		if _, err := parseChainedFixups(raw, off, size, segs, synthImg()); err == nil {
			t.Fatal("chain walking past the segment end must error")
		}
	})
	t.Run("start past segment end", func(t *testing.T) {
		raw, off, size, segs := (&chainedSynth{
			pageStarts: []uint16{chainedPtrStartNone, chainedPtrStartNone, chainedPtrStartNone, 0x100},
			entries:    map[uint64]uint64{},
		}).build() // page 3 start: 3*0x1000+0x100 = 0x3100 >= MemSz 0x3000
		if _, err := parseChainedFixups(raw, off, size, segs, synthImg()); err == nil {
			t.Fatal("a chain start past the segment end must error")
		}
	})
	t.Run("bind ordinal out of range", func(t *testing.T) {
		raw, off, size, segs := (&chainedSynth{
			pageStarts: []uint16{0},
			imports:    []string{"host_magic"},
			entries:    map[uint64]uint64{0x4000: chainedBindEntry(7, 0, 0)},
		}).build()
		if _, err := parseChainedFixups(raw, off, size, segs, synthImg()); err == nil || !contains(err.Error(), "ordinal") {
			t.Fatalf("err = %v, want an ordinal-range error", err)
		}
	})
	t.Run("bind symbol not in symtab", func(t *testing.T) {
		raw, off, size, segs := (&chainedSynth{
			pageStarts: []uint16{0},
			imports:    []string{"ghost"},
			entries:    map[uint64]uint64{0x4000: chainedBindEntry(0, 0, 0)},
		}).build()
		if _, err := parseChainedFixups(raw, off, size, segs, synthImg()); err == nil || !contains(err.Error(), "not in the symbol table") {
			t.Fatalf("err = %v, want a missing-symbol error", err)
		}
	})
}

// TestChainedAuthEntriesPolicyStrip pins PACPolicyStrip on the real decode
// path: authenticated rebase/bind entries are fully decoded (diversity,
// addrDiv, key all read) and materialize BARE addresses — auth rebase emits
// its 32-bit runtimeOffset as the rebase addend, auth bind resolves through
// the imports table with no addend.
func TestChainedAuthEntriesPolicyStrip(t *testing.T) {
	raw, off, size, segs := (&chainedSynth{
		pageStarts: []uint16{0},
		imports:    []string{"host_magic"},
		entries: map[uint64]uint64{
			0x4000: chainedAuthRebaseEntry(0x39c, 0xBEEF, 0, 2, 1), // key=DA, salty diversity
			0x4008: chainedAuthBindEntry(0, 0x1234, 0, 0, 0),       // key=IA
		},
	}).build()
	rels, err := parseChainedFixups(raw, off, size, segs, synthImg())
	if err != nil {
		t.Fatalf("parseChainedFixups: %v", err)
	}
	if len(rels) != 2 {
		t.Fatalf("relocs = %v, want exactly 2", rels)
	}
	wantRebase := loader.Reloc{Offset: 0x4000, Type: RelocRebasePointer, Addend: 0x39c}
	if rels[0] != wantRebase {
		t.Errorf("auth rebase = %+v, want %+v (bare runtimeOffset — PACPolicyStrip)", rels[0], wantRebase)
	}
	wantBind := loader.Reloc{Offset: 0x4008, Type: RelocBindPointer, Sym: 1, Addend: 0}
	if rels[1] != wantBind {
		t.Errorf("auth bind = %+v, want %+v (bare resolved address, no addend field)", rels[1], wantBind)
	}
}

// TestChainedAuthAddrDivRejected: addrDiv=1 (address-divided diversity) is
// a combination PACPolicyStrip makes no statement about — a loud error on
// BOTH authenticated kinds, never a silent strip.
func TestChainedAuthAddrDivRejected(t *testing.T) {
	for name, entry := range map[string]uint64{
		"auth rebase": chainedAuthRebaseEntry(0x39c, 0, 1, 0, 0),
		"auth bind":   chainedAuthBindEntry(0, 0, 1, 2, 0),
	} {
		t.Run(name, func(t *testing.T) {
			raw, off, size, segs := (&chainedSynth{
				pageStarts: []uint16{0},
				imports:    []string{"host_magic"},
				entries:    map[uint64]uint64{0x4000: entry},
			}).build()
			_, err := parseChainedFixups(raw, off, size, segs, synthImg())
			if err == nil || !contains(err.Error(), "addrDiv=1") || !contains(err.Error(), "PACPolicyStrip") {
				t.Fatalf("err = %v, want a loud addrDiv=1 / PACPolicyStrip error", err)
			}
		})
	}
}

// TestParseChainedMinimal drives the full Parse path with a minimal but
// valid chained-fixups Mach-O: header + LC_SEGMENT_64 + LC_DYLD_CHAINED_
// FIXUPS — the P5c replacement for the old "rejected" pin.
func TestParseChainedMinimal(t *testing.T) {
	// File layout: header+cmds at 0, segment payload at 0x1000 (one rebase
	// entry), fixups payload at 0x2000.
	raw := make([]byte, 0x2100)
	u32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(raw[off:], v) }
	u64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(raw[off:], v) }
	// mach_header_64
	u32(0x00, 0xfeedfacf)
	u32(0x04, 0x0100000c) // CPU_TYPE_ARM64
	u32(0x08, 2)          // CPU_SUBTYPE_ARM64E
	u32(0x0c, 6)          // MH_DYLIB
	u32(0x10, 2)          // ncmds
	u32(0x14, 72+16)      // sizeofcmds
	// LC_SEGMENT_64 (__DATA, one page at 0x1000, rw)
	u32(0x20, 0x19) // LC_SEGMENT_64
	u32(0x24, 72)
	copy(raw[0x28:], "__DATA\x00")
	u64(0x38, 0x1000) // vmaddr
	u64(0x40, 0x1000) // vmsize
	u64(0x48, 0x1000) // fileoff
	u64(0x50, 0x1000) // filesize
	u32(0x58, 3)      // maxprot rw
	u32(0x5c, 3)      // initprot rw
	// LC_DYLD_CHAINED_FIXUPS -> payload at 0x2000 (second command starts at
	// 0x20+72 = 0x68)
	u32(0x68, lcDyldChainedFixups)
	u32(0x6c, 16)
	u32(0x70, 0x2000) // dataoff
	u32(0x74, 0x40)   // datasize
	// Payload: header (starts at 0x1c, no imports) + starts_in_image +
	// starts_in_segment covering page 0, chain start at offset 0.
	p := 0x2000
	u32(p+0x00, 0)                                      // version
	u32(p+0x04, 0x1c)                                   // starts_offset
	u32(p+0x08, 0x40)                                   // imports_offset (empty; past the starts)
	u32(p+0x0c, 0x40)                                   // symbols_offset
	u32(p+0x10, 0)                                      // imports_count
	u32(p+0x14, 1)                                      // imports_format
	u32(p+0x18, 0)                                      // symbols_format
	u32(p+0x1c, 1)                                      // seg_count
	u32(p+0x20, 8)                                      // seg_info_offset[0]
	u32(p+0x24, 24)                                     // starts size
	binary.LittleEndian.PutUint16(raw[p+0x28:], 0x1000) // page_size
	binary.LittleEndian.PutUint16(raw[p+0x2a:], 1)      // pointer_format ARM64E
	u64(p+0x2c, 0x1000)                                 // segment_offset
	u32(p+0x34, 0)                                      // max_valid_pointer
	binary.LittleEndian.PutUint16(raw[p+0x38:], 1)      // page_count
	binary.LittleEndian.PutUint16(raw[p+0x3a:], 0)      // page_start[0]
	// The chain: a single rebase (target 0x42) at vaddr 0x1000, next = 0.
	u64(0x1000, chainedRebaseEntry(0x42, 0, 0))

	f, err := os.CreateTemp(t.TempDir(), "*.dylib")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	f.Close()
	img, err := Parse(f.Name())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(img.Relocs) != 1 {
		t.Fatalf("relocs = %v, want exactly 1", img.Relocs)
	}
	want := loader.Reloc{Offset: 0x1000, Type: RelocRebasePointer, Addend: 0x42}
	if img.Relocs[0] != want {
		t.Fatalf("reloc = %+v, want %+v", img.Relocs[0], want)
	}
}

// TestParseBothFixupSourcesRejected: an image carrying BOTH the classic
// LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS has an ambiguous fixup source —
// a loud error, never a guess.
func TestParseBothFixupSourcesRejected(t *testing.T) {
	var hdr []byte
	w32 := func(v uint32) { hdr = append(hdr, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	w32(0xfeedfacf)
	w32(0x0100000c)
	w32(0)
	w32(6)  // MH_DYLIB
	w32(2)  // ncmds
	w32(64) // sizeofcmds
	w32(0)
	w32(0)
	w32(lcDyldInfoOnly) // LC_DYLD_INFO_ONLY (48 bytes, all streams empty)
	w32(48)
	for i := 0; i < 10; i++ {
		w32(0)
	}
	w32(lcDyldChainedFixups)
	w32(16)
	w32(0)
	w32(4) // non-zero datasize: chained fixups present
	f, err := os.CreateTemp(t.TempDir(), "*.dylib")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Parse(f.Name()); err == nil || !contains(err.Error(), "ambiguous") {
		t.Fatalf("err = %v, want an ambiguous-fixup-source error", err)
	}
}
