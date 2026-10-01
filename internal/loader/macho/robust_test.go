package macho

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// .5d robustness contract (macho twin of the ELF parser's): a segment
// claiming more file bytes than the file HAS is a parse error, never a
// later slice-bounds panic in Plan.

// buildMachOOneSegment returns a minimal arm64 MH_DYLIB: header + one
// LC_SEGMENT_64 (__TEXT) whose file range the caller may corrupt.
func buildMachOOneSegment(t *testing.T, fileoff, filesz uint32) []byte {
	t.Helper()
	const (
		hdrSize   = 32
		lcSegSize = 72
	)
	buf := make([]byte, hdrSize+lcSegSize)
	p32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }
	p64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(buf[off:], v) }

	// Mach header (MH_MAGIC_64, CPU arm64, MH_DYLIB, 1 command).
	p32(0, 0xfeedfacf)
	p32(4, 0x0100000C) // cputype = CPU_TYPE_ARM64
	p32(8, 0)          // cpusubtype
	p32(12, 6)         // filetype = MH_DYLIB
	p32(16, 1)         // ncmds
	p32(20, lcSegSize) // sizeofcmds
	p32(24, 0)         // flags

	// LC_SEGMENT_64 __TEXT, no sections.
	o := hdrSize
	p32(o+0, 0x19) // LC_SEGMENT_64
	p32(o+4, lcSegSize)
	copy(buf[o+8:], "__TEXT")
	p64(o+24, 0)               // vmaddr
	p64(o+32, 0x4000)          // vmsize
	p64(o+40, uint64(fileoff)) // fileoff
	p64(o+48, uint64(filesz))  // filesize
	p32(o+56, 5)               // maxprot R+X
	p32(o+60, 5)               // initprot R+X
	p32(o+64, 0)               // nsects
	p32(o+68, 0)               // flags
	return buf
}

func TestMachoParseRejectsSegmentFileRangePastEOF(t *testing.T) {
	// The file is header+load-command only (96 bytes); the segment claims a
	// 0x4000-byte file range starting at 0x1000.
	buf := buildMachOOneSegment(t, 0x1000, 0x4000)
	p := filepath.Join(t.TempDir(), "corrupt.dylib")
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(p)
	if err == nil {
		t.Fatal("Parse must reject a segment whose file range exceeds the file")
	}
	if !strings.Contains(err.Error(), "exceeds file size") {
		t.Fatalf("err = %v, want the explicit corrupt-image message", err)
	}

	// The well-formed twin parses through the same guard unharmed (file
	// range [0,96) fits the 96-byte file; Parse may fail later on missing
	// TEXT payload metadata — the guard itself must not fire).
	ok := buildMachOOneSegment(t, 0, 96)
	p2 := filepath.Join(t.TempDir(), "ok.dylib")
	if err := os.WriteFile(p2, ok, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(p2); err != nil && strings.Contains(err.Error(), "exceeds file size") {
		t.Fatalf("well-formed segment wrongly rejected by the file-range guard: %v", err)
	}
}
