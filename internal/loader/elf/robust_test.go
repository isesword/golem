package elf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// .5d robustness contract: the loader REJECTS malformed binaries with a
// parse error — it never slices out of range later (Plan) and never
// silently drops a ragged relocation tail.

func writeCorruptELF32(t *testing.T, mutate func(buf []byte)) string {
	t.Helper()
	buf := buildELF32(t)
	mutate(buf)
	p := filepath.Join(t.TempDir(), "corrupt32.so")
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestParseRejectsSegmentFileRangePastEOF: a PT_LOAD claiming more file
// bytes than the file HAS must fail AT PARSE TIME — the legacy behavior
// was a slice-bounds panic in Image.Plan().
func TestParseRejectsSegmentFileRangePastEOF(t *testing.T) {
	// phdr[0].p_filesz @ 52+16: claim 0x10000 file bytes in a ~0x2b0 file.
	p := writeCorruptELF32(t, func(buf []byte) {
		binary.LittleEndian.PutUint32(buf[52+16:], 0x10000)
	})
	_, err := Parse(p)
	if err == nil {
		t.Fatal("Parse must reject a segment whose file range exceeds the file")
	}
	if !strings.Contains(err.Error(), "exceeds file size") {
		t.Fatalf("err = %v, want the explicit corrupt-image message", err)
	}
}

// TestParseRejectsRaggedRelocationSection: a .rel.dyn whose byte length is
// not a whole number of 8-byte REL entries must be a parse error — never a
// silently truncated relocation list.
func TestParseRejectsRaggedRelocationSection(t *testing.T) {
	// shdr[3] = .rel.dyn; sh_size @ shoff+3*40+20: 2 entries + a 3-byte rag.
	const shoff = 0x1c0
	p := writeCorruptELF32(t, func(buf []byte) {
		binary.LittleEndian.PutUint32(buf[shoff+3*40+20:], 2*8+3)
	})
	_, err := Parse(p)
	if err == nil {
		t.Fatal("Parse must reject a relocation section with a ragged tail")
	}
	if !strings.Contains(err.Error(), "not a multiple") {
		t.Fatalf("err = %v, want the ragged-entry-size message", err)
	}
}
