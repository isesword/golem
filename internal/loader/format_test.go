package loader

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/isesword/golem/internal/arch"
)

// elf64Header builds a minimal 64-byte ELF64 little-endian header with the
// given e_machine. Enough for Sniff — no program/section headers.
func elf64Header(machine uint16) []byte {
	h := make([]byte, 64)
	h[0], h[1], h[2], h[3] = 0x7f, 'E', 'L', 'F'
	h[4] = 2 // ELFCLASS64
	h[5] = 1 // ELFDATA2LSB
	h[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(h[16:], 3)        // ET_DYN
	binary.LittleEndian.PutUint16(h[18:], machine)  // e_machine
	binary.LittleEndian.PutUint32(h[20:], 1)        // e_version
	return h
}

// TestSniffELFAArch64: a valid ELF64/AArch64 header sniffs to
// (FormatELF, arch.IDARM64, VariantGeneric) — from a plain bytes.Reader, no
// backend, no guest memory, no parsing beyond the header.
func TestSniffELFAArch64(t *testing.T) {
	f, id, v, err := Sniff(bytes.NewReader(elf64Header(183))) // EM_AARCH64
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatELF {
		t.Errorf("format = %v, want FormatELF", f)
	}
	if id != arch.IDARM64 {
		t.Errorf("arch.ID = %d, want IDARM64 (%d)", id, arch.IDARM64)
	}
	if v != arch.VariantGeneric {
		t.Errorf("variant = %d, want VariantGeneric", v)
	}
}

// TestSniffRejectsNonELF: a foreign magic is an explicit error, not a
// best-effort guess.
func TestSniffRejectsNonELF(t *testing.T) {
	blob := elf64Header(183)
	blob[0] = 0x7f
	blob[1] = 'M' // not 'E'
	if _, _, _, err := Sniff(bytes.NewReader(blob)); err == nil {
		t.Fatal("expected error for non-ELF magic")
	}
	macho64 := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // MH_MAGIC_64 + arm64 cputype
	if _, _, _, err := Sniff(bytes.NewReader(macho64)); err == nil {
		t.Fatal("expected error for Mach-O (probe lands with loader/macho, P5b)")
	}
}

// TestSniffTruncated: a file shorter than the 20-byte sniff window must
// error, never silently mis-detect.
func TestSniffTruncated(t *testing.T) {
	for _, n := range []int{0, 4, 16, 19} {
		_, _, _, err := Sniff(bytes.NewReader(elf64Header(183)[:n]))
		if err == nil {
			t.Fatalf("truncated at %d bytes: expected error", n)
		}
		if !strings.Contains(err.Error(), "sniff") {
			t.Fatalf("truncated at %d bytes: error should name the probe: %v", n, err)
		}
	}
}

// TestSniffBigEndianMachine: e_machine honors EI_DATA — a big-endian ELF
// header decodes its machine field big-endian.
func TestSniffBigEndianMachine(t *testing.T) {
	h := elf64Header(183)
	h[5] = 2 // ELFDATA2MSB
	h[18], h[19] = 0, 183
	_, id, _, err := Sniff(bytes.NewReader(h))
	if err != nil {
		t.Fatal(err)
	}
	if id != arch.IDARM64 {
		t.Errorf("arch.ID = %d, want IDARM64 (%d)", id, arch.IDARM64)
	}
}
