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
	h[4] = 2                                       // ELFCLASS64
	h[5] = 1                                       // ELFDATA2LSB
	h[6] = 1                                       // EV_CURRENT
	binary.LittleEndian.PutUint16(h[16:], 3)       // ET_DYN
	binary.LittleEndian.PutUint16(h[18:], machine) // e_machine
	binary.LittleEndian.PutUint32(h[20:], 1)       // e_version
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
}

// macho64Header builds a minimal 32-byte 64-bit little-endian Mach-O header
// with the given cputype/cpusubtype. Enough for Sniff — no load commands.
func macho64Header(cputype, subtype uint32) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], 0xfeedfacf) // MH_MAGIC_64 (LE on disk)
	binary.LittleEndian.PutUint32(h[4:], cputype)
	binary.LittleEndian.PutUint32(h[8:], subtype)
	binary.LittleEndian.PutUint32(h[12:], 6) // MH_DYLIB
	return h
}

// TestSniffMachOARM64: a Mach-O arm64 dylib header sniffs to
// (FormatMachO, arch.IDARM64, VariantGeneric) — the same arch identity the
// ELF probe reports for AArch64, from a different container format (P5b).
func TestSniffMachOARM64(t *testing.T) {
	f, id, v, err := Sniff(bytes.NewReader(macho64Header(0x0100000c, 0))) // CPU_TYPE_ARM64 / ALL
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatMachO || id != arch.IDARM64 || v != arch.VariantGeneric {
		t.Fatalf("sniff = (%v, %d, %d), want (macho, IDARM64, Generic)", f, id, v)
	}
}

// TestSniffMachOARM64E: CPU_SUBTYPE_ARM64E (=2, here with the
// CPU_SUBTYPE_LIB64 capability bit set, as real toolchains emit) maps to
// VariantARM64E. Nothing registers that variant yet — the probe survives and
// arch.Resolve fails loudly downstream (the deliberate unsupported-variant
// surface until P5c's PAC/chained fixups).
func TestSniffMachOARM64E(t *testing.T) {
	f, id, v, err := Sniff(bytes.NewReader(macho64Header(0x0100000c, 0x80000002)))
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatMachO || id != arch.IDARM64 || v != arch.VariantARM64E {
		t.Fatalf("sniff = (%v, %d, %d), want (macho, IDARM64, ARM64E)", f, id, v)
	}
}

// TestSniffMachOX86_64: Mach-O x86_64 maps onto the same IDAMD64 the ELF
// probe reports.
func TestSniffMachOX86_64(t *testing.T) {
	f, id, v, err := Sniff(bytes.NewReader(macho64Header(0x01000007, 3))) // CPU_TYPE_X86_64 / ALL
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatMachO || id != arch.IDAMD64 || v != arch.VariantGeneric {
		t.Fatalf("sniff = (%v, %d, %d), want (macho, IDAMD64, Generic)", f, id, v)
	}
}

// TestSniffMachORejects: unknown cputype, unknown subtype, fat/universal and
// 32-bit/big-endian Mach-O variants all fail loudly — never a best-effort
// guess.
func TestSniffMachORejects(t *testing.T) {
	cases := map[string][]byte{
		"unknown cputype":   macho64Header(0xdead, 0),
		"unknown subtype":   macho64Header(0x0100000c, 9),
		"fat":               {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0},
		"fat64":             {0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0},
		"macho32":           {0xce, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 0, 0, 0, 0, 0},
		"macho64 bigendian": {0xfe, 0xed, 0xfa, 0xcf, 0x01, 0, 0, 0x0c, 0, 0, 0, 0},
	}
	for name, hdr := range cases {
		if _, _, _, err := Sniff(bytes.NewReader(hdr)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
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
