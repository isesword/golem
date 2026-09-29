package loader

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/isesword/golem/internal/arch"
)

// Format identifies an executable object format (P3 of the arch/platform
// abstraction, DESIGN.md §3.3). The Format owns object-file concerns only —
// it does NOT carry the Startup ABI: Image exposes startup metadata
// (PHDR/ENTRY), building auxv/initial stack/HWCAP is platform's job (P4).
type Format uint8

const (
	FormatELF Format = iota + 1
	FormatMachO
)

// String names the format for logs and error messages.
func (f Format) String() string {
	switch f {
	case FormatELF:
		return "elf"
	case FormatMachO:
		return "macho"
	default:
		return "unknown"
	}
}

// Sniff probes the file header only: ident/header -> Format + arch.ID +
// arch.Variant. It is deliberately lightweight — the first step of the P4
// boot sequence, where the Arch must be known BEFORE a backend is created.
// It must never map guest memory, apply relocations, initialize a backend,
// or run constructors. An io.ReaderAt (e.g. *os.File or bytes.Reader)
// suffices.
func Sniff(r io.ReaderAt) (Format, arch.ID, arch.Variant, error) {
	// e_ident[16] + e_type[2] + e_machine[2]: 20 bytes cover everything an
	// ELF probe needs (e_machine sits at the same offset in ELF32/ELF64).
	var hdr [20]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return 0, 0, 0, fmt.Errorf("loader: sniff: cannot read header (truncated?): %w", err)
	}
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported object format (not ELF: magic %#x)", [4]byte{hdr[0], hdr[1], hdr[2], hdr[3]})
	}
	// e_machine, endianness per EI_DATA.
	var machine uint16
	switch hdr[5] {
	case 1: // ELFDATA2LSB
		machine = binary.LittleEndian.Uint16(hdr[18:])
	case 2: // ELFDATA2MSB
		machine = binary.BigEndian.Uint16(hdr[18:])
	default:
		return 0, 0, 0, fmt.Errorf("loader: sniff: unknown ELF data encoding %d", hdr[5])
	}
	// ELF/AArch64 has no variant-encoding e_flags in use; Generic. (Mach-O
	// will derive Variant from cpusubtype — P5b.)
	return FormatELF, arch.ID(machine), arch.VariantGeneric, nil
}

// Parser parses one object file of a registered Format into an Image.
// Implemented by the format subpackages (loader/elf, ...).
type Parser func(path string) (*Image, error)

var parsers = map[Format]Parser{}

// RegisterParser makes a Parser available under f; called from a format
// package's init(). As in arch.Register, a duplicate key overwrites —
// registration happens at init time, so the last linked implementation wins.
func RegisterParser(f Format, p Parser) {
	if p == nil {
		return
	}
	parsers[f] = p
}

// Parse reads the object file at path and builds the Image, dispatching on
// the sniffed format. base is not applied here; all addresses are
// image-relative (load bias added at map time).
func Parse(path string) (*Image, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	format, _, _, err := Sniff(fh)
	fh.Close()
	if err != nil {
		return nil, err
	}
	p, ok := parsers[format]
	if !ok {
		return nil, fmt.Errorf("loader: no parser registered for format %s (import the loader/%s package for its init())", format, format)
	}
	return p(path)
}
