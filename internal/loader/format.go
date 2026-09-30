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
	// magic[4] + cputype[4] + cpusubtype[4]: 12 bytes cover everything a
	// Mach-O 64-bit probe needs; ELF reads further below.
	var hdr [12]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return 0, 0, 0, fmt.Errorf("loader: sniff: cannot read header (truncated?): %w", err)
	}
	switch magic := binary.LittleEndian.Uint32(hdr[:]); magic {
	case 0x464c457f: // "\x7fELF"
		return sniffELF(r)
	case 0xfeedfacf: // MH_MAGIC_64, little-endian on disk (CF FA ED FE)
		return sniffMachO64(hdr[:])
	case 0xfeedface, // MH_MAGIC (32-bit)
		0xcefaedfe, 0xcffaedfe: // MH_CIGAM / MH_CIGAM_64 (big-endian on disk)
		return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported Mach-O variant (magic %#x: only 64-bit little-endian is supported)", magic)
	case 0xcafebabe, 0xbebafeca, // FAT_MAGIC / FAT_CIGAM
		0xcafebabf, 0xbfbafeca: // FAT_MAGIC_64 / FAT_CIGAM_64
		return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported object format (fat/universal Mach-O: magic %#x)", magic)
	default:
		return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported object format (magic %#x)", magic)
	}
}

// sniffELF is the ELF branch of Sniff: e_machine at offset 18, endianness per
// EI_DATA.
func sniffELF(r io.ReaderAt) (Format, arch.ID, arch.Variant, error) {
	// e_ident[16] + e_type[2] + e_machine[2]: 20 bytes cover everything an
	// ELF probe needs (e_machine sits at the same offset in ELF32/ELF64).
	var hdr [20]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return 0, 0, 0, fmt.Errorf("loader: sniff: cannot read header (truncated?): %w", err)
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
	// ELF/AArch64 has no variant-encoding e_flags in use; Generic.
	return FormatELF, arch.ID(machine), arch.VariantGeneric, nil
}

// Mach-O CPU identities the probe recognizes (mach/machine.h). arch.ID values
// follow ELF numbering where one exists (arch.ID doc), so the Mach-O cputype
// maps onto the SAME ids the ELF probe reports — one arch identity regardless
// of container format.
const (
	machoCPUArm64  = 0x0100000c // CPU_TYPE_ARM64 (CPU_ARCH_ABI64 | 12)
	machoCPUX86_64 = 0x01000007 // CPU_TYPE_X86_64 (CPU_ARCH_ABI64 | 7)

	machoSubtypeMask   = 0xff000000 // CPU_SUBTYPE_MASK: capability bits (incl. CPU_SUBTYPE_LIB64)
	machoSubtypeARM64  = 0          // CPU_SUBTYPE_ARM64_ALL
	machoSubtypeARM64E = 2          // CPU_SUBTYPE_ARM64E
	machoSubtypeX86_64 = 3          // CPU_SUBTYPE_X86_64_ALL
)

// sniffMachO64 is the 64-bit little-endian Mach-O branch of Sniff: cputype /
// cpusubtype -> arch.ID + arch.Variant. ARM64E maps to VariantARM64E
// (CPU_SUBTYPE_ARM64E with the CPU_SUBTYPE_MASK capability bits — including
// LIB64 — masked off, per mach/machine.h); the arm64 package registers that
// variant with the SAME quad as VariantGeneric (P5c: the variant difference
// is authenticated chained fixups, which is the loader's business).
func sniffMachO64(hdr []byte) (Format, arch.ID, arch.Variant, error) {
	cputype := binary.LittleEndian.Uint32(hdr[4:])
	subtype := binary.LittleEndian.Uint32(hdr[8:]) &^ machoSubtypeMask
	switch cputype {
	case machoCPUArm64:
		switch subtype {
		case machoSubtypeARM64:
			return FormatMachO, arch.IDARM64, arch.VariantGeneric, nil
		case machoSubtypeARM64E:
			return FormatMachO, arch.IDARM64, arch.VariantARM64E, nil
		}
		return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported Mach-O arm64 cpusubtype %d", subtype)
	case machoCPUX86_64:
		if subtype != machoSubtypeX86_64 {
			return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported Mach-O x86_64 cpusubtype %d", subtype)
		}
		return FormatMachO, arch.IDAMD64, arch.VariantGeneric, nil
	}
	return 0, 0, 0, fmt.Errorf("loader: sniff: unsupported Mach-O cputype %#x", cputype)
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
