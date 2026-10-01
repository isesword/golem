// Package arm64 implements the ELF/AArch64 Relocator: the relocation
// SEMANTICS (what each R_AARCH64_* code writes into guest memory), split out
// of loader.Plan in (DESIGN.md §3.3). Memory layout — segment mapping,
// shareability, protections — stays in loader.Plan; this package only knows
// how one relocation entry is applied.
//
// Registers itself under (FormatELF, emu.ArchARM64) via init(); import it
// (blank) from the composition root. Only the 4 relocation types the Android
// ARM64 target actually uses are handled (verified via cmd/loadplan):
// RELATIVE, GLOB_DAT, JUMP_SLOT, ABS64. RELR entries were already expanded
// to RELATIVE at parse time (loader/elf).
package arm64

import (
	debugelf "debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

func init() { loader.RegisterRelocator(loader.FormatELF, emu.ArchARM64, relocator{}) }

type relocator struct{}

// Apply writes one relocation into guest memory. r.Offset is image-relative;
// base is the per-engine load bias; res resolves imported symbols through the
// SymbolResolver contract — the result is always a guest address, so a
// host-interposed symbol is indistinguishable from a guest one here.
func (relocator) Apply(b emu.Backend, img *loader.Image, r loader.Reloc, base uint64, res loader.SymbolResolver) error {
	target := base + r.Offset
	switch debugelf.R_AARCH64(r.Type) {
	case debugelf.R_AARCH64_RELATIVE:
		if err := put64(b, target, base+uint64(r.Addend)); err != nil {
			return err
		}
	case debugelf.R_AARCH64_GLOB_DAT, debugelf.R_AARCH64_JUMP_SLOT, debugelf.R_AARCH64_ABS64:
		val, err := img.SymValue(r.Sym, base, res)
		if err != nil {
			return err
		}
		if err := put64(b, target, val+uint64(r.Addend)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unhandled reloc type %s at 0x%x", debugelf.R_AARCH64(r.Type), r.Offset)
	}
	return nil
}

func put64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(emu.GuestAddr(addr), b[:])
}
