// Package arm32 implements the ELF/ARM (32-bit, armv7 EABI) Relocator: the
// relocation SEMANTICS (what each R_ARM_* code writes into guest memory),
// the ARM32 counterpart of loader/elf/arm64 and loader/elf/amd64 (P6c,
// DESIGN.md §3.3). Memory layout — segment mapping, shareability,
// protections — stays in loader.Plan; this package only knows how one
// relocation entry is applied.
//
// Registers itself under (FormatELF, emu.ArchARM) via init(); import it
// (blank) from the composition root.
//
// REL, not RELA: 32-bit ARM dynamic objects carry DT_REL (SHT_REL), whose
// entries have NO explicit addend — the addend is the 32-bit word already
// stored at the relocation target in the file image. Every handled type is
// therefore a READ-MODIFY-WRITE of one little-endian u32 (this is exactly
// how the bionic linker relocates REL sections: it reads the addend from
// *reloc before writing the result):
//
//	R_ARM_RELATIVE (23):  *P = B + A          (A = stored word)
//	R_ARM_ABS32    (2):   *P = S + A          (A = stored word)
//	R_ARM_TARGET1  (38):  *P = S + A          (same as ABS32 on Linux)
//	R_ARM_GLOB_DAT (21):  *P = S + A          (A = stored word, usually 0)
//	R_ARM_JUMP_SLOT(22):  *P = S + A          (A = stored word, usually 0)
//
// (B = load bias, S = resolved symbol value, A = addend.) TLS relocations
// (R_ARM_TLS_DTPMOD32/DTPOFF32/TPOFF32, 17/18/19) are deliberately NOT
// implemented: golem materializes TLS via arch.Arch.SetTLSBase rather than
// static-TLS relocation fixups — encountering one errors loudly instead of
// being silently misapplied.
package arm32

import (
	debugelf "debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

func init() { loader.RegisterRelocator(loader.FormatELF, emu.ArchARM, relocator{}) }

type relocator struct{}

// Apply writes one relocation into guest memory. r.Offset is image-relative;
// base is the per-engine load bias; res resolves imported symbols through the
// P3.5 SymbolResolver contract — the result is always a guest address, so a
// host-interposed symbol is indistinguishable from a guest one here.
//
// The addend is read from the target's stored word (REL semantics); the
// explicit r.Addend is ignored — REL entries carry none, and for RELR-
// expanded RELATIVE entries the parser already recorded the same value the
// target word holds, so reading memory is correct in both cases.
func (relocator) Apply(b emu.Backend, img *loader.Image, r loader.Reloc, base uint64, res loader.SymbolResolver) error {
	target := base + r.Offset
	switch debugelf.R_ARM(r.Type) {
	case debugelf.R_ARM_RELATIVE:
		// B + A: the stored value is the unrelocated address; add the bias.
		a, err := get32(b, target)
		if err != nil {
			return err
		}
		if err := put32(b, target, base+uint64(a)); err != nil {
			return err
		}
	case debugelf.R_ARM_GLOB_DAT, debugelf.R_ARM_JUMP_SLOT,
		debugelf.R_ARM_ABS32, debugelf.R_ARM_TARGET1:
		val, err := img.SymValue(r.Sym, base, res)
		if err != nil {
			return err
		}
		a, err := get32(b, target)
		if err != nil {
			return err
		}
		if err := put32(b, target, val+uint64(a)); err != nil {
			return err
		}
	case debugelf.R_ARM_TLS_DTPMOD32, debugelf.R_ARM_TLS_DTPOFF32, debugelf.R_ARM_TLS_TPOFF32,
		debugelf.R_ARM(0x20) /* R_ARM_TLS_GD32 */, debugelf.R_ARM(0x21), /* R_ARM_TLS_LDM32 */
		debugelf.R_ARM(0x22) /* R_ARM_TLS_LDO32 */, debugelf.R_ARM(0x23), /* R_ARM_TLS_IE32 */
		debugelf.R_ARM(0x24) /* R_ARM_TLS_LE32 */ :
		return fmt.Errorf("unimplemented TLS reloc type %s at 0x%x (golem materializes TLS via arch SetTLSBase, not static-TLS fixups)", debugelf.R_ARM(r.Type), r.Offset)
	default:
		return fmt.Errorf("unhandled reloc type %s at 0x%x", debugelf.R_ARM(r.Type), r.Offset)
	}
	return nil
}

func get32(be emu.Backend, addr uint64) (uint32, error) {
	b, err := be.MemRead(emu.GuestAddr(addr), 4)
	if err != nil {
		return 0, fmt.Errorf("read reloc addend at 0x%x: %w", addr, err)
	}
	if len(b) < 4 {
		return 0, fmt.Errorf("read reloc addend at 0x%x: short read (%d < 4)", addr, len(b))
	}
	return binary.LittleEndian.Uint32(b), nil
}

func put32(be emu.Backend, addr uint64, val uint64) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(val))
	return be.MemWrite(emu.GuestAddr(addr), b[:])
}
