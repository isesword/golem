// Package amd64 implements the ELF/x86-64 Relocator: the relocation SEMANTICS
// (what each R_X86_64_* code writes into guest memory), the AMD64 counterpart
// of loader/elf/arm64 (P5a, DESIGN.md §3.3). Memory layout — segment mapping,
// shareability, protections — stays in loader.Plan; this package only knows
// how one relocation entry is applied.
//
// Registers itself under (FormatELF, emu.ArchAMD64) via init(); import it
// (blank) from the composition root. The four relocation types handled are the
// ones a PIC shared object actually carries: RELATIVE (also what SHT_RELR
// expands to at parse time), GLOB_DAT, JUMP_SLOT, and R_X86_64_64 (absolute
// 64-bit). TLS relocations (DTPMOD64/DTPOFF64/TPOFF64) are deliberately NOT
// implemented: golem materializes TLS via arch.Arch.SetTLSBase rather than
// static-TLS relocation fixups, and no current fixture carries them — an
// unknown type errors loudly instead of being silently misapplied.
package amd64

import (
	debugelf "debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

func init() { loader.RegisterRelocator(loader.FormatELF, emu.ArchAMD64, relocator{}) }

type relocator struct{}

// Apply writes one relocation into guest memory. r.Offset is image-relative;
// base is the per-engine load bias; res resolves imported symbols through the
// P3.5 SymbolResolver contract — the result is always a guest address, so a
// host-interposed symbol is indistinguishable from a guest one here.
//
// x86-64 note: GLOB_DAT/JUMP_SLOT/R_X86_64_64 all compute S+A (symbol value
// plus addend) — like ARM64's GLOB_DAT/JUMP_SLOT/ABS64 trio the addend is
// explicit (RELA), so the semantics are identical to the AArch64
// implementation's; only the type codes differ.
func (relocator) Apply(b emu.Backend, img *loader.Image, r loader.Reloc, base uint64, res loader.SymbolResolver) error {
	target := base + r.Offset
	switch debugelf.R_X86_64(r.Type) {
	case debugelf.R_X86_64_RELATIVE:
		// B + A: the stored value is the load bias plus the addend.
		if err := put64(b, target, base+uint64(r.Addend)); err != nil {
			return err
		}
	case debugelf.R_X86_64_GLOB_DAT, debugelf.R_X86_64_JMP_SLOT, debugelf.R_X86_64_64:
		val, err := img.SymValue(r.Sym, base, res)
		if err != nil {
			return err
		}
		if err := put64(b, target, val+uint64(r.Addend)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unhandled reloc type %s at 0x%x", debugelf.R_X86_64(r.Type), r.Offset)
	}
	return nil
}

func put64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(emu.GuestAddr(addr), b[:])
}
