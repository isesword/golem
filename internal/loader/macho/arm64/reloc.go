// Package arm64 implements the Mach-O/ARM64 Relocator: the relocation
// SEMANTICS of the dyld rebase/bind opcodes the loader/macho parser expands
// into loader.Reloc entries, mirroring loader/elf/arm64. Memory layout
// — segment mapping, shareability, protections — stays in loader.Plan; this
// package only knows how one relocation entry is applied.
//
// Registers itself under (FormatMachO, emu.ArchARM64) via init(); import it
// (blank) from the composition root. ARM64E authenticated (chained) fixups
// are deliberately NOT here: the parser rejects LC_DYLD_CHAINED_FIXUPS at
// load time, so a relocator never meets them (the Variant-gated world).
package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/loader/macho"
)

func init() { loader.RegisterRelocator(loader.FormatMachO, emu.ArchARM64, relocator{}) }

type relocator struct{}

// Apply writes one relocation into guest memory. r.Offset is image-relative;
// base is the per-engine load bias; res resolves imported symbols through the
// .5 SymbolResolver contract — the result is always a guest address, so a
// host-interposed symbol is indistinguishable from a guest one here.
func (relocator) Apply(b emu.Backend, img *loader.Image, r loader.Reloc, base uint64, res loader.SymbolResolver) error {
	target := base + r.Offset
	switch r.Type {
	case macho.RelocRebasePointer:
		// REBASE_TYPE_POINTER: the addend is the unrelocated pointer value
		// the parser read from the file image (same convention as SHT_RELR
		// expansion in loader/elf) — relocate it by the load bias.
		if err := put64(b, target, base+uint64(r.Addend)); err != nil {
			return err
		}
	case macho.RelocBindPointer:
		// BIND_TYPE_POINTER: bind the slot to the resolved symbol address.
		val, err := img.SymValue(r.Sym, base, res)
		if err != nil {
			return err
		}
		if err := put64(b, target, val+uint64(r.Addend)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("macho/arm64: unhandled reloc type %d at %#x", r.Type, r.Offset)
	}
	return nil
}

func put64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(emu.GuestAddr(addr), b[:])
}
