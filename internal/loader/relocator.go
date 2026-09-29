package loader

import (
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Relocator applies the relocation SEMANTICS of one (Format, Arch) pair:
// what each relocation type code means and how it is written into guest
// memory. It deliberately does NOT live on arch.CallABI (calling conventions
// know nothing about object formats) and does NOT own memory layout (that
// stays in Plan — segment mapping, shareability, protections).
//
// base is the per-engine load bias; resolve maps imported symbol names to
// guest addresses. r.Offset is image-relative; the Relocator computes the
// final guest address itself.
type Relocator interface {
	Apply(b emu.Backend, img *Image, r Reloc, base uint64, resolve Resolver) error
}

// --- registry (same style as arch.Register / emu.Register) ---------------

type relocKey struct {
	f Format
	a emu.Arch
}

var relocators = map[relocKey]Relocator{}

// RegisterRelocator makes a Relocator available under (f, a); called from an
// implementation package's init() (e.g. loader/elf/arm64 registers
// (FormatELF, emu.ArchARM64)). A duplicate key overwrites — registration
// happens at init time, so the last linked implementation wins. An ARM64E
// authenticated-fixup capability is a macho/arm64-internal Variant branch,
// not a separate key.
func RegisterRelocator(f Format, a emu.Arch, r Relocator) {
	if r == nil {
		return
	}
	relocators[relocKey{f, a}] = r
}

// ResolveRelocator returns the Relocator registered for (f, a). An unknown
// pair is an error naming the missing implementation — the fix is to import
// the relevant loader/<format>/<arch> package for its init().
func ResolveRelocator(f Format, a emu.Arch) (Relocator, error) {
	if r, ok := relocators[relocKey{f, a}]; ok {
		return r, nil
	}
	return nil, fmt.Errorf("loader: no relocator registered for format=%s arch=%s (import the loader/%s/<arch> package for its init())", f, a, f)
}
