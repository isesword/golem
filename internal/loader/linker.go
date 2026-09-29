package loader

import (
	"debug/elf"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Resolver maps an imported symbol name to a guest address (e.g. a bionic
// export or an SVC trampoline). ok=false means unresolved.
type Resolver func(name string) (addr uint64, ok bool)

// Apply maps the image's PT_LOAD segments into the backend at `base` and
// performs all dynamic relocations (via the Relocator registered for the
// image's (Format, Arch) — e.g. loader/elf/arm64). After this the module's
// code/data is live in guest memory; init_array still needs to be executed
// by the caller.
// Legacy single-engine entry point: delegates to Plan + Plan.Apply with
// private (anonymous) memory everywhere — identical semantics to the
// historical implementation. Use Image.Plan + Plan.Apply to share read-only
// pages across engines.
func (img *Image) Apply(be emu.Backend, base uint64, resolve Resolver) error {
	plan, err := img.Plan()
	if err != nil {
		return err
	}
	return plan.Apply(be, base, resolve)
}

// SymValue resolves a relocation's symbol per engine: defined symbols =>
// base+value, imported (undef) => via the resolver. Used by Relocator
// implementations (loader/<format>/<arch>).
func (img *Image) SymValue(sym uint32, base uint64, resolve Resolver) (uint64, error) {
	if int(sym) >= len(img.Syms) {
		return 0, fmt.Errorf("reloc sym index %d out of range", sym)
	}
	s := img.Syms[sym]
	if !s.Undef {
		return base + s.Value, nil
	}
	if resolve != nil {
		if v, ok := resolve(s.Name); ok {
			return v, nil
		}
	}
	return 0, fmt.Errorf("unresolved import %q", s.Name)
}

func protOf(f elf.ProgFlag) int {
	p := 0
	if f&elf.PF_R != 0 {
		p |= emu.ProtRead
	}
	if f&elf.PF_W != 0 {
		p |= emu.ProtWrite
	}
	if f&elf.PF_X != 0 {
		p |= emu.ProtExec
	}
	return p
}
