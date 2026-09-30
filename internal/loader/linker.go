package loader

import (
	"debug/elf"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Apply maps the image's PT_LOAD segments into the backend at `base` and
// performs all dynamic relocations (via the Relocator registered for the
// image's (Format, Arch) — e.g. loader/elf/arm64), resolving every imported
// symbol through the given SymbolResolver (P3.5). After this the module's
// code/data is live in guest memory; init_array still needs to be executed
// by the caller.
// Legacy single-engine entry point: delegates to Plan + Plan.Apply with
// private (anonymous) memory everywhere — identical semantics to the
// historical implementation. Use Image.Plan + Plan.Apply to share read-only
// pages across engines.
func (img *Image) Apply(be emu.Backend, base uint64, res SymbolResolver) error {
	plan, err := img.Plan()
	if err != nil {
		return err
	}
	return plan.Apply(be, base, res)
}

// SymValue resolves a relocation's symbol per engine: defined symbols =>
// base+value, imported (undef) => via the SymbolResolver (P3.5: the one
// resolution contract — host replacements, guest exports and the unresolved
// fallback all sit behind it, and the resolver only ever returns guest
// addresses). Used by Relocator implementations (loader/<format>/<arch>).
func (img *Image) SymValue(sym uint32, base uint64, res SymbolResolver) (uint64, error) {
	if int(sym) >= len(img.Syms) {
		return 0, fmt.Errorf("reloc sym index %d out of range", sym)
	}
	s := img.Syms[sym]
	if !s.Undef {
		return base + s.Value, nil
	}
	if res == nil {
		return 0, fmt.Errorf("unresolved import %q (no resolver)", s.Name)
	}
	rs, err := res.Resolve(ResolveRequest{
		Requester:  img,
		Name:       s.Name,
		Binding:    s.Binding(),
		Visibility: s.Visibility,
	})
	if err != nil {
		return 0, fmt.Errorf("unresolved import %q (%s): %w", s.Name, s.Binding(), err)
	}
	// The resolver's answer is a guest address by contract, whatever the
	// symbol's Kind — including 0 for an unresolved WEAK undefined (ELF).
	return uint64(rs.Addr), nil
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
