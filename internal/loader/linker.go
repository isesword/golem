package loader

import (
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Resolver maps an imported symbol name to a guest address (e.g. a bionic
// export or an SVC trampoline). ok=false means unresolved.
type Resolver func(name string) (addr uint64, ok bool)

// Apply maps the image's PT_LOAD segments into the backend at `base` and
// performs all dynamic relocations. After this the module's code/data is live
// in guest memory; init_array still needs to be executed by the caller.
// Legacy single-engine entry point: delegates to Plan + Plan.Apply with
// private (anonymous) memory everywhere — identical semantics to the
// historical implementation. Use Image.Plan + Plan.ApplyShared to share
// read-only pages across engines.
//
// Only the 4 relocation types this target actually uses are handled (verified
// via cmd/loadplan): RELATIVE, GLOB_DAT, JUMP_SLOT, ABS64.
func (img *Image) Apply(be emu.Backend, base uint64, resolve Resolver) error {
	plan, err := img.Plan()
	if err != nil {
		return err
	}
	return plan.Apply(be, base, resolve)
}

// symValue resolves a relocation's symbol: defined symbols => base+value,
// imported (undef) => via the resolver.
func (img *Image) symValue(sym uint32, base uint64, resolve Resolver) (uint64, error) {
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

func put64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(addr, b[:])
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
