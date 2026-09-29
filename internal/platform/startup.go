package platform

import (
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
)

// AuxvEntry is one auxiliary-vector pair (Linux auxv / ELF ABI): a Type tag
// (AT_*) and its value — a scalar or a guest pointer, depending on the tag.
// The auxv vector a StartupABI builds is a []AuxvEntry terminated by
// AT_NULL; the concrete AT_* numbering belongs to the platform personality
// (e.g. platform/android), not to this package.
type AuxvEntry struct {
	Type uint64
	Val  uint64
}

// MemWriter is the slice of emu.Backend a StartupABI needs to materialize
// the initial-state data block into guest memory (the auxv vector, the
// AT_RANDOM bytes). Consumer-owned narrow interface (DESIGN.md invariant 2
// style): emu.Backend satisfies it.
type MemWriter interface {
	MemWrite(addr emu.GuestAddr, data []byte) error
}

// StartupContext is everything a StartupABI needs to build the process
// initial state (P4d, DESIGN.md §3.4 invariant 10 — the initial process
// image belongs to platform.StartupABI, which consumes loader metadata and
// arch capabilities; it is NOT the loader Format's job):
//
//   - Image/Base: startup metadata (PHDR table, entry point) of the main
//     image plus its load bias, from the loader (Image is nil when no main
//     module exists — a bionic-only boot).
//   - Features: the arch layer's CPUFeatures — the ONLY source of the
//     AT_HWCAP/AT_HWCAP2 bitmaps (P4d red line).
//   - AS/Stack: the address space and the already-mapped, already-reserved
//     initial stack region the data block is materialized into (the block
//     lives inside the stack mapping exactly like a real kernel's initial
//     stack frame; no new VA allocation is needed, so AddressSpace sees no
//     new Alloc/Reserve here).
//   - Mem: guest-memory writes for the materialization.
//   - Args/Env: the process argument/environment vectors. golem runs in
//     load-.so-and-call mode (no exec), so the current Android landing form
//     builds the auxv data block only and does not yet lay out
//     argc/argv/envp; the fields exist so an exec-style form (P5+) can
//     consume them without a contract change.
type StartupContext struct {
	Image    *loader.Image
	Base     emu.GuestAddr // load bias of Image (image-relative -> guest VA)
	AS       *memory.AddressSpace
	Stack    memory.Region // the mapped initial stack region
	Mem      MemWriter
	Args     []string
	Env      []string
	Features arch.CPUFeatures
}

// StartupABI builds the guest process initial state (P4d, DESIGN.md §3.4 /
// §6): the auxv vector — whose HWCAP bitmap comes exclusively from
// StartupContext.Features — plus the deterministic AT_RANDOM bytes, built
// once per emulator from the final image metadata.
//
// The Android implementation materializes the auxv vector as a data block at
// the top of the stack region and serves the interposed getauxval from that
// same vector (see platform/android/startup.go for why this is a data block
// and not an exec-style initial stack frame).
//
// Build-time ordering rule (P4e, locked by emulator's boot-order tests):
// with a main image the build MUST run after that image's FinalizeImage and
// before any of its init code executes; without a main image (bionic-only
// boot) the build is deliberately deferred to the first getauxval.
//
// P4e note: the entry/SP pair this contract used to return was removed —
// golem enters guest code through CallFunc/CallSymbol, never by jumping to
// an exec-style entry, and SP is set from the platform's StackTopReserve at
// boot, so nothing consumed the values (no speculative state kept).
type StartupABI interface {
	BuildInitialState(ctx *StartupContext) error
}
