// Package target defines the immutable Target: the single source of truth
// for arch / call-ABI / stub-encoder / object-format / platform resolution
// (DESIGN.md §4 boot sequence).
//
// Invariant: once boot has resolved a Target, no lower layer may re-guess
// the arch or platform from the SO header or config again — the Target is
// built once by the composition root and passed down read-only.
//
// Dependency direction: target aggregates arch, loader and platform; none of
// them may import target back. (A future platform.Factory bound to a Target
// — DESIGN.md §3.4 — will need this re-homed or split into an
// arch+format TargetInfo living lower; that is a decision.)
package target

import (
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
)

// Target is the resolved, immutable description of what an Emulator runs.
// Construct it once at boot and treat it as read-only afterwards. Features —
// the CPUFeatures / HWCAP single source of truth — is resolved together
// with the Arch/CallABI/StubEncoder quad and never re-derived downstream.
type Target struct {
	ID       arch.ID          // object-format machine identity (ELF e_machine) —.5
	Arch     arch.Arch        // pure CPU properties (invariant 13)
	CallABI  arch.CallABI     // function calling convention
	Stubs    arch.StubEncoder // guest trampoline encoding
	Features arch.CPUFeatures // CPU capability bits; sole HWCAP source
	Format   loader.Format    // object format of the main image
	Platform platform.ID      // OS platform personality
	Variant  arch.Variant     // ISA variant (e.g. ARM64E) within Arch
}
