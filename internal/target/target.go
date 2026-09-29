// Package target defines the immutable Target: the single source of truth
// for arch / call-ABI / stub-encoder / object-format / platform resolution
// (P4a, DESIGN.md §4 boot sequence).
//
// Invariant: once boot has resolved a Target, no lower layer may re-guess
// the arch or platform from the SO header or config again — the Target is
// built once by the composition root and passed down read-only.
//
// Dependency direction: target aggregates arch, loader and platform; none of
// them may import target back. (A future platform.Factory bound to a Target
// — DESIGN.md §3.4, P4e — will need this re-homed or split into an
// arch+format TargetInfo living lower; that is a P4e decision.)
package target

import (
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
)

// Target is the resolved, immutable description of what an Emulator runs.
// Construct it once at boot and treat it as read-only afterwards; Features
// (CPUFeatures / HWCAP source of truth) arrive in P4d and are deliberately
// not pre-built here (YAGNI).
type Target struct {
	Arch     arch.Arch        // pure CPU properties (invariant 13)
	CallABI  arch.CallABI     // function calling convention
	Stubs    arch.StubEncoder // guest trampoline encoding
	Format   loader.Format    // object format of the main image
	Platform platform.ID      // OS platform personality
	Variant  arch.Variant     // ISA variant (e.g. ARM64E) within Arch
}
