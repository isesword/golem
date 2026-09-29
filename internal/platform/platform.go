// Package platform is the root of golem's OS-platform layer (DESIGN.md
// §3.4): it owns the platform identity type, the platform-config contract
// and the layout-policy contract, and nothing else. Platform personalities
// (android today, darwin in P5b) live in subpackages that import this
// package — never the reverse.
//
// Dependency direction: platform imports only arch and memory (both sit
// below it per DESIGN.md §2), so any layer (arch, loader, emulator) may
// reference platform.ID and platform.LayoutPolicy without creating a cycle.
// In particular platform must NOT import internal/target: target aggregates
// platform (Target.Platform), so the LayoutPolicy input is narrowed to the
// minimal TargetInfo below instead of the full Target.
package platform

import (
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/memory"
)

// ID identifies an OS platform personality (syscall transport + semantics
// binding, startup ABI, layout policy, runtime libraries, VFS flavour).
type ID uint8

const (
	// Android is the Linux/bionic Android personality — the only supported
	// platform until P5b (Darwin).
	Android ID = iota + 1
	Darwin
)

// String names the platform for logs and error messages.
func (id ID) String() string {
	switch id {
	case Android:
		return "android"
	case Darwin:
		return "darwin"
	default:
		return "unknown"
	}
}

// Config is a platform personality's typed boot configuration (P4a,
// DESIGN.md §3.6 invariant 4): each platform subpackage defines its own
// Config struct with functional options (e.g. android.NewConfig(
// android.WithJNI(...))) and implements this interface so the composition
// root can carry it without knowing the concrete shape. The core layer never
// dispatches platform configs via any + type-switch; the composition root
// binds the single supported implementation at the option boundary.
type Config interface {
	PlatformID() ID
}

// TargetInfo is the minimal, dependency-safe input a LayoutPolicy plans
// against (P4c). It deliberately carries only arch address-space
// capabilities — NOT the full target.Target, because target aggregates
// platform (Target.Platform) and platform importing it back would close a
// dependency cycle.
type TargetInfo struct {
	Platform ID
	Caps     arch.AddressSpaceCaps
}

// LayoutOverrides carries optional user overrides of a platform's default
// guest address-space layout (emulator.Config.LayoutOverrides). Reserved for
// P5+; the zero value always means "platform defaults" and is currently the
// only supported value.
type LayoutOverrides struct{}

// LayoutPolicy answers exactly one question: how is the initial guest
// address space planned (P4c, DESIGN.md §3.4/§6)? It maps arch capabilities
// plus user overrides to a pure-data memory.Layout. It must NEVER Map, Alloc
// or Reserve — materializing the plan into backend mappings and allocation
// state is the AddressSpace's and the composition root's job.
type LayoutPolicy interface {
	Resolve(target TargetInfo, overrides LayoutOverrides) (memory.Layout, error)
}
