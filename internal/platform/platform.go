// Package platform is the root of golem's OS-platform layer (DESIGN.md
// §3.4): it owns the platform identity type, the platform-config contract,
// the layout-policy contract, the startup-ABI contract (P4d), and the
// platform registry (P5b.5) — the Factory/BindContext/Runtime seam through
// which the composition root binds a complete platform personality without
// holding any per-platform selection logic itself. Platform personalities
// (android, darwin) live in subpackages that import this package and
// register their factories from init() — this package never imports them.
//
// Dependency direction: platform imports only packages that sit below it per
// DESIGN.md §2 (arch, emu, loader, memory, kernel, interpose, profile, and
// the root dvm package — none of which imports platform back), so any layer (arch, loader, emulator) may reference platform.ID,
// platform.LayoutPolicy, platform.StartupABI and platform.Runtime without
// creating a cycle. In particular platform must NOT import internal/target:
// target aggregates platform (Target.Platform), so the LayoutPolicy input
// and the Factory's BindContext are narrowed to the minimal TargetInfo /
// arch.ID shapes instead of the full Target.
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
