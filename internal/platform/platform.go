// Package platform is the root of golem's OS-platform layer (DESIGN.md
// §3.4): it owns the platform identity type and the platform-config contract,
// and nothing else. Platform personalities (android today, darwin in P5b)
// live in subpackages that import this package — never the reverse.
//
// Dependency direction: platform imports no internal package, so any layer
// (arch, loader, emulator) may reference platform.ID without creating a
// cycle.
package platform

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
