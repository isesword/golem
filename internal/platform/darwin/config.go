// Package darwin is the Darwin (macOS/XNU) OS-platform personality (P5b,
// DESIGN.md §3.4): the BSD-syscall transport + number table + guest struct
// codecs, the guest address-space LayoutPolicy, the StartupABI (exec-style
// initial stack frame — Darwin has no auxv), and the typed boot Config.
//
// P5b scope is deliberately thin: it exists to prove the platform seam is
// real — that loader, kernel, emu and the emulator's boot pipeline carry no
// Android-shaped assumptions. The syscall table therefore binds only what the
// e2e acceptance chain exercises (the pid/uid family); everything else falls
// through Dispatch to a logged ENOSYS, exactly the bring-up policy the
// Android table started with.
package darwin

import (
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
)

// Config is the Darwin personality's typed boot configuration (P4a shape,
// DESIGN.md §3.6 invariant 4): the pieces that only make sense for a
// Darwin-flavoured guest, carried to the composition root as a
// platform.Config so emulator.Config stays platform-agnostic.
//
// Unlike android.Config there is deliberately no JNI/Dex/profile surface:
// a Darwin guest has no Java runtime and P5b models no device persona.
// ReplaceFns is the same interposition contract as Android's (both binding
// paths terminate in interpose.InterposeTable).
type Config struct {
	// ReplaceFns installs Go implementations by symbol name, with two binding
	// paths: names the loaded modules import as UNRESOLVED symbols get their
	// stub bound to the implementation (before linking); names the loaded
	// modules EXPORT are interposed after boot completes — an entry execution
	// hook, not a code patch. The callback context satisfies
	// interpose.CallContext; it is the emulator's *Hook, which callers that
	// import the emulator package may recover with ctx.(*emulator.Hook).
	ReplaceFns map[string]interpose.HostFunc
}

var _ platform.Config = (*Config)(nil)

// Option mutates a Darwin Config under construction (functional options).
type Option func(*Config)

// NewConfig builds a Darwin Config from functional options.
func NewConfig(opts ...Option) *Config {
	c := &Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// WithReplaceFns installs Go implementations by symbol name (see
// Config.ReplaceFns).
func WithReplaceFns(fns map[string]interpose.HostFunc) Option {
	return func(c *Config) { c.ReplaceFns = fns }
}

// PlatformID implements platform.Config.
func (c *Config) PlatformID() platform.ID { return platform.Darwin }
