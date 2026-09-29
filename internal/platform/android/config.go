// Package android is the Android OS-platform personality (DESIGN.md §3.4):
// the syscall transport + number table + struct codecs, the guest
// address-space LayoutPolicy, the StartupABI (auxv initial state), and the
// typed boot Config.
//
// Assembly status (P5b.5): the platform.Factory lives in factory.go —
// registered under platform.Android from init(), it binds the complete
// Runtime (startup/auxv, layout, syscall personality, runtime libraries,
// bionic TLS init, ReplaceFns, pthread stubs, the Java/device interop
// surface) from a minimal BindContext (arch.ID + this package's Config).
// The composition root (emulator.New) resolves and binds it without any
// Android-specific selection logic of its own.
package android

import (
	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/profile"
)

// Config is the Android personality's typed boot configuration (P4a,
// DESIGN.md §3.6 invariant 4): the pieces that only make sense for an
// Android-flavoured guest, carried to the composition root as a
// platform.Config so emulator.Config stays platform-agnostic.
//
// It is the options-era home of what used to be emulator.AndroidConfig; the
// legacy struct field is converted into this type exactly once, inside the
// emulator's options normalization (the legacy shim).
//
// ReplaceFns are interposition host functions by nature — both binding paths
// (link-time symbol binding and run-time entry interposition) terminate in
// interpose.InterposeTable — so the map values are interpose.HostFunc and
// this package imports interpose to name them. This extends the platform/*
// dependency set of DESIGN.md §2 with interpose (which itself only depends
// on emu/arch/memory/loader, so no cycle is possible).
type Config struct {
	// JNI is the Java callback handler the guest's JNIEnv calls dispatch to.
	// nil = dvm.AbstractJni{} (everything returns null/0). Implement dvm.Jni
	// (or embed dvm.AbstractJni and override a few methods) to model the
	// Java side.
	JNI dvm.Jni
	// DexPath optionally loads a classes.dex at boot so FindClass/GetMethodID/
	// GetFieldID resolve against real class/method/field metadata (signatures,
	// superclasses) instead of being synthesized. Metadata only — no bytecode.
	DexPath string
	// ReplaceFns installs Go implementations by symbol name, with two binding
	// paths: names the loaded modules import as UNRESOLVED symbols get their
	// stub bound to the implementation (before linking); names the loaded
	// modules EXPORT are interposed after boot completes — an entry execution
	// hook, not a code patch. Model NDK/libc functions the guest calls here
	// (e.g. the AAssetManager family). The callback context satisfies
	// interpose.CallContext; it is the emulator's *Hook, which callers that
	// import the emulator package may recover with ctx.(*emulator.Hook).
	ReplaceFns map[string]interpose.HostFunc
	// PropertyProvider, if set, answers the loaded .so's
	// __system_property_get(key) calls: return (value, true) to supply a
	// value, or ("", false) for "unset".
	PropertyProvider func(key string) (string, bool)
	// Profile, if non-nil, installs a deterministic device-liveness model:
	// the kernel clock's monotonic origin becomes the persona's boot time (so
	// uptime/elapsedRealtime report a device that has been up for days), the
	// battery sysfs files follow a plausible charge/discharge rhythm, and the
	// JNI time getters (System.currentTimeMillis/nanoTime,
	// SystemClock.elapsedRealtime/uptimeMillis) derive uptime from the same
	// virtual clock — the cross-check consistency risk-control probes look
	// for. nil = previous behavior (host clock, no battery files).
	// emulator.Config.Epoch still takes precedence when both are set
	// (deterministic signing mode).
	Profile *profile.Profile
}

var _ platform.Config = (*Config)(nil)

// Option mutates an Android Config under construction (functional options).
type Option func(*Config)

// NewConfig builds an Android Config from functional options.
func NewConfig(opts ...Option) *Config {
	c := &Config{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// WithJNI sets the Java callback handler (see Config.JNI).
func WithJNI(j dvm.Jni) Option {
	return func(c *Config) { c.JNI = j }
}

// WithDexPath loads a classes.dex at boot for metadata-backed JNI resolution
// (see Config.DexPath).
func WithDexPath(p string) Option {
	return func(c *Config) { c.DexPath = p }
}

// WithReplaceFns installs Go implementations by symbol name (see
// Config.ReplaceFns).
func WithReplaceFns(fns map[string]interpose.HostFunc) Option {
	return func(c *Config) { c.ReplaceFns = fns }
}

// WithPropertyProvider sets the __system_property_get answerer (see
// Config.PropertyProvider).
func WithPropertyProvider(p func(key string) (string, bool)) Option {
	return func(c *Config) { c.PropertyProvider = p }
}

// WithProfile installs a deterministic device-liveness model (see
// Config.Profile).
func WithProfile(p *profile.Profile) Option {
	return func(c *Config) { c.Profile = p }
}

// PlatformID implements platform.Config.
func (c *Config) PlatformID() platform.ID { return platform.Android }
