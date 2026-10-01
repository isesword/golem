package emulator

import (
	"errors"
	"fmt"
	"os"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/target"
)

// Option mutates the boot Config at New time (functional options —
// DESIGN.md §3.6 invariant 4: platform personality config must not inflate
// the platform-agnostic Config struct). Options apply in order, before the
// legacy shim runs.
type Option func(*Config) error

// WithPlatformConfig supplies the platform personality's typed configuration
// (e.g. android.NewConfig(android.WithJNI(...), android.WithDexPath(...)) or
// darwin.NewConfig(darwin.WithReplaceFns(...))). It is mutually exclusive
// with the deprecated Config.Android field: setting both fails New with an
// error instead of silently picking one.
//
// The option boundary accepts ANY platform.Config and routes it by
// PlatformID() only (— the core never dispatches platform configs via
// any + type-switch): the config's platform must match the platform the
// SOPath probe derives, checked once in the normalization step; the platform
// factory's Bind then asserts its own concrete config type.
func WithPlatformConfig(c platform.Config) Option {
	return func(cfg *Config) error {
		if c == nil {
			return errors.New("emulator: WithPlatformConfig(nil)")
		}
		cfg.pcfg = c
		return nil
	}
}

// normalizePlatformConfig is the options-normalization step of the boot
// sequence (DESIGN.md §4, step 1) and the ONE place the deprecated
// Config.Android field is read (the legacy shim). It runs AFTER the probe
// (resolveTarget), because the platform the config speaks for must match the
// probed platform: an android.Config with a Mach-O target (or a
// darwin.Config with an ELF target) is a boot-time error, not a silent
// mis-wiring. The matching is PlatformID() routing, not a type-switch.
//
// Android precedence: an explicit WithPlatformConfig wins; Config.Android is
// then required to be zero (setting both is an ambiguity error, not a silent
// override). With neither, cfg.pcfg stays nil and the platform factory's
// Bind supplies the platform defaults.
func normalizePlatformConfig(cfg *Config, tgt *target.Target) error {
	if cfg.pcfg != nil {
		if cfg.pcfg.PlatformID() != tgt.Platform {
			return fmt.Errorf("emulator: WithPlatformConfig(%s) but %s probes as %s; the platform config must match the guest platform", cfg.pcfg.PlatformID(), cfg.SOPath, tgt.Platform)
		}
		if legacyAndroidUsed(cfg.Android) {
			return errors.New("emulator: Config.Android (deprecated) and WithPlatformConfig are mutually exclusive; move the AndroidConfig fields to android.NewConfig options")
		}
		return nil
	}
	// No explicit platform config: the legacy shim converts the deprecated
	// Config.Android fields into an android.Config exactly once, here
	// (compatibility semantics preserved — only the storage location moved,
	// from the acfg field to the single pcfg slot).
	if legacyAndroidUsed(cfg.Android) {
		if tgt.Platform != platform.Android {
			return fmt.Errorf("emulator: Config.Android (deprecated) is the android personality but %s probes as %s; the platform config must match the guest platform", cfg.SOPath, tgt.Platform)
		}
		cfg.pcfg = android.NewConfig(
			android.WithJNI(cfg.Android.JNI),
			android.WithDexPath(cfg.Android.DexPath),
			android.WithReplaceFns(legacyReplaceFns(cfg.Android.ReplaceFns)),
			android.WithPropertyProvider(cfg.Android.PropertyProvider),
			android.WithProfile(cfg.Android.Profile),
		)
	}
	return nil
}

// legacyAndroidUsed reports whether any field of the deprecated AndroidConfig
// was set.
func legacyAndroidUsed(a AndroidConfig) bool {
	return a.JNI != nil || a.DexPath != "" || len(a.ReplaceFns) > 0 ||
		a.PropertyProvider != nil || a.Profile != nil
}

// legacyReplaceFns adapts the legacy ReplaceFns callbacks (keyed on the
// emulator's *Hook) to interpose.HostFunc, the type android.Config carries.
// *Hook satisfies interpose.CallContext, so the adaptation is a plain
// closure — the same one ReplaceE has always applied.
func legacyReplaceFns(fns map[string]func(h *Hook) uint64) map[string]interpose.HostFunc {
	if len(fns) == 0 {
		return nil
	}
	out := make(map[string]interpose.HostFunc, len(fns))
	for name, fn := range fns {
		fn := fn
		out[name] = func(ctx interpose.CallContext) uint64 {
			return fn(ctx.(*Hook))
		}
	}
	return out
}

// resolveTarget is steps 2–4 of the boot sequence (DESIGN.md §4): a
// lightweight probe (loader.Sniff reads the SO header only — no mapping, no
// relocation, no backend) → arch.Resolve → the immutable Target that is the
// single source of truth for arch/format/platform from here on.
//
// Arch precedence: an explicit Config.Arch wins over the probed header;
// without either, everything is ARM64 (the legacy default). Platform is
// DERIVED FROM THE PROBED FORMAT Mach-O -> Darwin, ELF -> Android;
// without an SOPath there is nothing to probe and the legacy default
// (Android) applies.
func resolveTarget(cfg Config) (*target.Target, error) {
	id := cfg.Arch
	variant := arch.VariantGeneric
	format := loader.FormatELF
	plat := platform.Android // legacy default; the probe may refine it
	if cfg.SOPath != "" {
		fh, err := os.Open(cfg.SOPath)
		if err != nil {
			return nil, fmt.Errorf("probe %s: %w", cfg.SOPath, err)
		}
		f, probedID, probedVariant, err := loader.Sniff(fh)
		_ = fh.Close()
		if err != nil {
			return nil, fmt.Errorf("probe %s: %w", cfg.SOPath, err)
		}
		format = f
		variant = probedVariant
		if f == loader.FormatMachO {
			plat = platform.Darwin
		}
		if id == 0 {
			id = probedID
		}
	}
	if id == 0 {
		id = arch.IDARM64 // legacy semantics: everything is ARM64
	}
	cpuArch, callABI, stubEnc, feats, err := arch.Resolve(id, variant)
	if err != nil {
		return nil, err
	}
	// The platform is carried in the Target so no lower layer ever re-derives
	// it. Features is the quad's CPUFeatures — the single HWCAP source
	// of truth the Android StartupABI and the interposed getauxval both
	// derive from (the Darwin StartupABI deliberately never consults it).
	return &target.Target{
		ID:       id,
		Arch:     cpuArch,
		CallABI:  callABI,
		Stubs:    stubEnc,
		Features: feats,
		Format:   format,
		Platform: plat,
		Variant:  variant,
	}, nil
}
