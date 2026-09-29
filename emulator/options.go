package emulator

import (
	"errors"
	"fmt"
	"os"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/platform/darwin"
	"github.com/isesword/golem/internal/target"
)

// Option mutates the boot Config at New time (functional options, P4a —
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
// Supported configs (checked once here, at the option boundary — the core
// never dispatches platform configs via any + type-switch): *android.Config
// and *darwin.Config (P5b). The config's platform must match the platform the
// SOPath probe derives — a mismatch fails New in the normalization step.
func WithPlatformConfig(c platform.Config) Option {
	return func(cfg *Config) error {
		if c == nil {
			return errors.New("emulator: WithPlatformConfig(nil)")
		}
		switch pc := c.(type) {
		case *android.Config:
			cfg.acfg = pc
		case *darwin.Config:
			cfg.dcfg = pc
		default:
			return fmt.Errorf("emulator: unsupported platform config %T (platform %s)", c, c.PlatformID())
		}
		return nil
	}
}

// normalizePlatformConfig is the options-normalization step of the boot
// sequence (DESIGN.md §4, step 1) and the ONE place the deprecated
// Config.Android field is read (the legacy shim). It runs AFTER the probe
// (resolveTarget), because the platform the config speaks for must match the
// probed platform: an android.Config with a Mach-O target (or a
// darwin.Config with an ELF target) is a boot-time error, not a silent
// mis-wiring.
//
// Android precedence: an explicit WithPlatformConfig wins; Config.Android is
// then required to be zero (setting both is an ambiguity error, not a silent
// override). With neither, the platform defaults (all-zero Config) apply.
func normalizePlatformConfig(cfg *Config, tgt *target.Target) (*android.Config, *darwin.Config, error) {
	switch tgt.Platform {
	case platform.Android:
		if cfg.dcfg != nil {
			return nil, nil, fmt.Errorf("emulator: WithPlatformConfig(darwin.Config) but %s probes as android (ELF); the platform config must match the guest platform", cfg.SOPath)
		}
		if cfg.acfg != nil {
			if legacy := legacyAndroidUsed(cfg.Android); legacy {
				return nil, nil, errors.New("emulator: Config.Android (deprecated) and WithPlatformConfig are mutually exclusive; move the AndroidConfig fields to android.NewConfig options")
			}
			return cfg.acfg, nil, nil
		}
		cfg.acfg = android.NewConfig(
			android.WithJNI(cfg.Android.JNI),
			android.WithDexPath(cfg.Android.DexPath),
			android.WithReplaceFns(legacyReplaceFns(cfg.Android.ReplaceFns)),
			android.WithPropertyProvider(cfg.Android.PropertyProvider),
			android.WithProfile(cfg.Android.Profile),
		)
		return cfg.acfg, nil, nil
	case platform.Darwin:
		if cfg.acfg != nil || legacyAndroidUsed(cfg.Android) {
			return nil, nil, fmt.Errorf("emulator: android platform config but %s probes as darwin (Mach-O); the platform config must match the guest platform", cfg.SOPath)
		}
		if cfg.dcfg == nil {
			cfg.dcfg = darwin.NewConfig()
		}
		return nil, cfg.dcfg, nil
	default:
		return nil, nil, fmt.Errorf("emulator: no platform-config normalization for platform %s", tgt.Platform)
	}
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
// without either, everything is ARM64 (the pre-P4 default). Platform is
// DERIVED FROM THE PROBED FORMAT (P5b): Mach-O -> Darwin, ELF -> Android;
// without an SOPath there is nothing to probe and the pre-P5 default
// (Android) applies.
func resolveTarget(cfg Config) (*target.Target, error) {
	id := cfg.Arch
	variant := arch.VariantGeneric
	format := loader.FormatELF
	plat := platform.Android // pre-P5 default; the probe may refine it
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
		id = arch.IDARM64 // pre-P4 semantics: everything is ARM64
	}
	cpuArch, callABI, stubEnc, feats, err := arch.Resolve(id, variant)
	if err != nil {
		return nil, err
	}
	// The platform is carried in the Target so no lower layer ever re-derives
	// it. Features (P4d) is the quad's CPUFeatures — the single HWCAP source
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

// resolveLayout is the LayoutPolicy step of the boot sequence (DESIGN.md §4,
// P4c): the target's platform personality plans the initial guest address
// space from the arch's address-space capabilities plus user overrides. The
// result is pure data — backend mappings and AddressSpace state are built
// from it later, never inside the policy. The platform-keyed policy selection
// is bound here at the composition root (same shape as the
// Transport/Table/Codecs injection in New).
func resolveLayout(tgt *target.Target, overrides platform.LayoutOverrides) (memory.Layout, error) {
	info := platform.TargetInfo{Platform: tgt.Platform, Caps: tgt.Arch.Caps()}
	switch tgt.Platform {
	case platform.Android:
		return android.LayoutPolicy{}.Resolve(info, overrides)
	case platform.Darwin:
		return darwin.LayoutPolicy{}.Resolve(info, overrides)
	default:
		return memory.Layout{}, fmt.Errorf("emulator: no LayoutPolicy for platform %s", tgt.Platform)
	}
}
