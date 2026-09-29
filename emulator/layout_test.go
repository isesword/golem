package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/target"
)

// TestResolveLayoutMatchesAndroidPolicy pins the P4c composition-root wiring:
// the layout New boots with must be exactly what the platform's LayoutPolicy
// resolves for the Target — the numbers of the retired pre-P4c layout helper,
// carried by the policy, with zero user overrides.
func TestResolveLayoutMatchesAndroidPolicy(t *testing.T) {
	tgt, err := resolveTarget(Config{})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	got, err := resolveLayout(tgt, platform.LayoutOverrides{})
	if err != nil {
		t.Fatalf("resolveLayout: %v", err)
	}
	want, err := android.LayoutPolicy{}.Resolve(
		platform.TargetInfo{Platform: platform.Android, Caps: tgt.Arch.Caps()},
		platform.LayoutOverrides{},
	)
	if err != nil {
		t.Fatalf("android.LayoutPolicy.Resolve: %v", err)
	}
	if got != want {
		t.Fatalf("composition-root layout diverges from the policy:\n got %+v\nwant %+v", got, want)
	}
	// Spot-pin the red-line numbers at the wiring level too.
	if got.ModuleRegion.Addr != 0x12000000 || got.StubBase != 0x60000000 ||
		got.StackBase != 0xC0000000 || got.TLSBase != 0xD0000000 ||
		got.HeapRegion.Addr != 0x30000000 || got.MmapRegion.Addr != 0x40000000 {
		t.Fatalf("layout numbers drifted from the legacy boot geometry: %+v", got)
	}
}

// TestResolveLayoutUnknownPlatform: a Target whose platform has no bound
// LayoutPolicy must fail loudly at the composition root.
func TestResolveLayoutUnknownPlatform(t *testing.T) {
	tgt := &target.Target{
		Arch:     fakeArch{},
		Format:   loader.FormatELF,
		Platform: platform.ID(99),
		Variant:  arch.VariantGeneric,
	}
	if _, err := resolveLayout(tgt, platform.LayoutOverrides{}); err == nil {
		t.Fatal("unknown platform must error, not invent a layout")
	}
}
