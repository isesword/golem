package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
)

// TestResolveLayoutMatchesAndroidPolicy pins the P4c/P5b.5 composition-root
// wiring: the layout New boots with must be exactly what the bound Runtime's
// LayoutPolicy resolves for the Target — the numbers of the retired pre-P4c
// layout helper, carried by the policy, with zero user overrides. The policy
// now reaches the composition root through the platform registry: resolve
// the factory for the probed platform, Bind, consume Runtime.Layout.
func TestResolveLayoutMatchesAndroidPolicy(t *testing.T) {
	tgt, err := resolveTarget(Config{})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	factory, err := platform.Resolve(tgt.Platform)
	if err != nil {
		t.Fatalf("platform.Resolve: %v", err)
	}
	rt, err := factory.Bind(platform.BindContext{ArchID: tgt.ID})
	if err != nil {
		t.Fatalf("factory.Bind: %v", err)
	}
	got, err := rt.Layout.Resolve(
		platform.TargetInfo{Platform: tgt.Platform, Caps: tgt.Arch.Caps()},
		platform.LayoutOverrides{},
	)
	if err != nil {
		t.Fatalf("Runtime.Layout.Resolve: %v", err)
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

// TestResolveLayoutUnknownPlatform: a Target whose platform has no
// registered factory fails loudly at the composition root's platform.Resolve
// (P5b.5) — before any layout is planned.
func TestResolveLayoutUnknownPlatform(t *testing.T) {
	if _, err := platform.Resolve(platform.ID(99)); err == nil {
		t.Fatal("unknown platform must error, not invent a layout")
	}
}
