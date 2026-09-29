package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

func darwinTarget() platform.TargetInfo {
	return platform.TargetInfo{
		Platform: platform.Darwin,
		Caps:     arch.AddressSpaceCaps{PointerBits: 64, PageSize: memory.PageSize},
	}
}

// TestLayoutGeometry pins the Darwin address-space geometry — deliberately
// NOT the Android one (module 0x40000000 vs Android's 0x12000000, stack
// 0xB0000000 vs 0xC0000000, TLS 0xE0000000 vs 0xD0000000): a second platform
// proves the seam by choosing its own numbers.
func TestLayoutGeometry(t *testing.T) {
	l, err := LayoutPolicy{}.Resolve(darwinTarget(), platform.LayoutOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	want := memory.Layout{
		ModuleRegion: memory.Region{Addr: 0x40000000, Size: 0x10000000},
		HeapRegion:   memory.Region{Addr: 0x50000000, Size: 0x10000000},
		MmapRegion:   memory.Region{Addr: 0x60000000, Size: 0x10000000},
		StubBase:     0x70000000, StubSize: 0x100000,
		StackBase:    0xB0000000, StackSize: 0x800000,
		TLSBase:      0xE0000000, TLSSize: 0x10000,
	}
	if l != want {
		t.Fatalf("layout = %+v, want %+v", l, want)
	}
	// Disjointness: module/heap/mmap tile contiguously and end at the stubs;
	// stack and TLS sit clear above.
	if l.ModuleRegion.End() != l.HeapRegion.Addr || l.HeapRegion.End() != l.MmapRegion.Addr || l.MmapRegion.End() != l.StubBase {
		t.Fatal("module/heap/mmap windows must tile [0x40000000, 0x70000000) contiguously")
	}
	if l.StackBase < l.StubBase+l.StubSize || l.TLSBase < l.StackBase+l.StackSize {
		t.Fatal("stub/stack/TLS windows overlap")
	}
}

func TestLayoutRejectsForeignPlatform(t *testing.T) {
	tgt := darwinTarget()
	tgt.Platform = platform.Android
	if _, err := (LayoutPolicy{}).Resolve(tgt, platform.LayoutOverrides{}); err == nil {
		t.Fatal("planning an Android target with the Darwin policy must error")
	}
}

func TestLayoutRejectsBadCaps(t *testing.T) {
	for _, caps := range []arch.AddressSpaceCaps{
		{PointerBits: 32, PageSize: memory.PageSize},
		{PointerBits: 64, PageSize: 0x4000},
	} {
		tgt := darwinTarget()
		tgt.Caps = caps
		if _, err := (LayoutPolicy{}).Resolve(tgt, platform.LayoutOverrides{}); err == nil {
			t.Fatalf("caps %+v must be rejected", caps)
		}
	}
}
