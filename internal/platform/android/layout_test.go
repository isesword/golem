package android

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

var arm64Caps = arch.AddressSpaceCaps{
	PointerBits: 64,
	VABits:      39,
	PageSize:    0x1000,
	MaxUserVA:   1 << 39,
}

// TestLayoutPolicyPinsLegacyNumbers is the behavior-invariant red line of
// P4c: the Android LayoutPolicy must reproduce, field by field, the exact
// guest address geometry the emulator booted with before P4c (the retired
// pre-P4c layout helper plus the heap/mmap boundaries New used to splice by
// hand from kernel.BrkBase / memory.MmapBase).
func TestLayoutPolicyPinsLegacyNumbers(t *testing.T) {
	l, err := LayoutPolicy{}.Resolve(
		platform.TargetInfo{Platform: platform.Android, Caps: arm64Caps},
		platform.LayoutOverrides{},
	)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// The pre-P4c constants, restated literally so this test fails if the
	// policy drifts from the historical numbers.
	want := memory.Layout{
		ModuleRegion: memory.Region{Addr: 0x12000000, Size: 0x1E000000},
		HeapRegion:   memory.Region{Addr: 0x30000000, Size: 0x10000000},
		MmapRegion:   memory.Region{Addr: 0x40000000, Size: 0x20000000},
		StubBase:     0x60000000,
		StubSize:     0x00100000,
		StackBase:    0xC0000000,
		StackSize:    0x00800000,
		TLSBase:      0xD0000000,
		TLSSize:      0x00010000,
	}
	if l != want {
		t.Fatalf("layout drifted from the legacy numbers:\n got %+v\nwant %+v", l, want)
	}

	// The heap/mmap bases must stay tied to the single definition sites the
	// pre-P4c code used: kernel.BrkBase and memory.MmapBase. And the regions
	// must tile contiguously: module window end == heap base == the address
	// where the old module-arena bump allocator collided with the heap
	// reservation; mmap window end == stub base == the old arena top
	// (ModuleBase+ModuleSize = 0x12000000+0x4E000000).
	if l.HeapRegion.Addr != kernel.BrkBase {
		t.Fatalf("heap base %#x != kernel.BrkBase %#x", l.HeapRegion.Addr, uint64(kernel.BrkBase))
	}
	if l.MmapRegion.Addr != memory.MmapBase {
		t.Fatalf("mmap base %#x != memory.MmapBase %#x", l.MmapRegion.Addr, uint64(memory.MmapBase))
	}
	if l.ModuleRegion.End() != l.HeapRegion.Addr ||
		l.HeapRegion.End() != l.MmapRegion.Addr ||
		l.MmapRegion.End() != l.StubBase {
		t.Fatalf("regions must tile [0x12000000, 0x60000000) contiguously, got module=%#x heap=%#x mmap=%#x stub=%#x",
			l.ModuleRegion.End(), l.HeapRegion.End(), l.MmapRegion.End(), l.StubBase)
	}
	// The retired ModuleSize shim's informal bound, for the record: the old
	// arena top equals the mmap window end.
	if got := uint64(0x12000000 + 0x4E000000); got != l.MmapRegion.End() {
		t.Fatalf("old arena top %#x != mmap window end %#x", got, l.MmapRegion.End())
	}
}

// TestLayoutPolicyZeroOverrides: the zero LayoutOverrides (platform defaults)
// is the only supported override value this stage, and the nil-equivalent
// path must produce the identical layout.
func TestLayoutPolicyZeroOverrides(t *testing.T) {
	info := platform.TargetInfo{Platform: platform.Android, Caps: arm64Caps}
	a, err := LayoutPolicy{}.Resolve(info, platform.LayoutOverrides{})
	if err != nil {
		t.Fatalf("Resolve zero overrides: %v", err)
	}
	b, err := LayoutPolicy{}.Resolve(info, platform.LayoutOverrides{})
	if err != nil {
		t.Fatalf("Resolve again: %v", err)
	}
	if a != b {
		t.Fatal("Resolve must be deterministic for zero overrides")
	}
}

// TestLayoutPolicyRejectsUnsupportedInputs: a policy must fail loudly on
// targets it cannot plan for — never invent a layout.
func TestLayoutPolicyRejectsUnsupportedInputs(t *testing.T) {
	p := LayoutPolicy{}
	if _, err := p.Resolve(platform.TargetInfo{Platform: platform.Darwin, Caps: arm64Caps}, platform.LayoutOverrides{}); err == nil {
		t.Fatal("non-Android platform must error")
	}
	caps32 := arch.AddressSpaceCaps{PointerBits: 32, VABits: 32, PageSize: 0x1000, MaxUserVA: 1 << 32}
	if _, err := p.Resolve(platform.TargetInfo{Platform: platform.Android, Caps: caps32}, platform.LayoutOverrides{}); err == nil {
		t.Fatal("32-bit caps must error")
	}
	caps16k := arch.AddressSpaceCaps{PointerBits: 64, VABits: 39, PageSize: 0x4000, MaxUserVA: 1 << 39}
	if _, err := p.Resolve(platform.TargetInfo{Platform: platform.Android, Caps: caps16k}, platform.LayoutOverrides{}); err == nil {
		t.Fatal("16K pages must error (layout assumes 4K)")
	}
}
