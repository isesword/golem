package memory

import (
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// testLayout mirrors the Android/AArch64 LayoutPolicy output numerically
// so these tests also pin the real region arithmetic: the module
// window, brk heap and mmap arena tile [0x12000000, 0x60000000) contiguously
// and abut the stub region.
var testLayout = Layout{
	ModuleRegion: Region{Addr: 0x12000000, Size: 0x1E000000},
	HeapRegion:   Region{Addr: 0x30000000, Size: 0x10000000},
	MmapRegion:   Region{Addr: 0x40000000, Size: 0x20000000},
	StubBase:     0x60000000,
	StubSize:     0x00100000,
	StackBase:    0xC0000000,
	StackSize:    0x00800000,
	TLSBase:      0xD0000000,
	TLSSize:      0x00010000,
}

func TestAddressSpaceBumpAlloc(t *testing.T) {
	as := NewAddressSpace(testLayout)

	m1, err := as.Alloc(PurposeModule, 0x200000+0x100000) // span + inter-module gap
	if err != nil {
		t.Fatal(err)
	}
	if uint64(m1) != testLayout.ModuleRegion.Addr {
		t.Fatalf("first module base = %#x, want %#x", uint64(m1), testLayout.ModuleRegion.Addr)
	}
	m2, err := as.Alloc(PurposeModule, 0x100000)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(m2) != testLayout.ModuleRegion.Addr+0x300000 {
		t.Fatalf("second module base = %#x, want %#x", uint64(m2), testLayout.ModuleRegion.Addr+0x300000)
	}

	s1, err := as.Alloc(PurposeStub, 8)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(s1) != testLayout.StubBase {
		t.Fatalf("first stub = %#x, want %#x", uint64(s1), testLayout.StubBase)
	}
	s2, err := as.Alloc(PurposeStub, 8)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(s2) != testLayout.StubBase+8 {
		t.Fatalf("second stub = %#x, want %#x", uint64(s2), testLayout.StubBase+8)
	}

	if got, want := as.Used(PurposeModule), uint64(0x400000); got != want {
		t.Fatalf("module used = %#x, want %#x", got, want)
	}
	if got, want := as.Remaining(PurposeStub), testLayout.StubSize-16; got != want {
		t.Fatalf("stub remaining = %#x, want %#x", got, want)
	}
}

func TestAddressSpaceAllocExhaustion(t *testing.T) {
	as := NewAddressSpace(testLayout)
	// The module window ends exactly at the heap region (ModuleRegion
	// semantics): an allocation that would cross ModuleRegion.End must fail,
	// not spill into the heap — even before anything is reserved.
	mw := testLayout.ModuleRegion
	if _, err := as.Alloc(PurposeModule, mw.Size+1); err == nil {
		t.Fatal("module alloc past the window bound must fail")
	}
	if _, err := as.Alloc(PurposeModule, mw.Size); err != nil {
		t.Fatalf("module alloc filling the window exactly must succeed: %v", err)
	}
	if _, err := as.Alloc(PurposeModule, 1); err == nil {
		t.Fatal("module alloc past a full window must fail")
	}
	// Stub region exhaustion.
	if _, err := as.Alloc(PurposeStub, testLayout.StubSize); err != nil {
		t.Fatal(err)
	}
	if _, err := as.Alloc(PurposeStub, 8); err == nil {
		t.Fatal("stub alloc past region end must fail")
	}
}

// TestAddressSpaceModuleWindowIsTight pins the ModuleRegion semantics:
// the module bump window ends at the heap base, so the exhaustion check
// fires at exactly the address where the legacy arena would have collided
// with the heap reservation — same boundary, now explicit region data.
func TestAddressSpaceModuleWindowIsTight(t *testing.T) {
	as := NewAddressSpace(testLayout)
	mw := testLayout.ModuleRegion
	if mw.End() != testLayout.HeapRegion.Addr {
		t.Fatalf("module window end %#x must abut the heap region at %#x", mw.End(), testLayout.HeapRegion.Addr)
	}
	if _, err := as.Alloc(PurposeModule, mw.Size-0x1000); err != nil {
		t.Fatal(err)
	}
	if _, err := as.Alloc(PurposeModule, 0x2000); err == nil {
		t.Fatal("module alloc crossing the window end must fail (exhaustion, not collision)")
	}
	if _, err := as.Alloc(PurposeModule, 0x1000); err != nil {
		t.Fatalf("module alloc ending exactly at the window end must succeed: %v", err)
	}
	if got := as.Used(PurposeModule); got != mw.Size {
		t.Fatalf("module used = %#x, want full window %#x", got, mw.Size)
	}
}

func TestAddressSpaceRegionIsolation(t *testing.T) {
	as := NewAddressSpace(testLayout)
	// Module allocations never land in the stub/stack/tls regions even across
	// many bumps: the bump cursor is confined to its own area.
	for i := 0; i < 16; i++ {
		a, err := as.Alloc(PurposeModule, 0x100000)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(a) < testLayout.ModuleRegion.Addr || uint64(a) >= testLayout.ModuleRegion.End() {
			t.Fatalf("module alloc %#x escaped its region", uint64(a))
		}
		if uint64(a) >= testLayout.StubBase && uint64(a) < testLayout.StubBase+testLayout.StubSize {
			t.Fatalf("module alloc %#x landed in the stub region", uint64(a))
		}
	}
	// Alloc on a purpose with no bump region (heap/mmap/guard are Reserve-only
	// this stage) must fail rather than invent an address.
	for _, p := range []Purpose{PurposeHeap, PurposeMmap, PurposeGuard} {
		if _, err := as.Alloc(p, 0x1000); err == nil {
			t.Fatalf("alloc %s: expected no-region error", p)
		}
	}
}

func TestAddressSpaceReserveConflicts(t *testing.T) {
	as := NewAddressSpace(testLayout)
	if err := as.Reserve(emu.GuestAddr(testLayout.StackBase), testLayout.StackSize, PurposeStack); err != nil {
		t.Fatal(err)
	}
	if err := as.Reserve(emu.GuestAddr(testLayout.TLSBase), testLayout.TLSSize, PurposeTLS); err != nil {
		t.Fatal(err)
	}
	// Overlapping an existing reservation must fail — even a single byte.
	if err := as.Reserve(emu.GuestAddr(testLayout.StackBase+testLayout.StackSize-1), 0x2000, PurposeGuard); err == nil {
		t.Fatal("reserve overlapping the stack reservation must fail")
	}
	if err := as.Reserve(emu.GuestAddr(testLayout.TLSBase), 0x1000, PurposeTLS); err == nil {
		t.Fatal("re-reserving the TLS range must fail")
	}
	// Zero size and wrap-around are rejected.
	if err := as.Reserve(emu.GuestAddr(0x50000000), 0, PurposeGuard); err == nil {
		t.Fatal("zero-size reserve must fail")
	}
	if err := as.Reserve(emu.GuestAddr(^uint64(0)-0xfff), 0x2000, PurposeGuard); err == nil {
		t.Fatal("wrapping reserve must fail")
	}
	// A non-overlapping guard page succeeds.
	if err := as.Reserve(emu.GuestAddr(testLayout.StackBase-0x1000), 0x1000, PurposeGuard); err != nil {
		t.Fatal(err)
	}
	if n := len(as.Reservations()); n != 3 {
		t.Fatalf("reservations = %d, want 3", n)
	}
}

func TestAddressSpaceReservedSubArenasBlockBump(t *testing.T) {
	as := NewAddressSpace(testLayout)
	// Register the brk heap and mmap arena from the Layout's region data,
	// exactly as the emulator does at boot (no boundary arithmetic at
	// the call site).
	if err := as.Reserve(emu.GuestAddr(testLayout.HeapRegion.Addr), testLayout.HeapRegion.Size, PurposeHeap); err != nil {
		t.Fatal(err)
	}
	if err := as.Reserve(emu.GuestAddr(testLayout.MmapRegion.Addr), testLayout.MmapRegion.Size, PurposeMmap); err != nil {
		t.Fatal(err)
	}
	// The module bump must refuse to plow into the registered heap range
	// instead of silently overlapping it. The module window already ends at
	// the heap base, so this is the exhaustion boundary wearing a second hat.
	a, err := as.Alloc(PurposeModule, testLayout.HeapRegion.Addr-testLayout.ModuleRegion.Addr+0x1000)
	if err == nil {
		t.Fatalf("module alloc crossing the heap reservation must fail, got %#x", uint64(a))
	}
	// An allocation that stops just short of the reservation is fine.
	if _, err := as.Alloc(PurposeModule, testLayout.HeapRegion.Addr-testLayout.ModuleRegion.Addr); err != nil {
		t.Fatalf("module alloc up to the heap reservation must succeed: %v", err)
	}
	// The next bump now sits exactly at the heap boundary and must fail.
	if _, err := as.Alloc(PurposeModule, 0x1000); err == nil {
		t.Fatal("module alloc at the heap boundary must fail")
	}
}

func TestAddressSpaceAreas(t *testing.T) {
	as := NewAddressSpace(testLayout)
	base, size, ok := as.Area(PurposeStack)
	if !ok || base != testLayout.StackBase || size != testLayout.StackSize {
		t.Fatalf("stack area = %#x+%#x ok=%v", base, size, ok)
	}
	base, size, ok = as.Area(PurposeModule)
	if !ok || base != testLayout.ModuleRegion.Addr || size != testLayout.ModuleRegion.Size {
		t.Fatalf("module area = %#x+%#x ok=%v", base, size, ok)
	}
	if _, _, ok := as.Area(PurposeHeap); ok {
		t.Fatal("heap must have no bump area")
	}
	if as.Layout() != testLayout {
		t.Fatal("Layout() must round-trip the construction layout")
	}
}
