package interpose

import (
	"errors"
	"strings"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
)

// stubBE is the minimal backend a StubManager needs: it records MemWrite
// bytes; everything else panics via the nil embedded interface.
type stubBE struct {
	emu.Backend
	writes map[emu.GuestAddr][]byte
}

func (b *stubBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	if b.writes == nil {
		b.writes = map[emu.GuestAddr][]byte{}
	}
	b.writes[addr] = append([]byte(nil), data...)
	return nil
}

// testEncoder emits a fixed 8-byte trampoline, like arm64's `svc #0; ret`.
type testEncoder struct{}

func (testEncoder) EmitStub(kind arch.StubKind) ([]byte, error) {
	if kind != arch.StubHostCall && kind != arch.StubUnresolved {
		return nil, errors.New("unknown kind")
	}
	return []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6}, nil
}

var testLayout = memory.Layout{
	ModuleBase: 0x12000000, ModuleSize: 0x1000000,
	StubBase: 0x60000000, StubSize: 0x1000,
	StackBase: 0xC0000000, StackSize: 0x1000,
	TLSBase: 0xD0000000, TLSSize: 0x1000,
}

func newTestStubManager(t *testing.T, l memory.Layout) (StubManager, *stubBE) {
	t.Helper()
	be := &stubBE{}
	return NewStubManager(memory.NewAddressSpace(l), testEncoder{}, be), be
}

func TestStubManagerAllocateLookup(t *testing.T) {
	m, be := newTestStubManager(t, testLayout)

	a1, err := m.Allocate(arch.StubUnresolved, "missing_import")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := m.Allocate(arch.StubHostCall, "host:strlen")
	if err != nil {
		t.Fatal(err)
	}
	if a1 != emu.GuestAddr(testLayout.StubBase) {
		t.Fatalf("first stub at %#x, want region base %#x", uint64(a1), testLayout.StubBase)
	}
	if a2 != a1+8 {
		t.Fatalf("second stub at %#x, want first+8 (%#x)", uint64(a2), uint64(a1)+8)
	}
	// trampoline bytes landed in guest memory
	if got := be.writes[a1]; len(got) != 8 || got[0] != 0x01 || got[3] != 0xd4 {
		t.Fatalf("stub bytes not written: % x", got)
	}
	// Lookup by trap-source address
	d, ok := m.Lookup(a1)
	if !ok || d.Name != "missing_import" || d.Kind != arch.StubUnresolved {
		t.Fatalf("Lookup(a1) = %+v,%v, want missing_import/StubUnresolved", d, ok)
	}
	if _, ok := m.Lookup(a1 + 4); ok {
		t.Fatal("Lookup must key on the stub's exact entry address, not mid-stub")
	}
	if _, ok := m.Lookup(0x12000000); ok {
		t.Fatal("Lookup must miss outside the stub table")
	}
}

func TestStubManagerHitCounts(t *testing.T) {
	m, _ := newTestStubManager(t, testLayout)
	a1, _ := m.Allocate(arch.StubUnresolved, "dup_name")
	a2, _ := m.Allocate(arch.StubUnresolved, "dup_name")

	// Lookup must NOT count; Hit counts by NAME (across addresses).
	if _, ok := m.Lookup(a1); !ok {
		t.Fatal("Lookup miss")
	}
	if got := m.Hits("dup_name"); got != 0 {
		t.Fatalf("Lookup must not count hits, got %d", got)
	}
	for i := 0; i < 2; i++ {
		if _, ok := m.Hit(a1); !ok {
			t.Fatal("Hit miss")
		}
	}
	if _, ok := m.Hit(a2); !ok {
		t.Fatal("Hit miss")
	}
	if got := m.Hits("dup_name"); got != 3 {
		t.Fatalf("Hits(dup_name) = %d, want 3 (counted by name across stubs)", got)
	}
	if _, ok := m.Hit(0xdead0000); ok {
		t.Fatal("Hit on an unknown address must report false")
	}
	if got := m.Hits("never_hit"); got != 0 {
		t.Fatalf("Hits(never_hit) = %d, want 0", got)
	}
}

func TestStubManagerRegionExhaustion(t *testing.T) {
	l := testLayout
	l.StubSize = 16 // exactly two 8-byte stubs
	m, _ := newTestStubManager(t, l)
	if _, err := m.Allocate(arch.StubUnresolved, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Allocate(arch.StubUnresolved, "b"); err != nil {
		t.Fatal(err)
	}
	_, err := m.Allocate(arch.StubUnresolved, "c")
	if err == nil {
		t.Fatal("third stub in a two-slot region must fail")
	}
	if !strings.Contains(err.Error(), "stub") {
		t.Fatalf("exhaustion error must name the stub region, got %v", err)
	}
	// a failed Allocate must not leave a phantom descriptor
	if _, ok := m.Lookup(emu.GuestAddr(l.StubBase + 16)); ok {
		t.Fatal("failed Allocate must not register a descriptor")
	}
}

func TestInterposeTable(t *testing.T) {
	tab := NewInterposeTable()
	f1 := func(CallContext) uint64 { return 1 }
	f2 := func(CallContext) uint64 { return 2 }

	tab.BindSymbol("add", f1)
	if h, ok := tab.LookupSymbol("add"); !ok || h(nil) != 1 {
		t.Fatal("BindSymbol/LookupSymbol round-trip failed")
	}
	if _, ok := tab.LookupSymbol("nope"); ok {
		t.Fatal("LookupSymbol must miss for unbound names")
	}

	addr := emu.GuestAddr(0x12345000)
	if err := tab.BindAddress(addr, f2); err != nil {
		t.Fatal(err)
	}
	if h, ok := tab.LookupAddress(addr); !ok || h(nil) != 2 {
		t.Fatal("BindAddress/LookupAddress round-trip failed")
	}
	if _, ok := tab.LookupAddress(addr + 4); ok {
		t.Fatal("LookupAddress must key on the exact entry address")
	}
	if err := tab.BindAddress(addr, f1); err == nil {
		t.Fatal("duplicate BindAddress on the same address must fail")
	}
	// the failed duplicate bind must not have displaced the original
	if h, ok := tab.LookupAddress(addr); !ok || h(nil) != 2 {
		t.Fatal("failed duplicate bind must keep the original HostFunc")
	}
}
