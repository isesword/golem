package interpose

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
)

// .5 HostResolver / UnresolvedStubResolver tests (DESIGN.md §3.8): the
// interpose→loader adapter contract — host symbol → stub guest address with
// Kind SymbolHostStub, stub reuse across repeated resolutions, decline on
// unbound names, and the weak-undefined ELF rule in the terminal fallback.

func newResolverFixture(t *testing.T) (*HostResolver, *UnresolvedStubResolver, InterposeTable, *memory.AddressSpace) {
	t.Helper()
	as := memory.NewAddressSpace(testLayout)
	stubs := NewStubManager(as, testEncoder{}, &stubBE{})
	tab := NewInterposeTable()
	return NewHostResolver(tab, stubs), NewUnresolvedStubResolver(stubs), tab, as
}

// Test ④: a host-bound symbol resolves to a stub guest address with Kind
// SymbolHostStub; the ResolvedSymbol carries no host callable (the type has
// no such field — this test asserts the observable contract).
func TestHostResolverResolvesBoundSymbol(t *testing.T) {
	hr, _, tab, _ := newResolverFixture(t)
	tab.BindSymbol("strlen", func(CallContext) uint64 { return 0 })

	rs, err := hr.Resolve(loader.ResolveRequest{Name: "strlen", Binding: loader.SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Kind != loader.SymbolHostStub {
		t.Fatalf("kind = %s, want host-stub", rs.Kind)
	}
	if rs.Addr == 0 || rs.Image != nil {
		t.Fatalf("addr=%#x image=%v, want a stub address with no image", uint64(rs.Addr), rs.Image)
	}
	if uint64(rs.Addr) < testLayout.StubBase || uint64(rs.Addr) >= testLayout.StubBase+testLayout.StubSize {
		t.Fatalf("addr %#x outside the stub region", uint64(rs.Addr))
	}

	// An unbound name declines with ErrSymbolUnresolved (the chain moves on).
	_, err = hr.Resolve(loader.ResolveRequest{Name: "unbound"})
	if !errors.Is(err, loader.ErrSymbolUnresolved) {
		t.Fatalf("unbound name must decline with ErrSymbolUnresolved, got %v", err)
	}
}

// Test ⑥: the same host symbol resolved 20 times (as 20 relocation
// references would) reuses ONE stub address — the AddressSpace stub region
// consumes exactly one slot.
func TestHostResolverStubReuse(t *testing.T) {
	hr, _, tab, as := newResolverFixture(t)
	tab.BindSymbol("getauxval", func(CallContext) uint64 { return 0 })

	first, err := hr.Resolve(loader.ResolveRequest{Name: "getauxval"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 19; i++ {
		rs, err := hr.Resolve(loader.ResolveRequest{Name: "getauxval"})
		if err != nil {
			t.Fatal(err)
		}
		if rs.Addr != first.Addr {
			t.Fatalf("resolution %d got %#x, want reused stub %#x", i+2, uint64(rs.Addr), uint64(first.Addr))
		}
	}
	if used := as.Used(memory.PurposeStub); used != 8 {
		t.Fatalf("stub region consumed %d bytes for 20 resolutions of one symbol, want 8 (one slot)", used)
	}

	// A different symbol gets its own slot.
	if _, err := hr.Resolve(loader.ResolveRequest{Name: "other"}); !errors.Is(err, loader.ErrSymbolUnresolved) {
		t.Fatalf("unbound: %v", err)
	}
	tab.BindSymbol("other", func(CallContext) uint64 { return 1 })
	if _, err := hr.Resolve(loader.ResolveRequest{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if used := as.Used(memory.PurposeStub); used != 16 {
		t.Fatalf("two host symbols want 2 slots (16 bytes), got %d", used)
	}
}

// Test ③: weak undefined resolves to address 0 WITHOUT error and WITHOUT
// consuming a stub slot (ELF semantics); a strong unresolved symbol still
// gets the documented lenient fallback stub (golem's historical semantics —
// kept deliberately, see DESIGN.md §6 notes), deduped by name.
func TestUnresolvedStubResolverWeakVsStrong(t *testing.T) {
	_, fr, _, as := newResolverFixture(t)

	rs, err := fr.Resolve(loader.ResolveRequest{Name: "weak_opt", Binding: loader.SymbolBindingWeak})
	if err != nil {
		t.Fatalf("weak undefined must not error: %v", err)
	}
	if rs.Addr != 0 {
		t.Fatalf("weak undefined resolved to %#x, want 0 (ELF)", uint64(rs.Addr))
	}
	if used := as.Used(memory.PurposeStub); used != 0 {
		t.Fatalf("weak undefined must not consume a stub slot, used %d bytes", used)
	}

	rs, err = fr.Resolve(loader.ResolveRequest{Name: "strong_missing", Binding: loader.SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Addr == 0 || rs.Kind != loader.SymbolUnresolvedStub {
		t.Fatalf("strong unresolved = %+v, want an unresolved-stub address", rs)
	}
	// Same name again → same stub (one slot per unresolved import).
	rs2, err := fr.Resolve(loader.ResolveRequest{Name: "strong_missing", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs2.Addr != rs.Addr {
		t.Fatalf("re-resolve = %+v, %v; want same stub %#x", rs2, err, uint64(rs.Addr))
	}
	if used := as.Used(memory.PurposeStub); used != 8 {
		t.Fatalf("one unresolved import must consume one slot (8 bytes), got %d", used)
	}
}

// Chain integration: host replacement wins over the guest global scope, the
// guest scope wins over the fallback — the boot order, assembled exactly the
// way the emulator wires it.
func TestBootChainOrder(t *testing.T) {
	hr, fr, tab, _ := newResolverFixture(t)
	dl := loader.NewDynamicLinker()
	dl.AddModule("libc.so", &loader.Image{Exports: map[string]uint64{"strlen": 0x500}}, 0x10000000)

	chain := loader.ChainResolvers(hr, dl.GlobalResolver(), fr)

	// strlen: exported by libc AND host-bound → host stub wins.
	tab.BindSymbol("strlen", func(CallContext) uint64 { return 0 })
	rs, err := chain.Resolve(loader.ResolveRequest{Name: "strlen", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Kind != loader.SymbolHostStub {
		t.Fatalf("host-bound export = %+v, %v; want host-stub (host wins)", rs, err)
	}

	// A guest-only export resolves from the global scope.
	dl.AddModule("libfoo.so", &loader.Image{Exports: map[string]uint64{"foo": 0x40}}, 0x20000000)
	rs, err = chain.Resolve(loader.ResolveRequest{Name: "foo", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Kind != loader.SymbolGuest || rs.Addr != 0x20000040 {
		t.Fatalf("guest export = %+v, %v; want guest 0x20000040", rs, err)
	}

	// Unknown strong → fallback stub; unknown weak → 0.
	rs, err = chain.Resolve(loader.ResolveRequest{Name: "unknown", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Kind != loader.SymbolUnresolvedStub || rs.Addr == 0 {
		t.Fatalf("unknown strong = %+v, %v; want unresolved-stub", rs, err)
	}
	rs, err = chain.Resolve(loader.ResolveRequest{Name: "unknown_weak", Binding: loader.SymbolBindingWeak})
	if err != nil || rs.Addr != 0 {
		t.Fatalf("unknown weak = %+v, %v; want 0", rs, err)
	}
}

// Compile-time assertion: both adapters satisfy the consumer-owned contract.
var (
	_ loader.SymbolResolver = (*HostResolver)(nil)
	_ loader.SymbolResolver = (*UnresolvedStubResolver)(nil)
)
