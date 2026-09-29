package loader

import (
	"errors"
	"strings"
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// P3.5 resolver-chain tests (DESIGN.md §3.3). The three canonical chain
// elements live in loader (DynamicLinker.GlobalResolver) and interpose
// (HostResolver / UnresolvedStubResolver); these tests pin the contract the
// composition root relies on: chain ORDER, the ErrSymbolUnresolved decline
// protocol, guest strong → guest address, missing strong → error at the
// scope level, and the weak/global binding reaching the resolver.

func exportImage(exports map[string]uint64) *Image {
	return &Image{Path: "test.so", Format: FormatELF, Exports: exports}
}

func TestDynamicLinkerGlobalScopeFirstWins(t *testing.T) {
	dl := NewDynamicLinker()
	dl.AddModule("libc.so", exportImage(map[string]uint64{"memcpy": 0x100, "strlen": 0x200}), 0x10000000)
	dl.AddModule("libfoo.so", exportImage(map[string]uint64{"memcpy": 0x9000, "foo": 0x300}), 0x20000000)

	// First-loaded definition wins (historical e.syms semantics).
	if a, ok := dl.LookupGlobal("memcpy"); !ok || a != 0x10000100 {
		t.Fatalf("memcpy = %#x,%v, want 0x10000100 (libc first-wins)", uint64(a), ok)
	}
	if a, ok := dl.LookupGlobal("foo"); !ok || a != 0x20000300 {
		t.Fatalf("foo = %#x,%v, want 0x20000300", uint64(a), ok)
	}
	if _, ok := dl.LookupGlobal("nope"); ok {
		t.Fatal("phantom global")
	}
	if len(dl.Modules()) != 2 || dl.Modules()[0].Name != "libc.so" {
		t.Fatalf("module graph order broken: %+v", dl.Modules())
	}
}

// Test ①: a guest strong symbol resolves to the correct guest address, as
// SymbolGuest with the defining image attached.
func TestGlobalResolverGuestStrongSymbol(t *testing.T) {
	dl := NewDynamicLinker()
	img := exportImage(map[string]uint64{"JNI_OnLoad": 0x400})
	dl.AddModule("libfoo.so", img, 0x20000000)

	rs, err := dl.GlobalResolver().Resolve(ResolveRequest{Name: "JNI_OnLoad", Binding: SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Addr != 0x20000400 || rs.Kind != SymbolGuest || rs.Image != img {
		t.Fatalf("got %+v, want addr 0x20000400 kind guest image libfoo.so", rs)
	}
}

// Test ②: a guest missing STRONG symbol is a resolution ERROR at the scope
// level (wrapping ErrSymbolUnresolved) — not a silent fallback. (The boot
// chain's documented leniency is an explicit LAST resolver, tested in
// interpose; a scope-only chain must fail loudly.)
func TestGlobalResolverMissingStrongIsError(t *testing.T) {
	dl := NewDynamicLinker()
	dl.AddModule("libfoo.so", exportImage(nil), 0x20000000)

	_, err := dl.GlobalResolver().Resolve(ResolveRequest{Name: "missing", Binding: SymbolBindingGlobal})
	if err == nil {
		t.Fatal("missing strong symbol must be an error")
	}
	if !errors.Is(err, ErrSymbolUnresolved) {
		t.Fatalf("error must wrap ErrSymbolUnresolved, got %v", err)
	}
}

func TestChainResolversOrderAndDecline(t *testing.T) {
	calls := []string{}
	mk := func(tag string, rs ResolvedSymbol, err error) SymbolResolver {
		return ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
			calls = append(calls, tag)
			return rs, err
		})
	}
	decline := ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
		calls = append(calls, "decline")
		return ResolvedSymbol{}, ErrSymbolUnresolved
	})

	// First hit wins; later resolvers are not consulted.
	c := ChainResolvers(decline, mk("hit", ResolvedSymbol{Addr: 0x42}, nil), mk("never", ResolvedSymbol{}, nil))
	rs, err := c.Resolve(ResolveRequest{Name: "x"})
	if err != nil || rs.Addr != 0x42 {
		t.Fatalf("chain resolve = %+v, %v", rs, err)
	}
	if strings.Join(calls, ",") != "decline,hit" {
		t.Fatalf("chain order = %v, want [decline hit]", calls)
	}

	// A non-decline error aborts the chain.
	boom := errors.New("boom")
	calls = nil
	c = ChainResolvers(mk("bad", ResolvedSymbol{}, boom), mk("never", ResolvedSymbol{}, nil))
	if _, err := c.Resolve(ResolveRequest{Name: "x"}); !errors.Is(err, boom) {
		t.Fatalf("non-decline error must abort the chain, got %v", err)
	}

	// All decline → error wrapping ErrSymbolUnresolved naming the symbol.
	c = ChainResolvers(decline)
	if _, err := c.Resolve(ResolveRequest{Name: "ghost"}); !errors.Is(err, ErrSymbolUnresolved) {
		t.Fatalf("exhausted chain must wrap ErrSymbolUnresolved, got %v", err)
	}

	// nil elements are skipped.
	if _, err := ChainResolvers(nil, nil).Resolve(ResolveRequest{Name: "x"}); err == nil {
		t.Fatal("empty chain must fail")
	}
}

// SymValue plumbing: defined symbols bypass the resolver (base+value);
// undefined ones reach it with Binding/Visibility carried through from the
// Sym (the weak/global distinction the fallback resolver acts on).
func TestSymValueCarriesBindingAndVisibility(t *testing.T) {
	img := &Image{
		Syms: []Sym{
			{}, // index 0 placeholder
			{Name: "local_fn", Value: 0x800, Bind: 0 /* STB_LOCAL */},
			{Name: "weak_imp", Undef: true, Bind: 2 /* STB_WEAK */, Visibility: SymbolVisibilityHidden},
		},
	}
	const base = 0x40000000

	// Defined: resolver must NOT be consulted.
	v, err := img.SymValue(1, base, nil)
	if err != nil || v != base+0x800 {
		t.Fatalf("defined sym = %#x, %v; want %#x", v, err, base+0x800)
	}

	var gotReq ResolveRequest
	res := ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
		gotReq = req
		return ResolvedSymbol{Addr: emu.GuestAddr(0xee00), Kind: SymbolHostStub}, nil
	})
	v, err = img.SymValue(2, base, res)
	if err != nil || v != 0xee00 {
		t.Fatalf("undef sym = %#x, %v; want 0xee00", v, err)
	}
	if gotReq.Name != "weak_imp" || gotReq.Binding != SymbolBindingWeak ||
		gotReq.Visibility != SymbolVisibilityHidden || gotReq.Requester != img {
		t.Fatalf("resolver saw %+v, want name/binding/visibility/requester carried through", gotReq)
	}

	// Resolver failure surfaces as an unresolved-import error.
	nores := ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
		return ResolvedSymbol{}, ErrSymbolUnresolved
	})
	if _, err := img.SymValue(2, base, nores); err == nil ||
		!strings.Contains(err.Error(), `unresolved import "weak_imp" (weak)`) {
		t.Fatalf("want unresolved-import error naming binding, got %v", err)
	}
	if _, err := img.SymValue(2, base, nil); err == nil {
		t.Fatal("undef sym with nil resolver must error")
	}
	if _, err := img.SymValue(99, base, nil); err == nil {
		t.Fatal("out-of-range sym index must error")
	}
}
