package interpose

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// HostResolver is the interpose→loader adapter (DESIGN.md §3.8, P3.5): it
// implements loader.SymbolResolver over the InterposeTable, so a symbol bound
// via BindSymbol resolves to a StubManager-materialized guest trampoline. The
// host callable itself never crosses the boundary — ResolvedSymbol carries
// only the guest address and Kind SymbolHostStub.
//
// Stub reuse: the FIRST resolution of a host symbol allocates its trampoline;
// every later resolution of the same name returns the SAME guest address, so
// N relocations against one host import consume exactly one stub slot. (The
// StubManager stays a plain bump allocator — dedup lives here, keyed by
// symbol name, because the manager also serves JNI table slots where
// per-slot identity matters.)
type HostResolver struct {
	tab   InterposeTable
	stubs StubManager
	bound map[string]emu.GuestAddr // symbol name -> materialized stub
}

// NewHostResolver adapts tab+stubs to a loader.SymbolResolver.
func NewHostResolver(tab InterposeTable, stubs StubManager) *HostResolver {
	return &HostResolver{tab: tab, stubs: stubs, bound: map[string]emu.GuestAddr{}}
}

// Resolve implements loader.SymbolResolver: InterposeTable.LookupSymbol hit →
// materialize (once) via StubManager.Allocate(StubHostCall) → ResolvedSymbol
// with Kind SymbolHostStub. A miss declines with loader.ErrSymbolUnresolved
// so the chain moves on to the guest global scope.
func (r *HostResolver) Resolve(req loader.ResolveRequest) (loader.ResolvedSymbol, error) {
	if _, ok := r.tab.LookupSymbol(req.Name); !ok {
		return loader.ResolvedSymbol{}, fmt.Errorf("interpose: no host binding for %q: %w", req.Name, loader.ErrSymbolUnresolved)
	}
	if a, ok := r.bound[req.Name]; ok {
		return loader.ResolvedSymbol{Addr: a, Kind: loader.SymbolHostStub}, nil
	}
	a, err := r.stubs.Allocate(arch.StubHostCall, "host:"+req.Name)
	if err != nil {
		return loader.ResolvedSymbol{}, fmt.Errorf("interpose: host stub for %q: %w", req.Name, err)
	}
	r.bound[req.Name] = a
	return loader.ResolvedSymbol{Addr: a, Kind: loader.SymbolHostStub}, nil
}

// UnresolvedStubResolver is the documented TERMINAL resolver of the boot
// chain — it never declines, so it must come last. It preserves golem's
// historical lenient semantics for strong imports no resolver claimed: a
// StubUnresolved trampoline (traps at call time, counts the hit by name,
// returns an optimistic 0), NOT a hard resolution error. The one ELF rule it
// adds is weak-undefined: a WEAK symbol nobody resolved binds to address 0
// without error and without consuming a stub slot (ELF semantics — the guest
// null-checks weak symbols before calling them).
//
// Like HostResolver it dedups by name: N relocations against the same
// unresolved import share one stub slot (pre-P3.5 each relocation allocated
// its own).
type UnresolvedStubResolver struct {
	stubs StubManager
	bound map[string]emu.GuestAddr
}

// NewUnresolvedStubResolver returns the terminal fallback resolver.
func NewUnresolvedStubResolver(stubs StubManager) *UnresolvedStubResolver {
	return &UnresolvedStubResolver{stubs: stubs, bound: map[string]emu.GuestAddr{}}
}

// Resolve implements loader.SymbolResolver.
func (r *UnresolvedStubResolver) Resolve(req loader.ResolveRequest) (loader.ResolvedSymbol, error) {
	if req.Binding == loader.SymbolBindingWeak {
		// ELF: an unresolved weak undefined symbol is 0, no error.
		return loader.ResolvedSymbol{Addr: 0, Kind: loader.SymbolGuest}, nil
	}
	if a, ok := r.bound[req.Name]; ok {
		return loader.ResolvedSymbol{Addr: a, Kind: loader.SymbolUnresolvedStub}, nil
	}
	a, err := r.stubs.Allocate(arch.StubUnresolved, req.Name)
	if err != nil {
		return loader.ResolvedSymbol{}, fmt.Errorf("interpose: unresolved stub for %q: %w", req.Name, err)
	}
	r.bound[req.Name] = a
	return loader.ResolvedSymbol{Addr: a, Kind: loader.SymbolUnresolvedStub}, nil
}
