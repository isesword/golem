package loader

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Symbol resolution, a first-class loader component (DESIGN.md §3.3).
//
// The loader owns the RESOLUTION CONTRACT (consumer-owned interface): who
// asks (Requester), what is asked for (Name/Version/Binding/Visibility), and
// what comes back — a guest-visible address, never a host callable. Host
// function bodies stay behind StubManager-materialized guest addresses;
// ResolvedSymbol deliberately carries no HostFunc, so guest symbols and
// host-interposed symbols are indistinguishable to the Relocator (both are
// just guest VAs).
//
// The resolver CHAIN composes the emulator's historical resolution order
// (host replacement symbols → global guest exports → unresolved fallback)
// out of small single-purpose resolvers instead of an if-else in the
// composition root. dlopen/lazy binding/version resolution are NOT
// implemented (YAGNI); the request shape reserves room for them.

// ErrSymbolUnresolved marks "this resolver does not know the symbol" — the
// chain moves on to the next resolver. Any OTHER error aborts resolution.
var ErrSymbolUnresolved = errors.New("loader: symbol unresolved")

// SymbolBinding is the format-agnostic binding vocabulary (ELF STB_* values;
// other formats map onto the closest equivalent, same convention as Sym.Bind).
// The weak/global distinction is load-bearing: a WEAK undefined symbol that no
// resolver claims resolves to address 0 WITHOUT error (ELF semantics), while a
// strong (GLOBAL) undefined symbol that survives the whole chain is an error —
// unless the chain ends in an explicit fallback resolver (see below).
type SymbolBinding uint8

const (
	SymbolBindingLocal  SymbolBinding = 0 // ELF STB_LOCAL
	SymbolBindingGlobal SymbolBinding = 1 // ELF STB_GLOBAL
	SymbolBindingWeak   SymbolBinding = 2 // ELF STB_WEAK
)

func (b SymbolBinding) String() string {
	switch b {
	case SymbolBindingLocal:
		return "local"
	case SymbolBindingGlobal:
		return "global"
	case SymbolBindingWeak:
		return "weak"
	}
	return fmt.Sprintf("binding(%d)", int(b))
}

// SymbolVisibility is the format-agnostic visibility vocabulary (ELF STV_*).
// Reserved for the versioned/Scoped resolution Android will need; no resolver
// consumes it yet.
type SymbolVisibility uint8

const (
	SymbolVisibilityDefault   SymbolVisibility = 0 // ELF STV_DEFAULT
	SymbolVisibilityInternal  SymbolVisibility = 1 // ELF STV_INTERNAL
	SymbolVisibilityHidden    SymbolVisibility = 2 // ELF STV_HIDDEN
	SymbolVisibilityProtected SymbolVisibility = 3 // ELF STV_PROTECTED
)

// SymbolKind says WHAT a resolved address points at. The Relocator treats all
// kinds identically (a guest VA is a guest VA); the kind exists for
// diagnostics, tests, and future policy (e.g. lazy binding).
type SymbolKind uint8

const (
	// SymbolGuest is a symbol defined by a loaded guest Image — or the null
	// result of a weak undefined symbol (Addr 0, Image nil).
	SymbolGuest SymbolKind = iota
	// SymbolHostStub is a host-interposed symbol materialized as a guest
	// trampoline by the StubManager. The host callable behind it is invisible
	// to the loader by construction.
	SymbolHostStub
	// SymbolUnresolvedStub is the fallback placeholder for a strong import no
	// resolver claimed (golem's documented lenient semantics: a stub that
	// traps and returns an optimistic 0, NOT an error).
	SymbolUnresolvedStub
)

func (k SymbolKind) String() string {
	switch k {
	case SymbolGuest:
		return "guest"
	case SymbolHostStub:
		return "host-stub"
	case SymbolUnresolvedStub:
		return "unresolved-stub"
	}
	return fmt.Sprintf("kind(%d)", int(k))
}

// Binding maps the symbol's format-native binding (Sym.Bind keeps the ELF
// vocabulary) onto the format-agnostic SymbolBinding.
func (s Sym) Binding() SymbolBinding {
	switch s.Bind {
	case elf.STB_LOCAL:
		return SymbolBindingLocal
	case elf.STB_WEAK:
		return SymbolBindingWeak
	default:
		return SymbolBindingGlobal
	}
}

// ResolveRequest is one symbol resolution query. Version/Visibility are
// reserved dimensions (symbol versioning, scoped lookup): carried, currently
// unconsumed. Requester is the importing Image (scope/DT_NEEDED-order
// resolution hooks for later; global-scope resolvers may ignore it).
type ResolveRequest struct {
	Requester  *Image
	Name       string
	Version    string // reserved; empty today
	Binding    SymbolBinding
	Visibility SymbolVisibility
}

// ResolvedSymbol is the resolution result: a guest-visible address plus what
// it points at. It NEVER carries a host callable — host functions materialize
// into guest stub addresses upstream (interpose.StubManager), so this struct
// is all a Relocator ever sees.
type ResolvedSymbol struct {
	Addr  emu.GuestAddr
	Size  uint64
	Image *Image     // defining image; nil for host stubs and the weak-undef null
	Kind  SymbolKind // SymbolGuest / SymbolHostStub / SymbolUnresolvedStub
}

// SymbolResolver resolves one imported symbol to a guest-visible address
// (consumer-owned in loader per DESIGN.md §3.3). Implementations:
// DynamicLinker.GlobalResolver (guest exports), interpose.HostResolver (host
// replacements), interpose.UnresolvedStubResolver (documented fallback).
// A resolver that does not know the symbol returns an error wrapping
// ErrSymbolUnresolved.
type SymbolResolver interface {
	Resolve(req ResolveRequest) (ResolvedSymbol, error)
}

// ResolverFunc adapts a plain function to SymbolResolver.
type ResolverFunc func(req ResolveRequest) (ResolvedSymbol, error)

// Resolve implements SymbolResolver.
func (f ResolverFunc) Resolve(req ResolveRequest) (ResolvedSymbol, error) { return f(req) }

// ChainResolvers composes resolvers in order: the first one that resolves
// wins. A resolver declines by returning an error wrapping
// ErrSymbolUnresolved (the chain moves on); any other error aborts the whole
// resolution. If every resolver declines, the chain returns an error wrapping
// ErrSymbolUnresolved — callers that want golem's lenient "unresolved import"
// semantics append an explicit fallback resolver (e.g.
// interpose.UnresolvedStubResolver) as the LAST element, which is where the
// weak-undefined → address 0 ELF rule lives too.
func ChainResolvers(rs ...SymbolResolver) SymbolResolver {
	chain := make([]SymbolResolver, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			chain = append(chain, r)
		}
	}
	return ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
		for _, r := range chain {
			rs, err := r.Resolve(req)
			if err == nil {
				return rs, nil
			}
			if !errors.Is(err, ErrSymbolUnresolved) {
				return ResolvedSymbol{}, err
			}
		}
		return ResolvedSymbol{}, fmt.Errorf("loader: %q: %w", req.Name, ErrSymbolUnresolved)
	})
}
