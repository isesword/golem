package loader

import (
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// DynamicLinker is the P3.5 skeleton of the module-graph component
// (DESIGN.md §3.3: Format parses, Relocator applies, SymbolResolver finds one
// symbol, DynamicLinker owns the module graph / load order / symbol scope).
// Today it records loaded images in load order and maintains the GLOBAL
// symbol scope (first-loaded definition wins — the historical e.syms
// semantics), exposing it as a SymbolResolver for the resolution chain.
//
// Deliberately NOT implemented (interface does not block them): dlopen/
// dlclose, per-module DT_NEEDED-ordered scopes, RTLD_NEXT, lazy binding.
type DynamicLinker struct {
	modules []*LinkedModule
	globals map[string]globalSym // name -> definition (first module wins)
}

// LinkedModule is one loaded image in the module graph.
type LinkedModule struct {
	Name  string
	Image *Image
	Base  uint64 // per-engine load bias
}

// globalSym is one definition in the global scope.
type globalSym struct {
	addr emu.GuestAddr
	size uint64
	mod  *LinkedModule
}

// NewDynamicLinker returns an empty module graph.
func NewDynamicLinker() *DynamicLinker {
	return &DynamicLinker{globals: map[string]globalSym{}}
}

// AddModule records a freshly loaded image: appended to the load order and
// its exports folded into the global scope FIRST-WINS (a later module's
// export never displaces an earlier one — the pre-P3.5 e.syms semantics,
// which is also how bionic's libc.so keeps priority over the target .so).
func (dl *DynamicLinker) AddModule(name string, img *Image, base uint64) *LinkedModule {
	m := &LinkedModule{Name: name, Image: img, Base: base}
	dl.modules = append(dl.modules, m)
	for n, off := range img.Exports {
		if _, exists := dl.globals[n]; !exists {
			dl.globals[n] = globalSym{addr: emu.GuestAddr(base + off), mod: m}
		}
	}
	return m
}

// Modules returns the module graph in load order.
func (dl *DynamicLinker) Modules() []*LinkedModule { return dl.modules }

// LookupGlobal reports the global-scope definition of name.
func (dl *DynamicLinker) LookupGlobal(name string) (emu.GuestAddr, bool) {
	g, ok := dl.globals[name]
	return g.addr, ok
}

// GlobalResolver exposes the global symbol scope as a SymbolResolver: guest
// symbols defined by any loaded module, in load order. This is the middle
// element of the boot resolution chain (after host replacements, before the
// unresolved fallback). A miss declines with ErrSymbolUnresolved.
func (dl *DynamicLinker) GlobalResolver() SymbolResolver {
	return ResolverFunc(func(req ResolveRequest) (ResolvedSymbol, error) {
		g, ok := dl.globals[req.Name]
		if !ok {
			return ResolvedSymbol{}, fmt.Errorf("loader: global scope: %q: %w", req.Name, ErrSymbolUnresolved)
		}
		return ResolvedSymbol{
			Addr:  g.addr,
			Size:  g.size,
			Image: g.mod.Image,
			Kind:  SymbolGuest,
		}, nil
	})
}
