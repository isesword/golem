package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// P3.5 wiring tests: the emulator's boot resolver chain — HostResolver
// (InterposeTable) → DynamicLinker global scope → UnresolvedStubResolver —
// replaces the old resolveSymbol if-else. These tests pin the assembled
// semantics end to end, including the trap-path dispatch back into the
// BindSymbol'd host function (ReplaceFns' link-time path, previously the
// hostByName/hostImpl pair).

// ReplaceFns' link-time binding is consumed: a bound name resolves to ONE
// reused host stub, and a trap at that stub dispatches to the host function.
func TestBindSymbolConsumedByResolutionAndTrap(t *testing.T) {
	be := &trapBE{}
	e := newTrapEmu(t, be)

	ran := 0
	e.bindHostFn("getauxval", func(em *Emulator, b emu.Backend) {
		ran++
		_ = b.RegWrite(em.retReg, 0x99)
	})

	rs, err := e.resolver.Resolve(loader.ResolveRequest{Name: "getauxval", Binding: loader.SymbolBindingGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Kind != loader.SymbolHostStub || rs.Addr == 0 {
		t.Fatalf("host symbol = %+v, want a host-stub address", rs)
	}
	// Repeat resolutions reuse the same stub.
	for i := 0; i < 20; i++ {
		again, err := e.resolver.Resolve(loader.ResolveRequest{Name: "getauxval"})
		if err != nil || again.Addr != rs.Addr {
			t.Fatalf("resolution %d = %+v, %v; want stub %#x reused", i, again, err, uint64(rs.Addr))
		}
	}

	// Trap dispatch: PC just past the stub's svc → the bound host fn runs.
	e.kctx = nil // any fall-through into the kernel would nil-panic
	be.pc = uint64(rs.Addr) + 4
	e.onInterrupt(be, 0)
	if ran != 1 {
		t.Fatalf("host fn ran %d times, want 1", ran)
	}
	if v := be.writes[e.retReg]; v != 0x99 {
		t.Fatalf("retReg = %#x, want 0x99 (host fn's own write)", v)
	}
	// The stub is NOT counted as an unresolved-stub hit (it dispatched).
	if n := e.stubMgr.Hits("host:getauxval"); n != 0 {
		t.Fatalf("dispatched host call counted as unresolved hit: %d", n)
	}
}

// The assembled chain keeps the historical order: host replacement > guest
// global export > unresolved fallback; weak undefined → 0.
func TestBootResolverChainSemantics(t *testing.T) {
	e := newTrapEmu(t, &trapBE{})

	// Guest export via the module graph.
	img := &loader.Image{Path: "libx.so", Format: loader.FormatELF, Exports: map[string]uint64{"guest_fn": 0x400, "strlen": 0x800}}
	e.dl.AddModule("libx.so", img, 0x12000000)

	// ① guest strong → correct guest address.
	rs, err := e.resolver.Resolve(loader.ResolveRequest{Name: "guest_fn", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Addr != 0x12000400 || rs.Kind != loader.SymbolGuest {
		t.Fatalf("guest strong = %+v, %v; want 0x12000400 guest", rs, err)
	}

	// Host replacement wins over a same-named guest export (historical order).
	e.bindHostFn("strlen", hostRet0)
	rs, err = e.resolver.Resolve(loader.ResolveRequest{Name: "strlen", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Kind != loader.SymbolHostStub {
		t.Fatalf("host-overridden export = %+v, %v; want host-stub", rs, err)
	}

	// ② missing strong → the documented lenient fallback: an unresolved stub
	// (current golem semantics — kept deliberately, NOT a hard error).
	rs, err = e.resolver.Resolve(loader.ResolveRequest{Name: "no_such", Binding: loader.SymbolBindingGlobal})
	if err != nil || rs.Kind != loader.SymbolUnresolvedStub || rs.Addr == 0 {
		t.Fatalf("missing strong = %+v, %v; want unresolved-stub fallback", rs, err)
	}

	// ③ weak undefined → 0, no error.
	rs, err = e.resolver.Resolve(loader.ResolveRequest{Name: "weak_opt", Binding: loader.SymbolBindingWeak})
	if err != nil || rs.Addr != 0 {
		t.Fatalf("weak undefined = %+v, %v; want 0", rs, err)
	}
}

// JNIEnv/JavaVM stubs (StubHostCall kind, non-"host:" names) must still fall
// through to the unresolved-stub path when not in jniDispatch — the P3.5
// trap-dispatch rewrite must not misclassify them.
func TestJavaVMStubStillFallsThrough(t *testing.T) {
	be := &trapBE{}
	e := newTrapEmu(t, be)
	svc64, err := e.stubMgr.Allocate(arch.StubHostCall, "JavaVM[3]")
	if err != nil {
		t.Fatal(err)
	}
	be.pc = uint64(svc64) + 4
	e.kctx = nil
	e.onInterrupt(be, 0)
	if n := e.stubMgr.Hits("JavaVM[3]"); n != 1 {
		t.Fatalf("JavaVM[3] hit count = %d, want 1 (optimistic-0 stub path)", n)
	}
	if v, ok := be.writes[e.retReg]; !ok || v != 0 {
		t.Fatalf("stub must write optimistic 0, writes=%v", be.writes)
	}
}
