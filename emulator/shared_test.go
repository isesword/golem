//go:build unicorn

package emulator

import (
	"testing"

	"github.com/isesword/golem/dvm"
)

// Phase B integration: read-only module pages shared via uc_mem_map_ptr.
// P2.5d: Replace is Function Interposition (an execution hook), so it no
// longer privatizes — the shared pages stay shared in every engine, and
// per-engine isolation comes from hooks being per-engine state.

func newSharedEngine(t *testing.T) *Emulator {
	t.Helper()
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
	})
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestSharedReadOnlyActive(t *testing.T) {
	e := newSharedEngine(t)
	if len(e.shared) == 0 {
		t.Fatal("no shared ranges after boot — page sharing did not engage")
	}
	for _, sr := range e.shared {
		if sr.addr == 0 || sr.size == 0 {
			t.Fatalf("bad shared range %+v", sr)
		}
	}
	// sanity: the engine still executes shared code
	r, err := e.CallSymbol("add", Words(2, 3)...)
	if err != nil || r != 5 {
		t.Fatalf("add(2,3)=%d err=%v, want 5", r, err)
	}
}

func TestReplaceInterposesOnlyThatEngine(t *testing.T) {
	a := newSharedEngine(t)
	b := newSharedEngine(t)

	addrA, ok := a.Sym("add")
	if !ok {
		t.Skip("native.so exports not loaded")
	}
	if !a.isShared(addrA, 8) {
		t.Fatal("add must live in a shared range before Replace")
	}

	// engine A interposes add: a*10+b
	a.Replace(addrA, func(h *Hook) uint64 { return mustArg(h, 0)*10 + mustArg(h, 1) })

	// Interposition writes NO guest memory: the range stays shared in A.
	if !a.isShared(addrA, 8) {
		t.Fatal("interposition must not privatize/unshare the target range")
	}
	if r, err := a.CallSymbol("add", Words(2, 3)...); err != nil || r != 23 {
		t.Fatalf("engine A add(2,3) after Replace = %d err=%v, want 23", r, err)
	}

	// engine B must be UNAFFECTED: hooks are per-engine, so it still runs the
	// shared original code.
	if r, err := b.CallSymbol("add", Words(2, 3)...); err != nil || r != 5 {
		t.Fatalf("engine B add(2,3) = %d err=%v, want original 5", r, err)
	}
	if !b.isShared(addrA, 8) {
		t.Fatal("engine B must still share the range")
	}
}

func TestNoSharedModulesOptOut(t *testing.T) {
	e, err := New(Config{
		SOPath:          "../examples/native/native.so",
		AssetRoot:       "../assets",
		NoSharedModules: true,
	})
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	defer e.Close()
	if len(e.shared) != 0 {
		t.Fatalf("NoSharedModules must produce zero shared ranges, got %d", len(e.shared))
	}
	if r, err := e.CallSymbol("add", Words(2, 3)...); err != nil || r != 5 {
		t.Fatalf("opt-out engine broken: add(2,3)=%d err=%v", r, err)
	}
}

// The global-ref JNI path must keep working on shared-page engines (classRefs
// are globals; classes live above the module mappings).
func TestSharedEngineJNI(t *testing.T) {
	e := newSharedEngine(t)
	if _, err := e.CallNativeStatic("com/example/nosuch/Bridge", "nonexistent", "()V"); err == nil {
		t.Fatal("expected unknown-method error")
	}
	_ = dvm.Ref(0)
}

// Phase A/B review regression: ReplaceFns entries naming symbols EXPORTED by
// the loaded modules must be interposed AFTER boot (the pre-boot pass only
// sees an empty symbol table and binds import overrides).
func TestReplaceFnsPostBootExportPatch(t *testing.T) {
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		Android: AndroidConfig{
			ReplaceFns: map[string]func(h *Hook) uint64{
				"add": func(h *Hook) uint64 { return mustArg(h, 0)*10 + mustArg(h, 1) },
			},
		},
	})
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	defer e.Close()
	r, err := e.CallSymbol("add", Words(2, 3)...)
	if err != nil {
		t.Fatal(err)
	}
	if r != 23 {
		t.Fatalf("ReplaceFns export interposition inactive: add(2,3)=%d, want 23 (2*10+3)", r)
	}
}
