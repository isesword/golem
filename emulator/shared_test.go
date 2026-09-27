//go:build unicorn

package emulator

import (
	"testing"

	"github.com/isesword/golem/dvm"
)

// Phase B integration: read-only module pages shared via uc_mem_map_ptr,
// with per-engine privatization when Replace patches guest code.

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
	r, err := e.CallSymbol("add", 2, 3)
	if err != nil || r != 5 {
		t.Fatalf("add(2,3)=%d err=%v, want 5", r, err)
	}
}

func TestReplacePrivatizesOnlyThatEngine(t *testing.T) {
	a := newSharedEngine(t)
	b := newSharedEngine(t)

	addrA, ok := a.Sym("add")
	if !ok {
		t.Skip("native.so exports not loaded")
	}
	if !a.isShared(addrA, 8) {
		t.Fatal("add must live in a shared range before Replace")
	}

	// engine A replaces add: a*10+b
	a.Replace(addrA, func(h *Hook) uint64 { return h.Arg(0)*10 + h.Arg(1) })

	if a.isShared(addrA, 8) {
		t.Fatal("Replace must privatize the patched range")
	}
	if r, err := a.CallSymbol("add", 2, 3); err != nil || r != 23 {
		t.Fatalf("engine A add(2,3) after Replace = %d err=%v, want 23", r, err)
	}

	// engine B must be UNAFFECTED: it still maps the shared original bytes
	if r, err := b.CallSymbol("add", 2, 3); err != nil || r != 5 {
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
	if r, err := e.CallSymbol("add", 2, 3); err != nil || r != 5 {
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
// the loaded modules must be entry-patched AFTER boot (the pre-boot pass only
// sees an empty symbol table and binds import overrides).
func TestReplaceFnsPostBootExportPatch(t *testing.T) {
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		ReplaceFns: map[string]func(h *Hook) uint64{
			"add": func(h *Hook) uint64 { return h.Arg(0)*10 + h.Arg(1) },
		},
	})
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	defer e.Close()
	r, err := e.CallSymbol("add", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if r != 23 {
		t.Fatalf("ReplaceFns export patch inactive: add(2,3)=%d, want 23 (2*10+3)", r)
	}
}
