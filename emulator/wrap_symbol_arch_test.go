package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform/android"
)

// P10-2c nesting + recursion, live on the REAL binding path. The native.so
// `nest`/`fact` probes route guest calls through a RESOLVABLE BINDING by
// taking the callee's address (data reloc naming the symbol) — exactly the
// slot WrapSymbol redirects. Each wrapped call pushes a WrapFrame; the post
// continuation must pop precisely its own, innermost-first.

func TestWrapSymbolNesting(t *testing.T) {
	e := newBootedOverride(t)

	p := e.WriteCStringAlloc("hello")
	if got, err := e.CallSymbol("nest", Words(p)...); err != nil || got != 1005 {
		t.Fatalf("baseline nest = %d, %v; want 1005", got, err)
	}

	var order []string
	var strlenRV, slenRV, strlenArg0 uint64
	stopStrlen, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		a0, _ := h.Arg(0)
		order = append(order, "strlen")
		strlenRV, strlenArg0 = rv.Raw, a0.Raw
		return rv.Raw + 1 // 5 → 6
	})
	if err != nil {
		t.Fatal(err)
	}
	stopSlen, err := e.WrapSymbol("slen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		order = append(order, "slen")
		slenRV = rv.Raw
		return rv.Raw + 2 // 6 → 8: the INNER rewrite feeds the outer wrap
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := e.CallSymbol("nest", Words(p)...)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1008 {
		t.Fatalf("nested nest = %d, want 1008 (strlen+1 then slen+2, +1000)", got)
	}
	if len(order) != 2 || order[0] != "strlen" || order[1] != "slen" {
		t.Fatalf("post order = %v, want [strlen slen] (innermost pops first)", order)
	}
	if strlenRV != 5 || strlenArg0 != p {
		t.Fatalf("strlen post: rv=%d arg0=%#x, want rv=5 arg0=%#x", strlenRV, strlenArg0, p)
	}
	if slenRV != 6 {
		t.Fatalf("slen post rv = %d, want 6 — the inner rewrite must reach the outer wrap", slenRV)
	}

	stopSlen()
	stopStrlen()
	if got, _ := e.CallSymbol("nest", Words(p)...); got != 1005 {
		t.Fatalf("unwound nest = %d, want 1005", got)
	}
}

func TestWrapSymbolRecursion(t *testing.T) {
	e := newBootedOverride(t)

	if got, err := e.CallSymbol("fact", Words(5)...); err != nil || got != 120 {
		t.Fatalf("baseline fact(5) = %d, %v; want 120", got, err)
	}

	posts := 0
	stop, err := e.WrapSymbol("fact", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		posts++
		return rv.Raw + 1
	})
	if err != nil {
		t.Fatal(err)
	}

	// fact(5) is entered by CallSymbol DIRECTLY (no binding — unwrapped);
	// its four recursive calls go through the redirected pointer binding, so
	// exactly four frames stack and unwind: 1→2, 4→5, 15→16, 64→65,
	// final 5*65 = 325. Any stacking error skews every level's arithmetic.
	got, err := e.CallSymbol("fact", Words(5)...)
	if err != nil {
		t.Fatal(err)
	}
	if got != 325 {
		t.Fatalf("wrapped fact(5) = %d, want 325", got)
	}
	if posts != 4 {
		t.Fatalf("posts = %d, want 4 (the direct top-level call is not wrapped)", posts)
	}

	stop()
	if got, _ := e.CallSymbol("fact", Words(5)...); got != 120 {
		t.Fatalf("unwrapped fact(5) = %d, want 120", got)
	}
}

// ---- P10-2d: the same wrap on the OTHER ELF architectures ------------------

func TestWrapSymbolAMD64DataBinding(t *testing.T) {
	const so = "../examples/native/hello_amd64.so"
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 { return 42 },
		}),
	)))
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	// via_fptr_table: 7 (seven, R_X86_64_RELATIVE — not wrappable) +
	// add(1,2) through fptr_table[1] (R_X86_64_64 naming a DEFINED,
	// preemptible symbol — the resolvable binding this test wraps).
	if got, err := e.CallSymbol("via_fptr_table"); err != nil || got != 10 {
		t.Fatalf("baseline via_fptr_table = %d, %v; want 10", got, err)
	}

	var a0, a1, rv uint64
	stop, err := e.WrapSymbol("add", func(h *Hook) uint64 {
		v0, _ := h.Arg(0)
		v1, _ := h.Arg(1)
		r, _ := h.ReturnValue()
		a0, a1, rv = v0.Raw, v1.Raw, r.Raw
		return r.Raw * 10 // 3 → 30
	})
	if err != nil {
		t.Fatalf("wrap add (data-reloc binding): %v", err)
	}

	got, err := e.CallSymbol("via_fptr_table")
	if err != nil {
		t.Fatal(err)
	}
	if got != 37 {
		t.Fatalf("wrapped via_fptr_table = %d, want 37 (7 + 3*10)", got)
	}
	if a0 != 1 || a1 != 2 || rv != 3 {
		t.Fatalf("add post: args=(%d,%d) rv=%d, want (1,2) rv=3", a0, a1, rv)
	}

	stop()
	if got, _ := e.CallSymbol("via_fptr_table"); got != 10 {
		t.Fatalf("unwound via_fptr_table = %d, want 10", got)
	}
}

func TestWrapSymbolARM32Binding(t *testing.T) {
	const so = "../examples/native/hello_android_arm32.so"
	const bionic = "../assets/android/sdk23/lib/libc.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	if _, err := os.Stat(bionic); err != nil {
		t.Skipf("ARM32 bionic assets not fetched: %v (run scripts/fetch_bionic_arm32.sh)", err)
	}
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 { return 42 },
		}),
	)))
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })

	// nest takes add's address (R_ARM_ABS32 naming a DEFINED preemptible
	// symbol — the resolvable binding), then p(3,4)+1000.
	if got, err := e.CallSymbol("nest", Words(3)...); err != nil || got != 1007 {
		t.Fatalf("baseline nest(3) = %d, %v; want 1007", got, err)
	}

	var a0, a1, rv uint64
	stop, err := e.WrapSymbol("add", func(h *Hook) uint64 {
		v0, _ := h.Arg(0)
		v1, _ := h.Arg(1)
		r, _ := h.ReturnValue()
		a0, a1, rv = v0.Raw, v1.Raw, r.Raw
		return r.Raw + 100 // 7 → 107
	})
	if err != nil {
		t.Fatalf("wrap add (ABS32 binding): %v", err)
	}

	got, err := e.CallSymbol("nest", Words(3)...)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1107 {
		t.Fatalf("wrapped nest(3) = %d, want 1107 (7+100, +1000)", got)
	}
	if a0 != 3 || a1 != 4 || rv != 7 {
		t.Fatalf("add post: args=(%d,%d) rv=%d, want (3,4) rv=7", a0, a1, rv)
	}
	stop()

	// Recursion through the binding — same arithmetic as ARM64: 325, 4 posts.
	posts := 0
	stopFact, err := e.WrapSymbol("fact", func(h *Hook) uint64 {
		r, _ := h.ReturnValue()
		posts++
		return r.Raw + 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e.CallSymbol("fact", Words(5)...); err != nil || got != 325 {
		t.Fatalf("wrapped fact(5) = %d, %v; want 325", got, err)
	}
	if posts != 4 {
		t.Fatalf("posts = %d, want 4", posts)
	}
	stopFact()
	if got, _ := e.CallSymbol("fact", Words(5)...); got != 120 {
		t.Fatalf("unwrapped fact(5) = %d, want 120", got)
	}
}
