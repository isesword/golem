package emulator

import (
	"strings"
	"testing"
)

// WrapSymbol live test on the REAL binding path: native.so imports
// strlen from bionic (GOT/JUMP_SLOT relocation); wrapping "strlen"
// redirects that GOT binding to the wrap entry stub, so guest code calling
// libc strlen flows entry-trap → REAL bionic strlen → post-trap → caller.

func TestWrapSymbolGOTPath(t *testing.T) {
	e := newBootedOverride(t)

	p := e.WriteCStringAlloc("hello")
	slen := func() uint64 {
		t.Helper()
		v, err := e.CallSymbol("slen", Words(p)...)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Baseline through real bionic strlen: 5.
	if got := slen(); got != 5 {
		t.Fatalf("baseline slen = %d, want 5", got)
	}

	var observedRV, observedArg0 uint64
	stop, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue() // the ORIGINAL bionic strlen's result
		a0, _ := h.Arg(0)        // the captured entry argument (the pointer)
		observedRV = rv.Raw
		observedArg0 = a0.Raw
		return rv.Raw + 1 // rewrite: strlen → strlen+1
	})
	if err != nil {
		t.Fatalf("WrapSymbol: %v", err)
	}

	// Guest-initiated through the GOT: original runs, post rewrite lands.
	if got := slen(); got != 6 {
		t.Fatalf("wrapped slen = %d, want 6 (strlen observed as 5, rewritten to 6)", got)
	}
	if observedRV != 5 {
		t.Fatalf("ReturnValue = %d, want 5", observedRV)
	}
	if observedArg0 != p {
		t.Fatalf("entry Arg(0) = %#x, want the string pointer %#x", observedArg0, p)
	}

	// Persistent: every call wraps again.
	if got := slen(); got != 6 {
		t.Fatalf("second wrapped slen = %d, want 6", got)
	}

	// Unwrap: original binding restored.
	stop()
	if got := slen(); got != 5 {
		t.Fatalf("unwrapped slen = %d, want 5", got)
	}

	// Re-wrappable after stop.
	stop2, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		return rv.Raw + 2
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := slen(); got != 7 {
		t.Fatalf("re-wrapped slen = %d, want 7", got)
	}
	stop2()
	if got := slen(); got != 5 {
		t.Fatalf("post-stop slen = %d, want 5", got)
	}
}

// TestWrapSymbolIsolation: overrides and wraps are per-emulator — a second
// instance (fresh GOT pages, fresh tables) is unaffected.
func TestWrapSymbolIsolation(t *testing.T) {
	e1 := newBootedOverride(t)
	e2 := newBootedOverride(t)

	p1 := e1.WriteCStringAlloc("hello")
	if _, err := e1.WrapSymbol("strlen", func(h *Hook) uint64 { return 6 }); err != nil {
		t.Fatal(err)
	}
	if got, _ := e1.CallSymbol("slen", Words(p1)...); got != 6 {
		t.Fatalf("e1 wrapped slen = %d, want 6", got)
	}
	p2 := e2.WriteCStringAlloc("hello")
	if got, _ := e2.CallSymbol("slen", Words(p2)...); got != 5 {
		t.Fatalf("e2 slen = %d, want 5 — wrap leaked across instances", got)
	}
}

// TestWrapSymbolErrors: unknown symbol, duplicate wrap while live, and the
// v1 honest no-binding case — "add" is called by guest-internal direct
// branches only (no reloc names it), so WrapSymbol must REFUSE it rather
// than pretend, and the refusal must leave no state behind.
func TestWrapSymbolErrors(t *testing.T) {
	e := newBootedOverride(t)

	if _, err := e.WrapSymbol("no-such-symbol", func(h *Hook) uint64 { return 0 }); err == nil {
		t.Fatal("unknown symbol must error")
	}

	stop, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		return rv.Raw + 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WrapSymbol("strlen", func(h *Hook) uint64 { return 0 }); err == nil {
		t.Fatal("duplicate wrap of a live wrap must error")
	}

	_, noBindErr := e.WrapSymbol("add", func(h *Hook) uint64 { return 0 })
	if noBindErr == nil || !strings.Contains(strings.ToLower(noBindErr.Error()), "binding") {
		t.Fatalf("no-binding wrap must be refused honestly, got: %v", noBindErr)
	}

	// Refusals and the live wrap coexist: slen still flows through the wrap.
	p := e.WriteCStringAlloc("hello")
	if got, _ := e.CallSymbol("slen", Words(p)...); got != 6 {
		t.Fatalf("slen with live wrap = %d, want 6", got)
	}
	stop()
	if got, _ := e.CallSymbol("slen", Words(p)...); got != 5 {
		t.Fatalf("slen after unwinds = %d, want 5", got)
	}
}
