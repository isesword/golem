//go:build unicorn

package emulator

import (
	"bytes"
	"testing"
)

// TestInterposeEntryHookE2E is the P2.5d acceptance test on a real backend:
// replacing an exported function must (a) run the host function instead of
// the guest body, (b) write the result back per the CallABI so nested guest
// callers see it too, and (c) leave guest .text byte-identical — the
// interposition mechanism never writes guest code (DESIGN.md invariant 11).
func TestInterposeEntryHookE2E(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	addr, ok := e.Sym("add")
	if !ok {
		t.Skip("native.so exports not loaded")
	}
	before, err := e.ReadBytes(addr, 16)
	if err != nil {
		t.Fatal(err)
	}
	// sanity: the original body computes a+b
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 5 {
		t.Fatalf("pre-interpose add(2,3) = %d, want 5", int32(r))
	}

	hostRan := 0
	if err := e.ReplaceE(addr, func(h *Hook) uint64 {
		hostRan++
		return h.Arg(0)*10 + h.Arg(1)
	}); err != nil {
		t.Fatal(err)
	}

	// Binding the interposition must not have touched guest .text.
	mid, err := e.ReadBytes(addr, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mid) {
		t.Fatalf("guest .text changed at bind time:\n before % x\n after  % x", before, mid)
	}

	// Top-level call: host fn runs, original body skipped (23 != 5), result
	// written back per the CallABI.
	if r, _ := e.CallSymbol("add", 2, 3); int32(r) != 23 {
		t.Fatalf("interposed add(2,3) = %d, want 23 (2*10+3)", int32(r))
	}
	if hostRan == 0 {
		t.Fatal("host function never ran")
	}

	// Repeatability: a second call through the same entry intercepts again.
	if r, _ := e.CallSymbol("add", 4, 5); int32(r) != 45 {
		t.Fatalf("interposed add(4,5) = %d, want 45", int32(r))
	}

	// After execution the code bytes are STILL identical, and the page is
	// still shared (no privatize compensation fired — it was retired).
	after, err := e.ReadBytes(addr, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("guest .text mutated by interposition:\n before % x\n after  % x", before, after)
	}
	if !e.isShared(addr, 16) {
		t.Fatal("interposed page must remain shared — nothing may write it")
	}
	// Other functions in the same module are unaffected.
	if r, _ := e.CallSymbol("fib", 20); r != 6765 {
		t.Fatalf("fib(20) = %d, want 6765 (interposition is per-entry)", r)
	}
}

// TestInterposeFromGuestCaller verifies the interception fires for a call
// issued BY guest code (not just host-initiated CallSymbol): native.so's slen
// imports strlen from bionic, so interposing libc's strlen entry must change
// slen's result — and ReturnFromCall must hand control back INTO the guest
// caller (LR = inside slen). Neither module's bytes may change.
func TestInterposeFromGuestCaller(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	addr, ok := e.Sym("strlen") // libc.so export; slen's import resolves to it
	if !ok {
		t.Skip("strlen export not found")
	}
	before, err := e.ReadBytes(addr, 16)
	if err != nil {
		t.Fatal(err)
	}

	p := e.WriteCStringAlloc("hello")
	if r, _ := e.CallSymbol("slen", p); int32(r) != 5 {
		t.Fatalf("pre-interpose slen(\"hello\") = %d, want 5", int32(r))
	}

	if err := e.ReplaceE(addr, func(h *Hook) uint64 { return 42 }); err != nil {
		t.Fatal(err)
	}
	// The guest caller (slen) branches into strlen's entry; the entry hook
	// must intercept that too, and the guest body must not run (42 != 5).
	if r, _ := e.CallSymbol("slen", p); int32(r) != 42 {
		t.Fatalf("slen(\"hello\") with strlen interposed = %d, want 42", int32(r))
	}
	after, err := e.ReadBytes(addr, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("guest .text mutated by interposition")
	}
}
