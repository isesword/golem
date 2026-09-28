//go:build unicorn

package emulator

import (
	"strings"
	"testing"
)

// TestGuestCallbackPanic: a panicking Replace callback runs inside the
// engine's C→Go trampoline, where an unrecovered panic would kill the whole
// process. The guard must instead recover it, stop the run, and surface it
// from CallSymbol as an ordinary error — and because guest state was
// abandoned mid-upcall, the emulator must then be poisoned against later
// calls.
func TestGuestCallbackPanic(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	if err := e.ReplaceSymbol("add", func(h *Hook) uint64 {
		panic("boom from guest callback")
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.CallSymbol("add", 2, 3); err == nil ||
		!strings.Contains(err.Error(), "panic during guest callback") {
		t.Fatalf("panicking callback must surface as an error, got %v", err)
	}
	if _, err := e.CallSymbol("fib", 5); err == nil ||
		!strings.Contains(err.Error(), "poisoned") {
		t.Fatalf("calls after a callback panic must report poisoned, got %v", err)
	}
}
