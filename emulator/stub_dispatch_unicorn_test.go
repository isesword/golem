//go:build unicorn

package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
)

// TestStubVsSyscallChannelsE2E verifies the trap-identity split on a real
// engine: a genuine bionic syscall never lands in the stub table, and a stub
// trampoline never reaches the kernel dispatcher.
func TestStubVsSyscallChannelsE2E(t *testing.T) {
	e, err := New(Config{SOPath: "../examples/native/native.so", AssetRoot: "../assets"})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer e.Close()

	// Real guest SVC (bionic's uname wrapper) must NOT hit the stub table.
	if _, err := e.CallSymbol("uname_machine_len"); err != nil {
		t.Fatal(err)
	}
	if h := e.stubMgr.HitCounts(); len(h) != 0 {
		t.Fatalf("guest syscalls misclassified as stubs: %v", h)
	}

	// Host-call and unresolved stubs trap into the stub branch (recorded as
	// hits, optimistic 0 return) — not into the kernel dispatcher.
	for _, kind := range []arch.StubKind{arch.StubHostCall, arch.StubUnresolved} {
		stub := e.makeStub("synthetic_stub", kind)
		r, err := e.CallFunc(stub)
		if err != nil {
			t.Fatalf("call stub (kind %d): %v", kind, err)
		}
		if r != 0 {
			t.Fatalf("stub (kind %d) return = %#x, want 0", kind, r)
		}
	}
	if e.stubMgr.Hits("synthetic_stub") != 2 {
		t.Fatalf("stub hits = %d, want synthetic_stub x2", e.stubMgr.Hits("synthetic_stub"))
	}
	if exited, code := e.GuestExited(); exited {
		t.Fatalf("guest exited(%d) — stub trap must not reach the kernel", code)
	}
}
