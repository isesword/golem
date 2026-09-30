package amd64

import (
	"bytes"
	"testing"

	"github.com/isesword/golem/internal/arch"
)

// TestStubEncoding pins the AMD64 trampoline bytes: `int3 ; ret`. INT3 routes
// through the interrupt channel (unicorn UC_HOOK_INTR, intno 3) — deliberately
// NOT the `syscall` instruction, which belongs to the real guest-syscall
// channel (UC_HOOK_INSN) and must never appear in a host stub.
func TestStubEncoding(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	for _, kind := range []arch.StubKind{arch.StubHostCall, arch.StubUnresolved} {
		code, err := s.EmitStub(kind)
		if err != nil {
			t.Fatalf("EmitStub(%v): %v", kind, err)
		}
		if !bytes.Equal(code, []byte{0xCC, 0xC3}) {
			t.Fatalf("EmitStub(%v) = % x, want cc c3 (int3 ; ret)", kind, code)
		}
		for i, b := range code[:len(code)-1] { // the trap portion
			if b == 0x0f && i+1 < len(code)-1 && code[i+1] == 0x05 {
				t.Fatalf("stub %v contains a syscall instruction — forbidden in host stubs", kind)
			}
		}
	}
}

// TestStubKindsShareBytes pins invariant 8: trap identity is by ADDRESS
// (StubManager metadata), never by anything in the emitted bytes, so both
// kinds emit identical code.
func TestStubKindsShareBytes(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	a, _ := s.EmitStub(arch.StubHostCall)
	b, _ := s.EmitStub(arch.StubUnresolved)
	if !bytes.Equal(a, b) {
		t.Fatalf("stub kinds must share bytes (classification is by address): % x vs % x", a, b)
	}
}

func TestStubUnknownKindErrors(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	if _, err := s.EmitStub(arch.StubKind(99)); err == nil {
		t.Fatal("EmitStub(unknown kind) must error")
	}
}

// TestEmitStubFreshCopy pins that callers receive an independent copy.
func TestEmitStubFreshCopy(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	a, _ := s.EmitStub(arch.StubHostCall)
	a[0] = 0x90
	b, _ := s.EmitStub(arch.StubHostCall)
	if b[0] != 0xCC {
		t.Fatal("EmitStub must return a fresh copy — a caller write leaked into the next stub")
	}
}

// TestTrapStubAddr pins the trap-PC → stub-entry mapping: int3 is 1 byte and
// unicorn reports RIP just past it (stub+1, pinned on the real engine by
// emu's TestUnicornAMD64HostStubTrap), so a stub at S traps with PC = S+1.
func TestTrapStubAddr(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	const stub = 0x78000000
	if got := s.TrapStubAddr(stub + 1); got != stub {
		t.Fatalf("TrapStubAddr(%#x) = %#x, want %#x (pc-1, int3 width)", stub+1, got, stub)
	}
}
