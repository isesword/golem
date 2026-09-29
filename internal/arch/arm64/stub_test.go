package arm64

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
)

// TestEmitStubBytes pins the trampoline encoding byte-for-byte to the
// pre-P1 hardcoded `svc #0 ; ret` — both stub kinds intentionally emit the
// same bytes (classification is by address + metadata, not svc immediate).
func TestEmitStubBytes(t *testing.T) {
	_, _, enc, _ := resolveQuad(t)
	want := []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6} // svc #0 ; ret
	for _, kind := range []arch.StubKind{arch.StubHostCall, arch.StubUnresolved} {
		got, err := enc.EmitStub(kind)
		if err != nil {
			t.Fatalf("EmitStub(%d): %v", kind, err)
		}
		if !bytesEqual(got, want) {
			t.Fatalf("EmitStub(%d) = % x, want % x (pre-P1 hardcoded bytes)", kind, got, want)
		}
		got[0] ^= 0xff // mutating the result must not corrupt later emissions
	}
	again, err := enc.EmitStub(arch.StubHostCall)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(again, want) {
		t.Fatalf("EmitStub returned aliased storage: % x", again)
	}
	if _, err := enc.EmitStub(arch.StubKind(99)); err == nil {
		t.Fatal("unknown stub kind must error")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
