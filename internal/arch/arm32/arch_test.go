package arm32

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

func resolveQuad(t *testing.T) (arch.Arch, arch.CallABI, arch.StubEncoder, arch.CPUFeatures) {
	t.Helper()
	a, c, s, f, err := arch.Resolve(arch.IDARM, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("Resolve(IDARM, generic): %v", err)
	}
	return a, c, s, f
}

// TestQuadRegistration pins the (IDARM, VariantGeneric) registration: all
// four capabilities resolve, and the CPU reports the ARM32 engine arch.
func TestQuadRegistration(t *testing.T) {
	a, c, s, f := resolveQuad(t)
	if a == nil || c == nil || s == nil || f == nil {
		t.Fatal("Resolve must return a non-nil Arch, CallABI, StubEncoder and CPUFeatures")
	}
	if a.EngineArch() != emu.ArchARM {
		t.Fatalf("EngineArch = %v, want ArchARM", a.EngineArch())
	}
}

// TestCPUProperties pins the armv7 CPU facts: role registers, pointer size,
// byte order and the Linux 3G/1G address-space ceiling.
func TestCPUProperties(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	if a.PC() != PC || a.SP() != SP {
		t.Fatalf("PC/SP = %v/%v, want r15/r13", a.PC(), a.SP())
	}
	if a.PtrSize() != 4 {
		t.Fatalf("PtrSize = %d, want 4", a.PtrSize())
	}
	caps := a.Caps()
	if caps.PointerBits != 32 || caps.PageSize != 0x1000 || caps.MaxUserVA != 0xBF000000 {
		t.Fatalf("Caps = %+v, want 32-bit pointers, 4K pages, MaxUserVA 0xbf000000 (Linux 3G/1G TASK_SIZE)", caps)
	}
}

// TestNormalizeCodeAddr pins the Thumb-bit strip: an address operation
// only — ISA state at control transfers is setPCBX's business (callabi.go).
func TestNormalizeCodeAddr(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	if got := a.NormalizeCodeAddr(0x1001); got != 0x1000 {
		t.Fatalf("NormalizeCodeAddr(0x1001) = %#x, want 0x1000 (Thumb bit stripped)", got)
	}
	if got := a.NormalizeCodeAddr(0x1000); got != 0x1000 {
		t.Fatalf("NormalizeCodeAddr(0x1000) = %#x, want unchanged", got)
	}
}

// TestSetTLSBase pins the TLS path: TPIDRURW (CP15 c13,c0,3), never a
// general-purpose register.
func TestSetTLSBase(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	b := newRegRec()
	if err := a.SetTLSBase(b, 0x715711DE); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[TPIDRURW]; got != 0x715711DE {
		t.Fatalf("TPIDRURW = %#x, want 0x715711de", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("SetTLSBase wrote %d registers, want exactly 1", len(b.writes))
	}
}

// TestStubEncoding pins the ARM-state stub bytes and the trap-address rule
// (svc traps at PC svc+4 — measured live in emu's TestUnicornARM32SvcTrapPC).
func TestStubEncoding(t *testing.T) {
	_, _, s, _ := resolveQuad(t)
	want := []byte{0x00, 0x00, 0x00, 0xef, 0x1e, 0xff, 0x2f, 0xe1} // svc #0 ; bx lr
	for _, kind := range []arch.StubKind{arch.StubHostCall, arch.StubUnresolved} {
		code, err := s.EmitStub(kind)
		if err != nil {
			t.Fatalf("EmitStub(%v): %v", kind, err)
		}
		if len(code) != len(want) {
			t.Fatalf("EmitStub(%v) = %d bytes, want %d", kind, len(code), len(want))
		}
		for i, b := range want {
			if code[i] != b {
				t.Fatalf("EmitStub(%v)[%d] = %#x, want %#x", kind, i, code[i], b)
			}
		}
	}
	if _, err := s.EmitStub(arch.StubKind(99)); err == nil {
		t.Fatal("EmitStub(unknown) must error")
	}
	if got := s.TrapStubAddr(0x5004); got != 0x5000 {
		t.Fatalf("TrapStubAddr(0x5004) = %#x, want 0x5000 (ARM svc traps at svc+4)", got)
	}
}

// TestEmptyFeatures pins the stage behavior: no optional CPU features.
func TestEmptyFeatures(t *testing.T) {
	_, _, _, f := resolveQuad(t)
	if hwcap, hwcap2 := f.HWCAP(); hwcap != 0 || hwcap2 != 0 {
		t.Fatalf("HWCAP() = (%#x, %#x), want (0, 0) — empty feature set", hwcap, hwcap2)
	}
}
