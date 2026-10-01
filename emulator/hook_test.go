package emulator

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// TestHookReadRole pins the facade: a Hook reads registers by ABI ROLE
// through the arch's RoleReader — the same question, portable across
// architectures, loud on unsupported roles.
func TestHookReadRole(t *testing.T) {
	be := &jniStubBE{
		regs: map[emu.Reg]uint64{
			arm64.LR:        0xFFFFFF00, // return address register (X30)
			arm64.SP:        0xC0001000,
			arm64.PC:        0xAAAA,
			arm64.TPIDR_EL0: 0x7777,
		},
		guest: map[uint64][]byte{},
		wrote: map[uint64][]byte{},
	}
	e := newTestEmulator(t, be) // the default test personality is Android/ARM64
	h := &Hook{e: e, kind: HookFunctionEntry}

	if got, err := h.ReadRole(RoleLR); err != nil || got != 0xFFFFFF00 {
		t.Errorf("ReadRole(LR) = %#x, %v; want 0xffffff00", got, err)
	}
	if got, err := h.ReadRole(RoleSP); err != nil || got != 0xC0001000 {
		t.Errorf("ReadRole(SP) = %#x, %v; want 0xc0001000", got, err)
	}
	if got, err := h.ReadRole(RoleTLS); err != nil || got != 0x7777 {
		t.Errorf("ReadRole(TLS) = %#x, %v; want 0x7777", got, err)
	}
	if _, err := h.ReadRole(RegisterRole(99)); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("unknown role err = %v, want ErrUnsupportedRole", err)
	}

	// Kind travels with the hook: entry-scoped questions gate on it .
	if h.Kind() != HookFunctionEntry {
		t.Fatalf("Kind() = %v, want function-entry", h.Kind())
	}
	var hc HookContext = h // compile-time: Hook satisfies the Portable facade
	_ = hc
}

// TestHookSemanticGating pins the context contract: entry-scoped
// questions (Arg/ReturnAddress) answer at function-entry hooks and fail
// with ErrContextUnavailable at instruction hooks — while ReadRole stays
// available everywhere (it is CPU observation, not a call-context fact).
func TestHookSemanticGating(t *testing.T) {
	be := &jniStubBE{
		regs:  map[emu.Reg]uint64{arm64.LR: 0xFFFFFF00, arm64.X0: 7},
		guest: map[uint64][]byte{},
		wrote: map[uint64][]byte{},
	}
	e := newTestEmulator(t, be)

	entry := &Hook{e: e, kind: HookFunctionEntry}
	if lr, err := entry.ReturnAddress(); err != nil || lr != 0xFFFFFF00 {
		t.Errorf("entry ReturnAddress = %#x, %v; want 0xffffff00 (X30)", lr, err)
	}
	if v, err := entry.Arg(0); err != nil || v.Raw != 7 {
		t.Errorf("entry Arg(0) = %+v, %v; want raw 7", v, err)
	}

	insn := &Hook{e: e, kind: HookInstruction}
	if _, err := insn.ReturnAddress(); !errors.Is(err, ErrContextUnavailable) {
		t.Errorf("instruction ReturnAddress err = %v, want ErrContextUnavailable", err)
	}
	if _, err := insn.Arg(0); !errors.Is(err, ErrContextUnavailable) {
		t.Errorf("instruction Arg(0) err = %v, want ErrContextUnavailable", err)
	}
	if _, err := insn.ReadRole(RoleLR); err != nil {
		t.Errorf("instruction ReadRole(LR) err = %v, want nil (CPU observation is kind-independent)", err)
	}

	// ReturnValue needs a function-EXIT context; none is installable yet.
	if _, err := entry.ReturnValue(); !errors.Is(err, ErrContextUnavailable) {
		t.Errorf("ReturnValue err = %v, want ErrContextUnavailable (no exit hooks yet)", err)
	}
}
