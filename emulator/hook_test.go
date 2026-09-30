package emulator

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// TestHookReadRole pins the P9 facade: a Hook reads registers by ABI ROLE
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

	// Kind travels with the hook: entry-scoped questions gate on it (P9b).
	if h.Kind() != HookFunctionEntry {
		t.Fatalf("Kind() = %v, want function-entry", h.Kind())
	}
	var hc HookContext = h // compile-time: Hook satisfies the Portable facade
	_ = hc
}
