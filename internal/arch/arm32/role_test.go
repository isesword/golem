package arm32

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// TestReadRole pins the ARM32 P9 role reader: every role is a plain
// register read (R11 = FP, R14 = LR, R13 = SP, R15 = PC, TPIDRURW = TLS).
func TestReadRole(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	rr, ok := a.(arch.RoleReader)
	if !ok {
		t.Fatal("arm32 must implement arch.RoleReader")
	}
	b := &regRec{regs: map[emu.Reg]uint64{
		R15: 0xAAAA, R13: 0xC0001000, R14: 0xFFFFFF01, R11: 0xB0000000, TPIDRURW: 0x7777,
	}}
	for role, want := range map[arch.RegisterRole]uint64{
		arch.RolePC: 0xAAAA, arch.RoleSP: 0xC0001000, arch.RoleLR: 0xFFFFFF01,
		arch.RoleFP: 0xB0000000, arch.RoleTLS: 0x7777,
	} {
		got, err := rr.ReadRole(b, role)
		if err != nil || got != want {
			t.Errorf("ReadRole(%s) = %#x, %v; want %#x", role, got, err, want)
		}
	}
	if _, err := rr.ReadRole(b, arch.RegisterRole(99)); !errors.Is(err, arch.ErrUnsupportedRole) {
		t.Fatalf("unknown role err = %v, want ErrUnsupportedRole", err)
	}
}
