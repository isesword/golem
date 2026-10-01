package arm64

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// TestReadRole pins the role reader (arch layer): PC/SP/LR/TLS are plain
// register reads; RoleFP is X29, which has NO abstract id and therefore
// travels through the register-file dump (file index 29).
func TestReadRole(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	rr, ok := a.(arch.RoleReader)
	if !ok {
		t.Fatal("arm64 must implement arch.RoleReader")
	}
	b := &regRec{regs: map[emu.Reg]uint64{
		PC: 0xAAAA, SP: 0xC0001000, LR: 0xFFFFFF00, TPIDR_EL0: 0x7777,
	}}
	for role, want := range map[arch.RegisterRole]uint64{
		arch.RolePC: 0xAAAA, arch.RoleSP: 0xC0001000,
		arch.RoleLR: 0xFFFFFF00, arch.RoleTLS: 0x7777,
	} {
		got, err := rr.ReadRole(b, role)
		if err != nil || got != want {
			t.Errorf("ReadRole(%s) = %#x, %v; want %#x", role, got, err, want)
		}
	}
	// RoleFP: served from the dump, not a named register.
	got, err := rr.ReadRole(b, arch.RoleFP)
	if err != nil || got != 0xF0F0F0F0F0F0F0F0 {
		t.Errorf("ReadRole(FP) = %#x, %v; want the dump's X29 slot", got, err)
	}
}

// TestReadRoleUnknown: an unknown role is a loud ErrUnsupportedRole.
func TestReadRoleUnknown(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	rr := a.(arch.RoleReader)
	if _, err := rr.ReadRole(&regRec{}, arch.RegisterRole(99)); !errors.Is(err, arch.ErrUnsupportedRole) {
		t.Fatalf("unknown role err = %v, want ErrUnsupportedRole", err)
	}
}

// ReadGPRegs backs the RoleFP path: the regRec dump carries X29 at slot 29.
func (r *regRec) ReadGPRegs() ([]uint64, error) {
	dump := make([]uint64, 34)
	dump[29] = 0xF0F0F0F0F0F0F0F0
	return dump, nil
}

// TestReadReturnAddress pins the observation semantic at the arch layer:
// at function entry the call returns to X30.
func TestReadReturnAddress(t *testing.T) {
	_, c, _, _ := resolveQuad(t)
	b := &regRec{regs: map[emu.Reg]uint64{LR: 0xFFFFFF00}}
	got, err := c.ReadReturnAddress(b)
	if err != nil || got != 0xFFFFFF00 {
		t.Fatalf("ReadReturnAddress = %#x, %v; want 0xffffff00", got, err)
	}
}
