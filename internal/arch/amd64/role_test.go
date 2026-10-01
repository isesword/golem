package amd64

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// TestReadRole pins the AMD64 role reader. The load-bearing case is the
// NEGATIVE one: RoleLR is unsupported (x86-64 has no link register — the
// return address lives on the stack), answered with ErrUnsupportedRole,
// never a silent zero.
func TestReadRole(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	rr, ok := a.(arch.RoleReader)
	if !ok {
		t.Fatal("amd64 must implement arch.RoleReader")
	}
	b := &regRec{regs: map[emu.Reg]uint64{
		RIP: 0xAAAA, RSP: 0xC0001000, RBP: 0xB0000000, FS_BASE: 0x7777,
	}}
	for role, want := range map[arch.RegisterRole]uint64{
		arch.RolePC: 0xAAAA, arch.RoleSP: 0xC0001000,
		arch.RoleFP: 0xB0000000, arch.RoleTLS: 0x7777,
	} {
		got, err := rr.ReadRole(b, role)
		if err != nil || got != want {
			t.Errorf("ReadRole(%s) = %#x, %v; want %#x", role, got, err, want)
		}
	}
	if _, err := rr.ReadRole(b, arch.RoleLR); !errors.Is(err, arch.ErrUnsupportedRole) {
		t.Fatalf("RoleLR on AMD64 err = %v, want ErrUnsupportedRole", err)
	}
	if _, err := rr.ReadRole(b, arch.RegisterRole(99)); !errors.Is(err, arch.ErrUnsupportedRole) {
		t.Fatalf("unknown role err = %v, want ErrUnsupportedRole", err)
	}
}

// TestReadReturnAddress pins the AMD64 observation semantic: at function
// entry the return address is the little-endian word at [RSP] — read from
// the STACK, not a register (invariant 13).
func TestReadReturnAddress(t *testing.T) {
	_, c, _, _ := resolveQuad(t)
	const want = uint64(0xFFFFFF00)
	b := &regRec{
		regs: map[emu.Reg]uint64{RSP: 0xC0001000},
		mem:  map[uint64][]byte{},
	}
	for i := 0; i < 8; i++ {
		b.mem[0xC0001000+uint64(i)] = []byte{byte(want >> (8 * i))}
	}
	got, err := c.ReadReturnAddress(b)
	if err != nil || got != 0xFFFFFF00 {
		t.Fatalf("ReadReturnAddress = %#x, %v; want 0xffffff00", got, err)
	}
}
