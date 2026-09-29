package arm64

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

func resolveCallABI(t *testing.T) arch.CallABI {
	t.Helper()
	_, c, _, _ := resolveQuad(t)
	return c
}

func TestCallABIRoleRegisters(t *testing.T) {
	c := resolveCallABI(t)
	if c.LR() != LR || c.Ret() != X0 {
		t.Fatalf("role regs: LR=%v Ret=%v, want LR(X30) / X0", c.LR(), c.Ret())
	}
	for i := 0; i < 8; i++ {
		if got, want := c.Arg(i), X0+emu.Reg(i); got != want {
			t.Fatalf("Arg(%d) = %v, want %v", i, got, want)
		}
	}
}

func TestArgOutOfRangePanics(t *testing.T) {
	c := resolveCallABI(t)
	for _, i := range []int{-1, 8, 100} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Arg(%d) must panic", i)
				}
				if s, ok := r.(string); !ok || s == "" {
					t.Fatalf("Arg(%d) panic must carry a message, got %v", i, r)
				}
			}()
			c.Arg(i)
		}()
	}
}

// TestReadArgs pins AAPCS64 argument reads: args 0..n-1 come from X0..X(n-1),
// for every n in 0..8.
func TestReadArgs(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{}}
	for i := 0; i < 8; i++ {
		b.regs[X0+emu.Reg(i)] = uint64(0x1000 + i)
	}
	for n := 0; n <= 8; n++ {
		args, err := c.ReadArgs(b, n)
		if err != nil {
			t.Fatalf("ReadArgs(%d): %v", n, err)
		}
		if len(args) != n {
			t.Fatalf("ReadArgs(%d) returned %d values", n, len(args))
		}
		for i, v := range args {
			if want := uint64(0x1000 + i); v != want {
				t.Fatalf("ReadArgs(%d)[%d] = %#x, want %#x (X%d)", n, i, v, want, i)
			}
		}
	}
}

// TestReadArgsOutOfRange pins the not-yet-implemented stack-spill path: n>8
// (and nonsense n<0) must error, not silently read the wrong registers.
func TestReadArgsOutOfRange(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{}}
	for _, n := range []int{-1, 9, 100} {
		if _, err := c.ReadArgs(b, n); err == nil {
			t.Fatalf("ReadArgs(%d) must error (stack-spill args unimplemented)", n)
		}
	}
}

// TestWriteResult pins the AAPCS64 result write-back: X0 ← Value, nothing
// else touched (Value2 has no consumer on ARM64 today).
func TestWriteResult(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{}
	if err := c.WriteResult(b, arch.CallResult{Value: 0xdeadbeef, Value2: 0xfeed}); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[X0]; got != 0xdeadbeef {
		t.Fatalf("WriteResult wrote X0 = %#x, want 0xdeadbeef", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("WriteResult must write exactly one register, wrote %v", b.writes)
	}
}

// TestReturnFromCall pins the AAPCS64 return flow: PC ← X30 (LR).
func TestReturnFromCall(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{LR: 0x1234abcd}}
	if err := c.ReturnFromCall(b); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[PC]; got != 0x1234abcd {
		t.Fatalf("ReturnFromCall wrote PC = %#x, want 0x1234abcd (the LR value)", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("ReturnFromCall must write exactly PC, wrote %v", b.writes)
	}
}
