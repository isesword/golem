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

// TestReadArgsStackSpill pins the AAPCS64 stack-spill reads: args 8+ come
// from [SP, #(i-8)*8] — exactly where PrepareCall puts them.
func TestReadArgsStackSpill(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{SP: 0xC0001000}}
	for i := 0; i < 8; i++ {
		b.regs[X0+emu.Reg(i)] = uint64(0x1000 + i)
	}
	b.setU64(0xC0001000, 0x2008) // arg 8
	b.setU64(0xC0001008, 0x2009) // arg 9
	args, err := c.ReadArgs(b, 10)
	if err != nil {
		t.Fatalf("ReadArgs(10): %v", err)
	}
	for i := 0; i < 8; i++ {
		if want := uint64(0x1000 + i); args[i] != want {
			t.Fatalf("args[%d] = %#x, want %#x (X%d)", i, args[i], want, i)
		}
	}
	if args[8] != 0x2008 || args[9] != 0x2009 {
		t.Fatalf("stack args = %#x, %#x, want 0x2008, 0x2009 ([SP], [SP+8])", args[8], args[9])
	}
}

// TestReadArgsNegative pins that a nonsense count errors instead of reading
// the wrong registers.
func TestReadArgsNegative(t *testing.T) {
	c := resolveCallABI(t)
	if _, err := c.ReadArgs(&regRec{}, -1); err == nil {
		t.Fatal("ReadArgs(-1) must error")
	}
}

// TestPrepareCallRegisters pins the register portion of an AAPCS64 call:
// args 0..7 land in X0..X7, LR ← Return, PC ← Entry, SP untouched.
func TestPrepareCallRegisters(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{SP: 0xC0002000}}
	args := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: args}); err != nil {
		t.Fatal(err)
	}
	for i, v := range args {
		if got := b.regs[X0+emu.Reg(i)]; got != v {
			t.Fatalf("X%d = %#x, want %#x", i, got, v)
		}
	}
	if got := b.regs[LR]; got != 0xFFFFFF00 {
		t.Fatalf("LR = %#x, want the return address 0xffffff00", got)
	}
	if got := b.regs[PC]; got != 0xAAAA {
		t.Fatalf("PC = %#x, want the entry 0xaaaa", got)
	}
	if got := b.regs[SP]; got != 0xC0002000 {
		t.Fatalf("SP = %#x, want unchanged 0xc0002000 (no spill args)", got)
	}
}

// TestPrepareCallStackSpill pins the AAPCS64 stack spill: args 8+ land at
// [SP, #(i-8)*8] after SP drops by a 16-aligned spill area, and a subsequent
// ReadArgs at entry recovers every argument (the round trip CallFunc-style
// paths rely on).
func TestPrepareCallStackSpill(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{SP: 0xC0002000}}
	args := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: args}); err != nil {
		t.Fatal(err)
	}
	sp := b.regs[SP]
	if sp >= 0xC0002000 {
		t.Fatalf("SP = %#x, want below the original 0xc0002000 (spill area allocated)", sp)
	}
	if sp%16 != 0 {
		t.Fatalf("SP = %#x, want 16-aligned (AAPCS64 public-interface rule)", sp)
	}
	if got := b.getU64(sp); got != 9 {
		t.Fatalf("[SP] = %#x, want arg 8 (= 9)", got)
	}
	if got := b.getU64(sp + 8); got != 10 {
		t.Fatalf("[SP+8] = %#x, want arg 9 (= 10)", got)
	}
	// Round trip: ReadArgs at entry must recover the full argument list.
	got, err := c.ReadArgs(b, len(args))
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range args {
		if got[i] != v {
			t.Fatalf("ReadArgs[%d] = %#x, want %#x", i, got[i], v)
		}
	}
}

// TestReadResult pins the AAPCS64 result read: Value ← X0, Value2 zero.
func TestReadResult(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{X0: 0xdeadbeef}}
	r, err := c.ReadResult(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != 0xdeadbeef || r.Value2 != 0 {
		t.Fatalf("ReadResult = %#x/%#x, want 0xdeadbeef/0 (X0, no second result reg)", r.Value, r.Value2)
	}
}

// TestArgReg pins the optional introspection capability: X0..X7 for 0..7,
// ok=false beyond the register portion. ArgReg is NOT part of the core
// CallABI contract, so the test goes through CallABIIntrospector.
func TestArgReg(t *testing.T) {
	c := resolveCallABI(t)
	intro, ok := c.(arch.CallABIIntrospector)
	if !ok {
		t.Fatal("aapcs64 does not implement arch.CallABIIntrospector")
	}
	for i := 0; i < 8; i++ {
		r, ok := intro.ArgReg(i)
		if !ok || r != X0+emu.Reg(i) {
			t.Fatalf("ArgReg(%d) = %v, %v, want X%d, true", i, r, ok, i)
		}
	}
	for _, i := range []int{-1, 8, 100} {
		if r, ok := intro.ArgReg(i); ok {
			t.Fatalf("ArgReg(%d) = %v, true, want ok=false (no register for stack args)", i, r)
		}
	}
}

// TestResultReg pins the introspection result registers: 0 → X0, and no
// second integer result register (AAPCS64 uses only X0 today).
func TestResultReg(t *testing.T) {
	c := resolveCallABI(t)
	intro, ok := c.(arch.CallABIIntrospector)
	if !ok {
		t.Fatal("aapcs64 does not implement arch.CallABIIntrospector")
	}
	if r, ok := intro.ResultReg(0); !ok || r != X0 {
		t.Fatalf("ResultReg(0) = %v, %v, want X0, true", r, ok)
	}
	for _, i := range []int{-1, 1, 2} {
		if r, ok := intro.ResultReg(i); ok {
			t.Fatalf("ResultReg(%d) = %v, true, want ok=false", i, r)
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
