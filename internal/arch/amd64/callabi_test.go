package amd64

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

// TestCallABIRoleRegisters pins the SysV AMD64 roles: args in
// RDI/RSI/RDX/RCX/R8/R9, result in RAX, and NO link register — LR() is NoLR
// (the return address lives on the stack; see ReturnFromCall).
func TestCallABIRoleRegisters(t *testing.T) {
	c := resolveCallABI(t)
	if c.LR() != NoLR {
		t.Fatalf("LR() = %v, want NoLR — SysV AMD64 has no link register (return address is on the stack)", c.LR())
	}
	if c.Ret() != RAX {
		t.Fatalf("Ret() = %v, want RAX", c.Ret())
	}
	want := []emu.Reg{RDI, RSI, RDX, RCX, R8, R9}
	for i, w := range want {
		if got := c.Arg(i); got != w {
			t.Fatalf("Arg(%d) = %v, want %v", i, got, w)
		}
	}
}

// TestArgRegsVsSyscallABI pins the two-ABI separation (P5a requirement): the
// SysV FUNCTION call's 4th integer argument is RCX, while the Linux x86-64
// SYSCALL ABI's 4th argument is R10 (the `syscall` instruction itself
// clobbers RCX with the return RIP). The two conventions share five
// registers and differ exactly here; merging them is the classic bug.
func TestArgRegsVsSyscallABI(t *testing.T) {
	c := resolveCallABI(t)
	if got := c.Arg(3); got != RCX {
		t.Fatalf("SysV function arg 3 = %v, want RCX", got)
	}
	// The syscall ABI's registers are platform/android's transport — asserted
	// there against the same frozen ids (TestLinuxAMD64TransportDecode reads
	// R10 for arg 3). Here we pin only that the function ABI is NOT R10.
	if c.Arg(3) == R10 {
		t.Fatal("SysV function arg 3 must not be R10 — that is the syscall ABI")
	}
}

func TestArgOutOfRangePanics(t *testing.T) {
	c := resolveCallABI(t)
	for _, i := range []int{-1, 6, 100} {
		func() {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Arg(%d) must panic (SysV has 6 integer argument registers)", i)
				}
				if s, ok := r.(string); !ok || s == "" {
					t.Fatalf("Arg(%d) panic must carry a message, got %v", i, r)
				}
			}()
			c.Arg(i)
		}()
	}
}

// TestReadArgs pins SysV argument reads: args 0..n-1 come from
// RDI/RSI/RDX/RCX/R8/R9, for every n in 0..6.
func TestReadArgs(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{}}
	for i := 0; i < 6; i++ {
		b.regs[argRegs[i]] = uint64(0x1000 + i)
	}
	for n := 0; n <= 6; n++ {
		args, err := c.ReadArgs(b, n)
		if err != nil {
			t.Fatalf("ReadArgs(%d): %v", n, err)
		}
		if len(args) != n {
			t.Fatalf("ReadArgs(%d) returned %d values", n, len(args))
		}
		for i, v := range args {
			if want := uint64(0x1000 + i); v != want {
				t.Fatalf("ReadArgs(%d)[%d] = %#x, want %#x", n, i, v, want)
			}
		}
	}
}

// TestReadArgsOutOfRange pins the not-yet-implemented stack-spill path: n>6
// (and nonsense n<0) must error, not silently read the wrong registers.
func TestReadArgsOutOfRange(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{}}
	for _, n := range []int{-1, 7, 100} {
		if _, err := c.ReadArgs(b, n); err == nil {
			t.Fatalf("ReadArgs(%d) must error (stack-spill args unimplemented)", n)
		}
	}
}

// TestWriteResult pins the SysV result write-back: RAX ← Value, RDX ← Value2
// (the SysV 128-bit result pair), nothing else touched.
func TestWriteResult(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{}
	if err := c.WriteResult(b, arch.CallResult{Value: 0xdeadbeef, Value2: 0xfeed}); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[RAX]; got != 0xdeadbeef {
		t.Fatalf("WriteResult wrote RAX = %#x, want 0xdeadbeef", got)
	}
	if got := b.writes[RDX]; got != 0xfeed {
		t.Fatalf("WriteResult wrote RDX = %#x, want 0xfeed (Value2)", got)
	}
	if len(b.writes) != 2 {
		t.Fatalf("WriteResult must write exactly RAX and RDX, wrote %v", b.writes)
	}
}

// TestReturnFromCall pins the SysV return flow: retAddr ← [RSP]; RSP += 8;
// PC ← retAddr — one `ret`'s register/stack effect. The red zone below RSP
// must stay untouched.
func TestReturnFromCall(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RSP: 0xC0001000}}
	b.setU64(0xC0001000, 0x1234abcd) // the return address on the stack
	if err := c.ReturnFromCall(b); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[RIP]; got != 0x1234abcd {
		t.Fatalf("ReturnFromCall wrote RIP = %#x, want 0x1234abcd (the [RSP] value)", got)
	}
	if got := b.writes[RSP]; got != 0xC0001008 {
		t.Fatalf("ReturnFromCall wrote RSP = %#x, want 0xc0001008 (popped 8)", got)
	}
	if len(b.writes) != 2 {
		t.Fatalf("ReturnFromCall must write exactly RSP and RIP, wrote %v", b.writes)
	}
}

// TestReturnFromCallNested pins stack restoration across a NESTED host/guest
// call pair: the inner ReturnFromCall pops exactly the inner frame's return
// address, leaving the outer frame's return address at the new [RSP] for the
// outer ReturnFromCall — the stack is never corrupted.
func TestReturnFromCallNested(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RSP: 0xC0001000}}
	// Guest stack after `call inner` inside `outer`: [RSP]=inner_ret,
	// [RSP+8]=outer_ret.
	b.setU64(0xC0001000, 0xAAAA0000) // inner return address
	b.setU64(0xC0001008, 0xBBBB0000) // outer return address

	if err := c.ReturnFromCall(b); err != nil { // inner host call returns
		t.Fatal(err)
	}
	if got := b.regs[RIP]; got != 0xAAAA0000 {
		t.Fatalf("inner return: RIP = %#x, want 0xaaaa0000", got)
	}
	if got := b.regs[RSP]; got != 0xC0001008 {
		t.Fatalf("inner return: RSP = %#x, want 0xc0001008", got)
	}
	if err := c.ReturnFromCall(b); err != nil { // outer host call returns
		t.Fatal(err)
	}
	if got := b.regs[RIP]; got != 0xBBBB0000 {
		t.Fatalf("outer return: RIP = %#x, want 0xbbbb0000", got)
	}
	if got := b.regs[RSP]; got != 0xC0001010 {
		t.Fatalf("outer return: RSP = %#x, want 0xc0001010 — both frames popped", got)
	}
}
