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

// TestArgRegsVsSyscallABI pins the two-ABI separation (P5a requirement): the
// SysV FUNCTION call's 4th integer argument is RCX, while the Linux x86-64
// SYSCALL ABI's 4th argument is R10 (the `syscall` instruction itself
// clobbers RCX with the return RIP). The two conventions share five
// registers and differ exactly here; merging them is the classic bug.
func TestArgRegsVsSyscallABI(t *testing.T) {
	c := resolveCallABI(t)
	intro, ok := c.(arch.CallABIIntrospector)
	if !ok {
		t.Fatal("sysV64 does not implement arch.CallABIIntrospector")
	}
	r3, ok := intro.ArgReg(3)
	if !ok || r3 != RCX {
		t.Fatalf("SysV function arg 3 = %v, %v, want RCX, true", r3, ok)
	}
	// The syscall ABI's registers are platform/android's transport — asserted
	// there against the same frozen ids (TestLinuxAMD64TransportDecode reads
	// R10 for arg 3). Here we pin only that the function ABI is NOT R10.
	if r3 == R10 {
		t.Fatal("SysV function arg 3 must not be R10 — that is the syscall ABI")
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

// TestReadArgsStackSpill pins the SysV stack-spill reads: args 6+ come from
// [RSP+8+(i-6)*8] — above the return address at [RSP].
func TestReadArgsStackSpill(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RSP: 0xC0001000}}
	for i := 0; i < 6; i++ {
		b.regs[argRegs[i]] = uint64(0x1000 + i)
	}
	b.setU64(0xC0001000, 0xFFFFFF00) // the return address — never an argument
	b.setU64(0xC0001008, 0x2006)     // arg 6
	b.setU64(0xC0001010, 0x2007)     // arg 7
	args, err := c.ReadArgs(b, 8)
	if err != nil {
		t.Fatalf("ReadArgs(8): %v", err)
	}
	for i := 0; i < 6; i++ {
		if want := uint64(0x1000 + i); args[i] != want {
			t.Fatalf("args[%d] = %#x, want %#x", i, args[i], want)
		}
	}
	if args[6] != 0x2006 || args[7] != 0x2007 {
		t.Fatalf("stack args = %#x, %#x, want 0x2006, 0x2007 ([RSP+8], [RSP+16])", args[6], args[7])
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

// TestPrepareCallRegisters pins the register portion of a SysV call: args
// 0..5 land in RDI/RSI/RDX/RCX/R8/R9, the return address is pushed at the new
// [RSP], entry RSP ≡ 8 (mod 16), RIP ← Entry.
func TestPrepareCallRegisters(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RSP: 0xC0002000}}
	args := []uint64{1, 2, 3, 4, 5, 6}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: arch.WordArgs(args...)}); err != nil {
		t.Fatal(err)
	}
	for i, v := range args {
		if got := b.regs[argRegs[i]]; got != v {
			t.Fatalf("arg reg %d = %#x, want %#x", i, got, v)
		}
	}
	rsp := b.regs[RSP]
	if rsp%16 != 8 {
		t.Fatalf("entry RSP = %#x, want ≡ 8 (mod 16) — the post-`call` convention", rsp)
	}
	if got := b.getU64(rsp); got != 0xFFFFFF00 {
		t.Fatalf("[RSP] = %#x, want the pushed return address 0xffffff00", got)
	}
	if got := b.regs[RIP]; got != 0xAAAA {
		t.Fatalf("RIP = %#x, want the entry 0xaaaa", got)
	}
}

// TestPrepareCallStackSpill pins SysV stack arguments: args 6+ at
// [RSP+8+(i-6)*8] above the return address, and a subsequent ReadArgs at
// entry recovers every argument (the round trip CallFunc-style paths rely
// on). 8 arguments = 6 registers + 2 stack slots.
func TestPrepareCallStackSpill(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RSP: 0xC0002000}}
	args := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: arch.WordArgs(args...)}); err != nil {
		t.Fatal(err)
	}
	rsp := b.regs[RSP]
	if rsp%16 != 8 {
		t.Fatalf("entry RSP = %#x, want ≡ 8 (mod 16)", rsp)
	}
	if got := b.getU64(rsp); got != 0xFFFFFF00 {
		t.Fatalf("[RSP] = %#x, want the return address", got)
	}
	if got := b.getU64(rsp + 8); got != 7 {
		t.Fatalf("[RSP+8] = %#x, want arg 6 (= 7)", got)
	}
	if got := b.getU64(rsp + 16); got != 8 {
		t.Fatalf("[RSP+16] = %#x, want arg 7 (= 8)", got)
	}
	// Nothing below the new RSP may be written (the red zone stays intact):
	// the fake memory map must not extend below rsp.
	for addr := range b.mem {
		if addr < rsp {
			t.Fatalf("PrepareCall wrote at %#x, below the new RSP %#x (red-zone violation)", addr, rsp)
		}
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

// TestPrepareCallAlignmentOddSpill pins alignment with an ODD number of stack
// arguments: one padding slot is required so entry RSP still lands ≡ 8
// (mod 16).
func TestPrepareCallAlignmentOddSpill(t *testing.T) {
	c := resolveCallABI(t)
	for _, origRSP := range []uint64{0xC0002000, 0xC0002010, 0xC0002008} {
		b := &regRec{regs: map[emu.Reg]uint64{RSP: origRSP}}
		args := []uint64{1, 2, 3, 4, 5, 6, 7} // one stack arg
		if err := c.PrepareCall(b, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: arch.WordArgs(args...)}); err != nil {
			t.Fatal(err)
		}
		rsp := b.regs[RSP]
		if rsp%16 != 8 {
			t.Fatalf("origRSP %#x: entry RSP = %#x, want ≡ 8 (mod 16)", origRSP, rsp)
		}
		if got := b.getU64(rsp); got != 0xFFFFFF00 {
			t.Fatalf("origRSP %#x: [RSP] = %#x, want the return address", origRSP, got)
		}
		if got := b.getU64(rsp + 8); got != 7 {
			t.Fatalf("origRSP %#x: [RSP+8] = %#x, want arg 6 (= 7)", origRSP, got)
		}
	}
}

// TestReadResult pins the SysV result read: Value ← RAX, Value2 ← RDX — the
// exact inverse of WriteResult.
func TestReadResult(t *testing.T) {
	c := resolveCallABI(t)
	b := &regRec{regs: map[emu.Reg]uint64{RAX: 0xdeadbeef, RDX: 0xfeed}}
	r, err := c.ReadResult(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.Value != 0xdeadbeef || r.Value2 != 0xfeed {
		t.Fatalf("ReadResult = %#x/%#x, want 0xdeadbeef/0xfeed (RAX/RDX)", r.Value, r.Value2)
	}
}

// TestArgReg pins the optional introspection capability: RDI/RSI/RDX/RCX/R8/R9
// for 0..5, ok=false beyond the register portion (stack args have no
// register). ArgReg is NOT part of the core CallABI contract, so the test
// goes through CallABIIntrospector.
func TestArgReg(t *testing.T) {
	c := resolveCallABI(t)
	intro, ok := c.(arch.CallABIIntrospector)
	if !ok {
		t.Fatal("sysV64 does not implement arch.CallABIIntrospector")
	}
	for i, w := range argRegs {
		r, ok := intro.ArgReg(i)
		if !ok || r != w {
			t.Fatalf("ArgReg(%d) = %v, %v, want %v, true", i, r, ok, w)
		}
	}
	for _, i := range []int{-1, 6, 100} {
		if r, ok := intro.ArgReg(i); ok {
			t.Fatalf("ArgReg(%d) = %v, true, want ok=false (args 6+ spill to the stack)", i, r)
		}
	}
}

// TestResultReg pins the introspection result registers: 0 → RAX, 1 → RDX,
// matching WriteResult/ReadResult; anything else is ok=false.
func TestResultReg(t *testing.T) {
	c := resolveCallABI(t)
	intro, ok := c.(arch.CallABIIntrospector)
	if !ok {
		t.Fatal("sysV64 does not implement arch.CallABIIntrospector")
	}
	for i, w := range []emu.Reg{RAX, RDX} {
		r, ok := intro.ResultReg(i)
		if !ok || r != w {
			t.Fatalf("ResultReg(%d) = %v, %v, want %v, true", i, r, ok, w)
		}
	}
	for _, i := range []int{-1, 2, 100} {
		if r, ok := intro.ResultReg(i); ok {
			t.Fatalf("ResultReg(%d) = %v, true, want ok=false", i, r)
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
