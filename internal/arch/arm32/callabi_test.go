package arm32

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// regRec is the fake Backend the CallABI tests drive (mirrors arch/arm64's):
// registers in a map (writes recorded so "must NOT be written" is
// testable), memory as sparse bytes.
type regRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	regs        map[emu.Reg]uint64
	writes      map[emu.Reg]uint64
	mem         map[uint64]byte
}

func newRegRec() *regRec {
	return &regRec{regs: map[emu.Reg]uint64{}, writes: map[emu.Reg]uint64{}, mem: map[uint64]byte{}}
}

func (r *regRec) RegRead(reg emu.Reg) (uint64, error) { return r.regs[reg], nil }

func (r *regRec) RegWrite(reg emu.Reg, v uint64) error {
	r.writes[reg] = v
	r.regs[reg] = v
	return nil
}

func (r *regRec) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		out[i] = r.mem[uint64(addr)+uint64(i)]
	}
	return out, nil
}

func (r *regRec) MemWrite(addr emu.GuestAddr, data []byte) error {
	for i, b := range data {
		r.mem[uint64(addr)+uint64(i)] = b
	}
	return nil
}

func (r *regRec) u32(addr uint64) uint32 {
	return binary.LittleEndian.Uint32([]byte{r.mem[addr], r.mem[addr+1], r.mem[addr+2], r.mem[addr+3]})
}

func word(v uint64) arch.CallArg { return arch.CallArg{Value: v, Kind: arch.ArgWord} }
func u64(v uint64) arch.CallArg  { return arch.CallArg{Value: v, Kind: arch.ArgU64} }

const testSP = 0x80001000

// prepare runs PrepareCall on a fresh fake with SP=testSP.
func prepare(t *testing.T, entry emu.GuestAddr, args ...arch.CallArg) *regRec {
	t.Helper()
	b := newRegRec()
	b.regs[SP] = testSP
	c := aapcs32{}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: entry, Return: 0xFFFFFF00, Args: args}); err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	return b
}

// TestPrepareCallPairMatrix pins the AAPCS32 register-pair rules — the
// whole reason Architecture Exception #1 exists (cases):
//
//	f(u32 a, u64 b)       -> a=r0, r1 SKIPPED (never written), b=r2:r3
//	f(u64 a, u32 b)       -> a=r0:r1, b=r2
//	f(u32 x3, u64)        -> words r0..r2, r3 skipped, u64 wholly on stack
//	f(u32 x4, u64)        -> words r0..r3, u64 wholly on stack (8-aligned)
//	f(u64, u64, u64)      -> r0:r1, r2:r3, third wholly on stack
//	f(u32 x4, u32, u64)   -> 5th word stack+0, u64 stack+8 (padding at +4)
func TestPrepareCallPairMatrix(t *testing.T) {
	t.Run("u32 then u64 skips r1", func(t *testing.T) {
		b := prepare(t, 0x1000, word(0xAAAA), u64(0x1122334455667788))
		if got := b.regs[R0]; got != 0xAAAA {
			t.Fatalf("r0 = %#x, want 0xaaaa", got)
		}
		if _, written := b.writes[R1]; written {
			t.Fatalf("r1 = %#x, want NEVER WRITTEN (skipped for pair alignment)", b.writes[R1])
		}
		if b.regs[R2] != 0x55667788 || b.regs[R3] != 0x11223344 {
			t.Fatalf("r2:r3 = %#x:%#x, want 0x55667788:0x11223344 (little-endian pair)", b.regs[R2], b.regs[R3])
		}
		if got := b.regs[SP]; got != testSP {
			t.Fatalf("SP = %#x, want unchanged (no spill)", got)
		}
	})
	t.Run("u64 then u32 packs tight", func(t *testing.T) {
		b := prepare(t, 0x1000, u64(0x1122334455667788), word(0xBBBB))
		if b.regs[R0] != 0x55667788 || b.regs[R1] != 0x11223344 || b.regs[R2] != 0xBBBB {
			t.Fatalf("r0:r1:r2 = %#x:%#x:%#x, want 0x55667788:0x11223344:0xbbbb", b.regs[R0], b.regs[R1], b.regs[R2])
		}
	})
	t.Run("three words then u64 skips r3 and spills", func(t *testing.T) {
		b := prepare(t, 0x1000, word(1), word(2), word(3), u64(0xA5A5A5A5A5A5A5A5))
		if _, written := b.writes[R3]; written {
			t.Fatalf("r3 = %#x, want NEVER WRITTEN (pair cannot straddle r3+stack)", b.writes[R3])
		}
		sp := b.regs[SP]
		if sp != testSP-8 {
			t.Fatalf("SP = %#x, want %#x (8-byte spill, 8-aligned)", sp, uint64(testSP-8))
		}
		if b.u32(sp) != 0xA5A5A5A5 || b.u32(sp+4) != 0xA5A5A5A5 {
			t.Fatalf("stack u64 = %#x:%#x, want the pair at SP+0", b.u32(sp), b.u32(sp+4))
		}
	})
	t.Run("four words then u64 spills 8-aligned", func(t *testing.T) {
		b := prepare(t, 0x1000, word(1), word(2), word(3), word(4), u64(0xDEADBEEFCAFEF00D))
		if b.regs[R0] != 1 || b.regs[R1] != 2 || b.regs[R2] != 3 || b.regs[R3] != 4 {
			t.Fatalf("r0..r3 = %v, want 1,2,3,4", []uint64{b.regs[R0], b.regs[R1], b.regs[R2], b.regs[R3]})
		}
		sp := b.regs[SP]
		if sp != testSP-8 || sp%8 != 0 {
			t.Fatalf("SP = %#x, want %#x (8-aligned)", sp, uint64(testSP-8))
		}
		if b.u32(sp) != 0xCAFEF00D || b.u32(sp+4) != 0xDEADBEEF {
			t.Fatalf("stack u64 = %#x:%#x at SP, want lo:hi 0xcafef00d:0xdeadbeef", b.u32(sp), b.u32(sp+4))
		}
	})
	t.Run("three u64s: last one spills", func(t *testing.T) {
		b := prepare(t, 0x1000, u64(1), u64(2), u64(3))
		if b.regs[R0] != 1 || b.regs[R1] != 0 || b.regs[R2] != 2 || b.regs[R3] != 0 {
			t.Fatalf("regs = %#x:%#x:%#x:%#x, want 1:0:2:0", b.regs[R0], b.regs[R1], b.regs[R2], b.regs[R3])
		}
		sp := b.regs[SP]
		if sp != testSP-8 || b.u32(sp) != 3 || b.u32(sp+4) != 0 {
			t.Fatalf("spill = %#x:%#x at SP %#x, want u64(3) at %#x", b.u32(sp), b.u32(sp+4), sp, uint64(testSP-8))
		}
	})
	t.Run("word spill then u64 keeps 8-byte alignment with padding", func(t *testing.T) {
		b := prepare(t, 0x1000, word(1), word(2), word(3), word(4), word(5), u64(0x1122334455667788))
		sp := b.regs[SP]
		if sp != testSP-16 {
			t.Fatalf("SP = %#x, want %#x (4-byte word + 4 pad + 8-byte u64)", sp, uint64(testSP-16))
		}
		if got := b.u32(sp); got != 5 {
			t.Fatalf("stack word = %#x at SP+0, want 5", got)
		}
		if b.u32(sp+8) != 0x55667788 || b.u32(sp+12) != 0x11223344 {
			t.Fatalf("stack u64 = %#x:%#x at SP+8 (8-aligned), want lo:hi", b.u32(sp+8), b.u32(sp+12))
		}
	})
	t.Run("ArgPtr is a single word slot", func(t *testing.T) {
		b := prepare(t, 0x1000, arch.CallArg{Value: 0xCAFE, Kind: arch.ArgPtr}, u64(9))
		if b.regs[R0] != 0xCAFE || b.regs[R2] != 9 {
			t.Fatalf("r0/r2 = %#x/%#x, want 0xcafe/9 (ptr word, pair at r2:r3)", b.regs[R0], b.regs[R2])
		}
	})
	t.Run("odd spill size still lands the arg at the 8-aligned SP", func(t *testing.T) {
		b := prepare(t, 0x1000, word(1), word(2), word(3), word(4), word(5))
		sp := b.regs[SP]
		if sp != testSP-8 {
			t.Fatalf("SP = %#x, want %#x (4-byte spill rounded down to 8)", sp, uint64(testSP-8))
		}
		if got := b.u32(sp); got != 5 {
			t.Fatalf("stack word = %#x at SP+0, want 5 (ReadArgs slot 4 reads [SP])", got)
		}
	})
}

// TestPrepareCallFrame pins the non-argument frame effects: LR verbatim
// (its bit0 is the caller's ISA state) and the PC set with BX semantics.
func TestPrepareCallFrame(t *testing.T) {
	t.Run("even entry selects ARM state", func(t *testing.T) {
		b := prepare(t, 0x1000)
		b.regs[CPSR] = cpsrT // pre-set: must be CLEARED by the even entry
		prepare2(t, b, 0x1000)
		if got := b.regs[PC]; got != 0x1000 {
			t.Fatalf("PC = %#x, want 0x1000", got)
		}
		if b.regs[CPSR]&cpsrT != 0 {
			t.Fatalf("CPSR.T set for an even entry, want clear (ARM state)")
		}
		if got := b.regs[LR]; got != 0xFFFFFF00 {
			t.Fatalf("LR = %#x, want the return address verbatim", got)
		}
	})
	t.Run("odd entry selects Thumb state and strips bit0", func(t *testing.T) {
		b := newRegRec()
		b.regs[SP] = testSP
		c := aapcs32{}
		if err := c.PrepareCall(b, arch.CallRequest{Entry: 0x1001, Return: 0xFFFFFF01, Args: nil}); err != nil {
			t.Fatal(err)
		}
		if got := b.regs[PC]; got != 0x1000 {
			t.Fatalf("PC = %#x, want 0x1000 (bit0 stripped)", got)
		}
		if b.regs[CPSR]&cpsrT == 0 {
			t.Fatalf("CPSR.T clear for an odd entry, want set (Thumb state)")
		}
		if got := b.regs[LR]; got != 0xFFFFFF01 {
			t.Fatalf("LR = %#x, want verbatim 0xffffff01 (bit0 preserved for the return)", got)
		}
	})
}

// prepare2 reruns PrepareCall on an existing fake (for CPSR preset tests).
func prepare2(t *testing.T, b *regRec, entry emu.GuestAddr, args ...arch.CallArg) {
	t.Helper()
	c := aapcs32{}
	if err := c.PrepareCall(b, arch.CallRequest{Entry: entry, Return: 0xFFFFFF00, Args: args}); err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
}

// TestReadArgsWordView pins the raw slot view: r0..r3 then stack words —
// a wide argument is two slots, a skipped register keeps its stale value,
// and regrouping is the reader's (signature-aware) business.
func TestReadArgsWordView(t *testing.T) {
	c := aapcs32{}
	b := newRegRec()
	b.regs[R0], b.regs[R1], b.regs[R2], b.regs[R3] = 0x11, 0xDEAD, 0x22, 0x33
	b.regs[SP] = 0x7000
	for i, v := range []byte{0x44, 0, 0, 0, 0x55, 0, 0, 0} {
		b.mem[0x7000+uint64(i)] = v
	}
	args, err := c.ReadArgs(b, 6)
	if err != nil {
		t.Fatalf("ReadArgs: %v", err)
	}
	want := []uint64{0x11, 0xDEAD, 0x22, 0x33, 0x44, 0x55}
	for i, w := range want {
		if args[i] != w {
			t.Fatalf("args[%d] = %#x, want %#x", i, args[i], w)
		}
	}
	if _, err := c.ReadArgs(b, -1); err == nil {
		t.Fatal("ReadArgs(-1) must error")
	}
}

// TestResultRoundTrip pins r0/r1 result access (64-bit results ride r0:r1).
func TestResultRoundTrip(t *testing.T) {
	c := aapcs32{}
	b := newRegRec()
	if err := c.WriteResult(b, arch.CallResult{Value: 0x55667788, Value2: 0x11223344}); err != nil {
		t.Fatal(err)
	}
	res, err := c.ReadResult(b)
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != 0x55667788 || res.Value2 != 0x11223344 {
		t.Fatalf("result = %#x:%#x, want 0x55667788:0x11223344", res.Value, res.Value2)
	}
}

// TestReturnFromCallBX pins the interworking return: LR bit0 selects the
// ISA state, PC becomes even.
func TestReturnFromCallBX(t *testing.T) {
	c := aapcs32{}
	b := newRegRec()
	b.regs[LR] = 0x2001 // Thumb return
	if err := c.ReturnFromCall(b); err != nil {
		t.Fatal(err)
	}
	if b.regs[PC] != 0x2000 || b.regs[CPSR]&cpsrT == 0 {
		t.Fatalf("PC=%#x CPSR=%#x, want PC 0x2000 + Thumb state", b.regs[PC], b.regs[CPSR])
	}
	b.regs[LR] = 0x2000 // ARM return
	if err := c.ReturnFromCall(b); err != nil {
		t.Fatal(err)
	}
	if b.regs[PC] != 0x2000 || b.regs[CPSR]&cpsrT != 0 {
		t.Fatalf("PC=%#x CPSR=%#x, want PC 0x2000 + ARM state", b.regs[PC], b.regs[CPSR])
	}
}

// TestIntrospector pins ArgReg/ResultReg.
func TestIntrospector(t *testing.T) {
	c := aapcs32{}
	for i, want := range []emu.Reg{R0, R1, R2, R3} {
		if got, ok := c.ArgReg(i); !ok || got != want {
			t.Fatalf("ArgReg(%d) = (%v, %v), want (%v, true)", i, got, ok, want)
		}
	}
	if _, ok := c.ArgReg(4); ok {
		t.Fatal("ArgReg(4) must be ok=false (stack slot)")
	}
	if r0, _ := c.ResultReg(0); r0 != R0 {
		t.Fatalf("ResultReg(0) = %v, want R0", r0)
	}
	if r1, _ := c.ResultReg(1); r1 != R1 {
		t.Fatalf("ResultReg(1) = %v, want R1", r1)
	}
	if _, ok := c.ResultReg(2); ok {
		t.Fatal("ResultReg(2) must be ok=false")
	}
}
