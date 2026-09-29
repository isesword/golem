package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// machMsgTrap is the wire form of Mach trap number -31 (mach_msg_trap):
// int64 -31 as uint64. (A named constant because uint64(-31) does not
// compile — a negative constant overflows.)
const machMsgTrap = uint64(0xFFFFFFFFFFFFFFE1)

// regBE is a register-file-only emu.Backend test double (same shape as the
// Android transport tests): the transport and dispatch boundary tests below
// never touch guest memory, so everything else panics loudly via the nil
// embedded interface.
type regBE struct {
	emu.Backend
	regs   map[emu.Reg]uint64
	writes []emu.Reg // every RegWrite, in call order of arrival
}

func newRegBE() *regBE { return &regBE{regs: map[emu.Reg]uint64{}} }

func (b *regBE) RegRead(r emu.Reg) (uint64, error) { return b.regs[r], nil }
func (b *regBE) RegWrite(r emu.Reg, v uint64) error {
	b.regs[r] = v
	b.writes = append(b.writes, r)
	return nil
}

// --- Decode: x16 number + x0..x5 args, NArg=6 ---

func TestTransportDecode(t *testing.T) {
	be := newRegBE()
	be.regs[arm64.X16] = SYS_getpid
	for i, r := range []emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5} {
		be.regs[r] = uint64(0x100 * (i + 1))
	}
	tr := NewARM64Transport()
	f, err := tr.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	if f.Num != SYS_getpid {
		t.Errorf("Num = %d, want %d (x16, NOT Linux's x8)", f.Num, SYS_getpid)
	}
	if f.NArg != 6 {
		t.Errorf("NArg = %d, want 6", f.NArg)
	}
	for i := 0; i < 6; i++ {
		if want := uint64(0x100 * (i + 1)); f.Args[i] != want {
			t.Errorf("Args[%d] = %#x, want %#x (x%d)", i, f.Args[i], want, i)
		}
	}
	if tr.mach {
		t.Error("positive number must NOT be classified as a Mach trap")
	}
}

// --- success: carry CLEAR, x0 = Value, x1 = Value2 (the dual return value
// Linux ignores) ---

func TestTransportEncodeSuccess(t *testing.T) {
	be := newRegBE()
	be.regs[arm64.NZCV] = nzcvCarry // a set carry MUST be cleared
	tr := NewARM64Transport()
	if _, err := tr.Decode(be); err != nil { // x16 = 0 -> unix class
		t.Fatal(err)
	}
	if err := tr.EncodeResult(be, kernel.Result{Value: 42, Value2: 7}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != 42 {
		t.Errorf("x0 = %d, want 42", got)
	}
	if got := be.regs[arm64.X1]; got != 7 {
		t.Errorf("x1 = %d, want 7 (Value2 is carried on Darwin)", got)
	}
	if got := be.regs[arm64.NZCV]; got&nzcvCarry != 0 {
		t.Errorf("NZCV = %#x, carry must be CLEAR on success", got)
	}
}

// --- failure: carry SET, x0 = errno with the Darwin numbering (ENOSYS
// 38 -> 78; the coinciding low numbers pass through) ---

func TestTransportEncodeErrno(t *testing.T) {
	be := newRegBE()
	tr := NewARM64Transport()
	if _, err := tr.Decode(be); err != nil {
		t.Fatal(err)
	}
	if err := tr.EncodeResult(be, kernel.Result{Errno: kernel.ENOSYS}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != 78 {
		t.Errorf("x0 = %d, want 78 (Darwin ENOSYS; kernel carries Linux's 38)", got)
	}
	if got := be.regs[arm64.NZCV]; got&nzcvCarry == 0 {
		t.Errorf("NZCV = %#x, carry must be SET on error", got)
	}
	// Other flags in NZCV must survive the read-modify-write.
	be.regs[arm64.NZCV] = 0x80000000 // N set
	if err := tr.EncodeResult(be, kernel.Result{Errno: kernel.EBADF}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != 9 {
		t.Errorf("x0 = %d, want 9 (EBADF coincides on both kernels)", got)
	}
	if got := be.regs[arm64.NZCV]; got != 0x80000000|nzcvCarry {
		t.Errorf("NZCV = %#x, want N preserved + C set (%#x)", got, 0x80000000|nzcvCarry)
	}
}

// --- Mach trap (x16 negative): kern_return_t in x0, carry untouched ---

func TestTransportEncodeMachTrap(t *testing.T) {
	be := newRegBE()
	be.regs[arm64.X16] = machMsgTrap // mach_msg_trap (x16 = -31)
	be.regs[arm64.NZCV] = 0          // must stay clear: Mach has no carry convention
	tr := NewARM64Transport()
	f, err := tr.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.mach {
		t.Fatal("negative x16 must be classified as a Mach trap")
	}
	if err := tr.EncodeResult(be, kernel.Result{Errno: kernel.ENOSYS}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != uint64(kernel.ENOSYS) {
		t.Errorf("x0 = %d, want %d (kern_return_t-style direct return)", got, kernel.ENOSYS)
	}
	if got := be.regs[arm64.NZCV]; got != 0 {
		t.Errorf("NZCV = %#x, Mach traps must not touch the carry flag", got)
	}
	_ = f
}

// --- end-to-end: the real table + transport through kernel.Context.Dispatch.
// getpid (20) -> Pid, carry clear; an unimplemented number -> carry set,
// x0 = 78; a Mach trap misses the table identically (huge uint64). ---

func TestDispatchEndToEnd(t *testing.T) {
	be := newRegBE()
	ctx := &kernel.Context{
		B: be, Pid: 4242,
		Transport: NewARM64Transport(),
		Table:     NewARM64SyscallTable(kernel.DefaultHandlers()),
		Codecs:    XNUARM64Codecs{},
	}

	be.regs[arm64.X16] = SYS_getpid
	ctx.Dispatch()
	if be.regs[arm64.X0] != 4242 {
		t.Fatalf("getpid x0 = %d, want 4242", be.regs[arm64.X0])
	}
	if be.regs[arm64.NZCV]&nzcvCarry != 0 {
		t.Fatal("getpid success must clear the carry flag")
	}

	be.regs[arm64.X16] = 9999 // not in the table
	ctx.Dispatch()
	if be.regs[arm64.X0] != 78 {
		t.Fatalf("unimplemented syscall x0 = %d, want 78 (Darwin ENOSYS)", be.regs[arm64.X0])
	}
	if be.regs[arm64.NZCV]&nzcvCarry == 0 {
		t.Fatal("unimplemented syscall must set the carry flag")
	}

	be.regs[arm64.X16] = machMsgTrap // mach_msg_trap: no handler, Mach encoding
	be.regs[arm64.NZCV] = 0
	ctx.Dispatch()
	if be.regs[arm64.NZCV]&nzcvCarry != 0 {
		t.Fatal("a Mach trap miss must NOT go through the unix carry encoding")
	}
}
