package android

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// regBE is a register-file-only emu.Backend test double: the transport and
// dispatch boundary tests below never touch guest memory, so everything else
// panics loudly via the nil embedded interface.
type regBE struct {
	emu.Backend
	regs   map[emu.Reg]uint64
	writes map[emu.Reg]uint64 // every RegWrite, in call order of arrival
}

func newRegBE() *regBE {
	return &regBE{regs: map[emu.Reg]uint64{}, writes: map[emu.Reg]uint64{}}
}

// negErrno is the Linux wire encoding of an errno: two's complement in x0.
// (A function, not constant arithmetic — uint64(-38) is a compile error.)
func negErrno(e kernel.Errno) uint64 { return uint64(-int64(e)) }

func (b *regBE) RegRead(r emu.Reg) (uint64, error)  { return b.regs[r], nil }
func (b *regBE) RegWrite(r emu.Reg, v uint64) error { b.regs[r] = v; b.writes[r] = v; return nil }

// --- (c) Decode: x8 number + x0..x5 args, NArg=6 ---

func TestTransportDecode(t *testing.T) {
	be := newRegBE()
	be.regs[arm64.X8] = kernel.SYS_mmap
	for i, r := range []emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5} {
		be.regs[r] = uint64(0x100 * (i + 1))
	}
	f, err := LinuxARM64Transport{}.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	if f.Num != kernel.SYS_mmap {
		t.Errorf("Num = %d, want %d (x8)", f.Num, kernel.SYS_mmap)
	}
	if f.NArg != 6 {
		t.Errorf("NArg = %d, want 6", f.NArg)
	}
	for i := 0; i < 6; i++ {
		if want := uint64(0x100 * (i + 1)); f.Args[i] != want {
			t.Errorf("Args[%d] = %#x, want %#x (x%d)", i, f.Args[i], want, i)
		}
	}
}

// --- (b) success: Result{Value: N} encodes to x0 = N ---

func TestTransportEncodeSuccess(t *testing.T) {
	be := newRegBE()
	be.regs[arm64.X0] = 0xdeadbeef // must be overwritten
	if err := (LinuxARM64Transport{}).EncodeResult(be, kernel.Result{Value: 42}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != 42 {
		t.Fatalf("x0 = %#x, want 42", got)
	}
}

// --- (a) failure: Result{Errno: ENOSYS} encodes to x0 = -ENOSYS ---

func TestTransportEncodeErrno(t *testing.T) {
	be := newRegBE()
	if err := (LinuxARM64Transport{}).EncodeResult(be, kernel.Result{Errno: kernel.ENOSYS}); err != nil {
		t.Fatal(err)
	}
	want := negErrno(kernel.ENOSYS)
	if got := be.regs[arm64.X0]; got != want {
		t.Fatalf("x0 = %#x, want %#x (-ENOSYS two's complement)", got, want)
	}
}

// --- (e) Value2: Linux ignores it; only x0 is ever written. Darwin will
// encode Value2 into x1 + manage the carry flag — Result carrying Value2 must
// not disturb the Linux encoding. ---

func TestTransportIgnoresValue2(t *testing.T) {
	be := newRegBE()
	if err := (LinuxARM64Transport{}).EncodeResult(be, kernel.Result{Value: 7, Value2: 9}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm64.X0]; got != 7 {
		t.Fatalf("x0 = %d, want 7", got)
	}
	if len(be.writes) != 1 {
		t.Fatalf("Linux transport must write exactly x0, wrote %d registers: %v", len(be.writes), be.writes)
	}
	if _, ok := be.writes[arm64.X1]; ok {
		t.Fatal("Value2 must NOT leak into x1 on Linux (that is the Darwin encoding)")
	}
}

// --- end-to-end: unimplemented syscall -> ENOSYS through the real
// transport/table -> x0 = -ENOSYS; implemented syscall -> its value. ---

func TestDispatchEndToEnd(t *testing.T) {
	be := newRegBE()
	ctx := &kernel.Context{
		B: be, Pid: 4242,
		Transport: LinuxARM64Transport{},
		Table:     NewSyscallTable(),
		Codecs:    AsmGenericLP64Codecs{},
	}

	be.regs[arm64.X8] = 9999 // not in the table
	ctx.Dispatch()
	if want := negErrno(kernel.ENOSYS); be.regs[arm64.X0] != want {
		t.Fatalf("unimplemented syscall x0 = %#x, want %#x (-ENOSYS)", be.regs[arm64.X0], want)
	}

	be.regs[arm64.X8] = kernel.SYS_getpid
	ctx.Dispatch()
	if be.regs[arm64.X0] != 4242 {
		t.Fatalf("getpid x0 = %d, want 4242", be.regs[arm64.X0])
	}
}
