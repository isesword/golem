package darwin

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// memRec is a platform.MemWriter test double recording every write.
type memRec struct {
	writes map[uint64][]byte
}

func newMemRec() *memRec { return &memRec{writes: map[uint64][]byte{}} }

func (m *memRec) MemWrite(addr emu.GuestAddr, data []byte) error {
	m.writes[uint64(addr)] = append([]byte(nil), data...)
	return nil
}

func (m *memRec) read64(addr uint64) uint64 {
	for base, d := range m.writes {
		if addr >= base && addr+8 <= base+uint64(len(d)) {
			return binary.LittleEndian.Uint64(d[addr-base:])
		}
	}
	return 0
}

func (m *memRec) readStr(addr uint64) string {
	for base, d := range m.writes {
		if addr >= base && addr < base+uint64(len(d)) {
			tail := d[addr-base:]
			for i, b := range tail {
				if b == 0 {
					return string(tail[:i])
				}
			}
		}
	}
	return ""
}

func startupCtx(mem *memRec) *platform.StartupContext {
	return &platform.StartupContext{
		Stack: memory.Region{Addr: 0xB0000000, Size: 0x800000},
		Mem:   mem,
		// Features deliberately nil: the Darwin StartupABI must NOT consult
		// the arch feature set — the HWCAP/auxv coupling is Android-only.
	}
}

// TestInitialStackFrame pins the exec-style frame: argc at SP =
// stack-top - StackTopReserve, argv0 + apple0 pointing at the string, all
// terminators zero. And the headline: NO auxv exists anywhere in this ABI.
func TestInitialStackFrame(t *testing.T) {
	mem := newMemRec()
	ctx := startupCtx(mem)
	s := &StartupABI{}
	if err := s.BuildInitialState(ctx); err != nil {
		t.Fatal(err)
	}

	sp := uint64(ctx.Stack.Addr) + uint64(ctx.Stack.Size) - StackTopReserve
	if sp%16 != 0 {
		t.Fatalf("SP = %#x, want 16-aligned", sp)
	}
	if got := uint64(s.StackTop()); got != sp {
		t.Fatalf("StackTop = %#x, want %#x (boot sets SP from StackTopReserve)", got, sp)
	}
	if got := mem.read64(sp); got != 1 {
		t.Fatalf("argc = %d, want 1", got)
	}
	argv0Ptr := mem.read64(sp + 8)
	if argv0Ptr == 0 || mem.readStr(argv0Ptr) != argv0 {
		t.Fatalf("argv[0] = %#x -> %q, want %q", argv0Ptr, mem.readStr(argv0Ptr), argv0)
	}
	if got := mem.read64(sp + 16); got != 0 {
		t.Fatalf("argv terminator = %#x, want 0", got)
	}
	if got := mem.read64(sp + 24); got != 0 {
		t.Fatalf("envp terminator = %#x, want 0 (empty environment)", got)
	}
	if got := mem.read64(sp + 32); got != argv0Ptr {
		t.Fatalf("apple[0] = %#x, want the executable_path string %#x", got, argv0Ptr)
	}
	if got := mem.read64(sp + 40); got != 0 {
		t.Fatalf("apple terminator = %#x, want 0", got)
	}
}

func TestStartupBuildsOnce(t *testing.T) {
	s := &StartupABI{}
	if err := s.BuildInitialState(startupCtx(newMemRec())); err != nil {
		t.Fatal(err)
	}
	if err := s.BuildInitialState(startupCtx(newMemRec())); err == nil {
		t.Fatal("a second BuildInitialState must error")
	}
}

func TestStartupValidation(t *testing.T) {
	s := &StartupABI{}
	if err := s.BuildInitialState(nil); err == nil {
		t.Fatal("nil context must error")
	}
	ctx := startupCtx(newMemRec())
	ctx.Mem = nil
	if err := s.BuildInitialState(ctx); err == nil {
		t.Fatal("nil Mem must error")
	}
	ctx = startupCtx(newMemRec())
	ctx.Stack.Size = 0x10
	if err := s.BuildInitialState(ctx); err == nil {
		t.Fatal("a stack smaller than StackTopReserve must error")
	}
}
