package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// trapBE is a minimal emu.Backend for driving onInterrupt without a CPU
// engine: programmable PC/X8, recorded register writes. Everything else
// panics via the nil embedded interface.
type trapBE struct {
	emu.Backend
	pc     uint64
	x8     uint64
	writes map[emu.Reg]uint64
}

func (b *trapBE) RegRead(r emu.Reg) (uint64, error) {
	switch r {
	case arm64.PC:
		return b.pc, nil
	case arm64.X8:
		return b.x8, nil
	}
	return 0, nil
}

func (b *trapBE) RegWrite(r emu.Reg, v uint64) error {
	if b.writes == nil {
		b.writes = map[emu.Reg]uint64{}
	}
	b.writes[r] = v
	return nil
}

// newTrapEmu builds an Emulator for interrupt-dispatch tests through the
// shared test constructor (full Arch/CallABI triple + role regs +
// transport/table/codecs injected); tests that want a specific backend pass
// it in, and may still nil out e.kctx to prove the stub path never reaches
// the kernel.
func newTrapEmu(t *testing.T, be emu.Backend) *Emulator {
	t.Helper()
	return newTestEmulator(t, be)
}

// Negative test ①: a trap whose source address is a stub must be dispatched
// to the stub table and must NOT fall through into the kernel syscall
// dispatcher (scCount stays 0; kctx is nil, so any fall-through would panic).
func TestHostCallStubSkipsKernelDispatch(t *testing.T) {
	svc := legacyARM64Layout.StubBase // inside the stub region
	be := &trapBE{pc: svc + 4}        // the engine has advanced PC past the svc
	e := newTrapEmu(t, be)
	e.stubs[svc] = "unresolved_import"
	e.kctx = nil // a fall-through into kctx.DispatchFrame would nil-panic

	e.onInterrupt(be, 0)

	if e.stubHits["unresolved_import"] != 1 {
		t.Fatalf("stub hit not recorded: %v", e.stubHits)
	}
	if e.scCount != 0 {
		t.Fatalf("syscall counter moved on a stub hit: %d", e.scCount)
	}
	if v, ok := be.writes[e.retReg]; !ok || v != 0 {
		t.Fatalf("stub must write the optimistic 0 return, writes=%v", be.writes)
	}
}

// Negative test ②: a real guest syscall (trap source OUTSIDE the stub table,
// e.g. bionic's own svc) must NOT be classified as a host-call stub — it
// falls through to the kernel dispatcher (scCount advances, -ENOSYS written
// back for the unimplemented number, stubHits untouched).
func TestGuestSyscallNotClassifiedAsStub(t *testing.T) {
	be := &trapBE{pc: 0x12000004, x8: 99999} // module region; unimplemented nr
	e := newTrapEmu(t, be)                   // kctx injected with transport+table by newTestEmulator

	e.onInterrupt(be, 0)

	if len(e.stubHits) != 0 {
		t.Fatalf("guest syscall misclassified as stub: %v", e.stubHits)
	}
	if e.scCount != 1 {
		t.Fatalf("syscall counter must advance to 1, got %d", e.scCount)
	}
	var ret int64 = -38 // -kernel.ENOSYS, as the dispatcher encodes it
	if got, want := be.writes[e.retReg], uint64(ret); got != want {
		t.Fatalf("syscall result = %#x, want %#x (-ENOSYS)", got, want)
	}
}
