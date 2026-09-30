package emulator

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// jniStubBE is a registers-and-memory stub: RegRead/RegWrite serve the
// canned call-ABI argument and result registers (arg n = Xn, result = X0),
// MemRead/MemWrite serve a tiny scratch area — just enough to drive
// handleJNI without an engine.
type jniStubBE struct {
	regs  map[emu.Reg]uint64
	guest map[uint64][]byte // MemRead source
	wrote map[uint64][]byte // MemWrite record
}

func (b *jniStubBE) RegRead(r emu.Reg) (uint64, error)  { return b.regs[r], nil }
func (b *jniStubBE) RegWrite(r emu.Reg, v uint64) error { b.regs[r] = v; return nil }
func (b *jniStubBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	if d, ok := b.guest[uint64(addr)]; ok && uint64(len(d)) >= size {
		return d[:size], nil
	}
	return nil, errors.New("unmapped")
}
func (b *jniStubBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	cp := make([]byte, len(data))
	copy(cp, data)
	b.wrote[uint64(addr)] = cp
	return nil
}
func (b *jniStubBE) MemMap(emu.GuestAddr, uint64, int) error                    { return nil }
func (b *jniStubBE) MemUnmap(emu.GuestAddr, uint64) error                       { return nil }
func (b *jniStubBE) MemProtect(emu.GuestAddr, uint64, int) error                { return nil }
func (b *jniStubBE) MemMapPtr(emu.GuestAddr, uint64, int, unsafe.Pointer) error { return nil }
func (b *jniStubBE) InstallTrap(emu.TrapKind, emu.TrapHandler) (emu.HookHandle, error) {
	return nil, nil
}
func (b *jniStubBE) Start(emu.GuestAddr, emu.GuestAddr) error              { return nil }
func (b *jniStubBE) StartCount(emu.GuestAddr, emu.GuestAddr, uint64) error { return nil }
func (b *jniStubBE) Stop() error                                           { return nil }
func (b *jniStubBE) Close() error                                          { return nil }

// TestGuestJNIArrayCaps pins the P7.6 policy on the JNI array surface: a
// guest-supplied length never sizes a host allocation (NewByteArray over
// cap refuses with JNI NULL), and the array-region bounds are uint64-safe —
// the old int(start+ln) WRAPPED for huge values (2^63+2^63 → 0) and sliced
// out of range; out-of-range now leaves a pending exception, like ART's
// ArrayIndexOutOfBoundsException.
func TestGuestJNIArrayCaps(t *testing.T) {
	be := &jniStubBE{
		regs:  map[emu.Reg]uint64{},
		guest: map[uint64][]byte{},
		wrote: map[uint64][]byte{},
	}
	e := newTestEmulator(t, be) // in-bounds region paths MemWrite through e.be
	e.vm = dvm.NewVM()

	// NewByteArray: normal length allocates a live 5-element array...
	be.regs[arm64.X1] = 5
	e.handleJNI(jniNewByteArray, be)
	ref := dvm.Ref(int32(be.regs[arm64.X0]))
	if ref == 0 {
		t.Fatal("NewByteArray(5) must allocate")
	}
	o := e.vm.Deref(ref)
	if o == nil {
		t.Fatal("NewByteArray(5) returned a dangling ref")
	}
	if bs, ok := o.Value.([]byte); !ok || len(bs) != 5 {
		t.Fatalf("NewByteArray(5) = %T(%v), want 5-byte array", o.Value, o.Value)
	}

	// ...and an over-cap length refuses with JNI NULL — never a giant make().
	be.regs[arm64.X1] = kernel.MaxGuestIO + 1
	e.handleJNI(jniNewByteArray, be)
	if be.regs[arm64.X0] != 0 {
		t.Fatalf("over-cap NewByteArray = %#x, want JNI NULL", be.regs[arm64.X0])
	}

	// GetByteArrayRegion: huge start+len must not wrap into a false pass.
	arr := dvm.NewByteArray(e.vm, []byte{1, 2, 3, 4})
	be.regs[arm64.X1] = uint64(uint32(arr))
	be.regs[arm64.X2] = 1 << 63 // start
	be.regs[arm64.X3] = 1 << 63 // len: start+len wraps to 0 in int arithmetic
	be.regs[arm64.X4] = 0x9000
	e.handleJNI(jniGetByteArrayRegion, be)
	if !e.pendingExc {
		t.Fatal("out-of-bounds GetByteArrayRegion must leave a pending exception")
	}
	e.pendingExc = false

	// In-bounds region still copies (bytes 1..2 of {1,2,3,4}).
	be.regs[arm64.X2] = 1
	be.regs[arm64.X3] = 2
	e.handleJNI(jniGetByteArrayRegion, be)
	if d := be.wrote[0x9000]; len(d) != 2 || d[0] != 2 || d[1] != 3 {
		t.Fatalf("in-bounds GetByteArrayRegion wrote %v, want [2 3]", d)
	}

	// SetByteArrayRegion: same wrap guard, then the in-bounds copy-back.
	be.regs[arm64.X2] = 1 << 63
	be.regs[arm64.X3] = 1 << 63
	e.handleJNI(jniSetByteArrayRegion, be)
	if !e.pendingExc {
		t.Fatal("out-of-bounds SetByteArrayRegion must leave a pending exception")
	}
	e.pendingExc = false
	be.regs[arm64.X2] = 2
	be.regs[arm64.X3] = 2
	be.guest[0x9000] = []byte{0xAA, 0xBB}
	e.handleJNI(jniSetByteArrayRegion, be)
	if o := e.vm.Deref(arr); o == nil {
		t.Fatal("array ref went dangling")
	} else if bs := o.Value.([]byte); bs[2] != 0xAA || bs[3] != 0xBB {
		t.Fatalf("SetByteArrayRegion left %v, want [1 2 170 187]", bs)
	}
}
