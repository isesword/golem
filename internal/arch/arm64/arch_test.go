package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// regRec is an emu.Backend test double with a programmable register file and
// guest memory: RegRead serves preset values, RegWrite is recorded (and kept
// readable, for stack pop sequences), MemRead serves recorded/preset bytes.
// Everything else panics via the nil embedded interface.
type regRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	regs        map[emu.Reg]uint64
	writes      map[emu.Reg]uint64
	mem         map[uint64][]byte // addr -> bytes
}

func (r *regRec) RegRead(reg emu.Reg) (uint64, error) { return r.regs[reg], nil }

func (r *regRec) RegWrite(reg emu.Reg, v uint64) error {
	if r.writes == nil {
		r.writes = map[emu.Reg]uint64{}
	}
	r.writes[reg] = v
	if r.regs == nil {
		r.regs = map[emu.Reg]uint64{}
	}
	r.regs[reg] = v // keep reads consistent with writes (stack pop sequences)
	return nil
}

func (r *regRec) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		if b, ok := r.mem[uint64(addr)+uint64(i)]; ok {
			out[i] = b[0]
		}
	}
	return out, nil
}

func (r *regRec) MemWrite(addr emu.GuestAddr, data []byte) error {
	if r.mem == nil {
		r.mem = map[uint64][]byte{}
	}
	for i, b := range data {
		r.mem[uint64(addr)+uint64(i)] = []byte{b}
	}
	return nil
}

// setU64 presets a little-endian qword in the fake guest memory.
func (r *regRec) setU64(addr uint64, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	_ = r.MemWrite(emu.GuestAddr(addr), b[:])
}

// getU64 reads a little-endian qword back from the fake guest memory.
func (r *regRec) getU64(addr uint64) uint64 {
	raw, _ := r.MemRead(emu.GuestAddr(addr), 8)
	return binary.LittleEndian.Uint64(raw)
}

// resolveQuad resolves the registered (Arch, CallABI, StubEncoder,
// CPUFeatures) quad for (IDARM64, VariantGeneric); this package's init must
// have registered it.
func resolveQuad(t *testing.T) (arch.Arch, arch.CallABI, arch.StubEncoder, arch.CPUFeatures) {
	t.Helper()
	a, c, s, f, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("arm64 target quad must be registered by this package's init: %v", err)
	}
	return a, c, s, f
}

func TestQuadRegistration(t *testing.T) {
	a, c, s, f := resolveQuad(t)
	if a == nil || c == nil || s == nil || f == nil {
		t.Fatal("Resolve must return a non-nil Arch, CallABI, StubEncoder and CPUFeatures")
	}
	if a.EngineArch() != emu.ArchARM64 {
		t.Fatalf("EngineArch = %v, want ArchARM64", a.EngineArch())
	}
}

// TestARM64EQuadRegistration pins the variant contract: (IDARM64,
// VariantARM64E) resolves to the SAME quad components as VariantGeneric —
// ARM64E is one engine architecture; the variant difference (authenticated
// chained fixups) is the loader's business, not a forked core Arch.
func TestARM64EQuadRegistration(t *testing.T) {
	g, gc, gs, gf := resolveQuad(t)
	e, ec, es, ef, err := arch.Resolve(arch.IDARM64, arch.VariantARM64E)
	if err != nil {
		t.Fatalf("Resolve(IDARM64, VariantARM64E): %v", err)
	}
	if e != g || ec != gc || es != gs || ef != gf {
		t.Fatal("ARM64E must share the exact VariantGeneric quad components")
	}
}

// TestEmptyFeatures pins the behavior-invariant red line: the arm64
// CPUFeatures implementation is an EMPTY feature set, so the Linux auxv
// bitmaps are exactly the legacy hardcoded values AT_HWCAP=0 / AT_HWCAP2=0
// (advertise no optional CPU features).
func TestEmptyFeatures(t *testing.T) {
	_, _, _, f := resolveQuad(t)
	if hwcap, hwcap2 := f.HWCAP(); hwcap != 0 || hwcap2 != 0 {
		t.Fatalf("HWCAP() = (%#x, %#x), want (0, 0) — behavior-invariant empty feature set", hwcap, hwcap2)
	}
	for _, feat := range []arch.Feature{0, 1, 31, 1 << 20} {
		if f.Has(feat) {
			t.Fatalf("Has(%#x) = true, want false for the empty feature set", uint32(feat))
		}
	}
}

func TestArchCPUProperties(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	if a.PC() != PC || a.SP() != SP {
		t.Fatalf("role regs: PC=%v SP=%v", a.PC(), a.SP())
	}
	if a.PtrSize() != 8 {
		t.Fatalf("PtrSize = %d, want 8", a.PtrSize())
	}
	if a.ByteOrder() != binary.LittleEndian {
		t.Fatal("ByteOrder must be little-endian")
	}
}

func TestSetTLSBase(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	b := &regRec{}
	if err := a.SetTLSBase(b, 0xD0000000); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[TPIDR_EL0]; got != 0xD0000000 {
		t.Fatalf("SetTLSBase wrote reg TPIDR_EL0 = %#x, want 0xd0000000", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("SetTLSBase must write exactly one register, wrote %v", b.writes)
	}
}

func TestNormalizeCodeAddrIdentity(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	for _, addr := range []emu.GuestAddr{0, 0x1234, 0xffffff00, 0xff00000000001234} {
		if got := a.NormalizeCodeAddr(addr); got != addr {
			t.Fatalf("NormalizeCodeAddr(%#x) = %#x, want identity (TBI off)", addr, got)
		}
	}
}
