package amd64

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// regRec is an emu.Backend test double with a programmable register file and
// guest memory: RegRead serves preset values, RegWrite is recorded, MemRead
// serves preset bytes. Everything else panics via the nil embedded interface.
type regRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	regs        map[emu.Reg]uint64
	writes      map[emu.Reg]uint64
	mem         map[uint64][]byte // addr -> bytes (MemRead serves from here)
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
// CPUFeatures) quad for (IDAMD64, VariantGeneric); this package's init must
// have registered it.
func resolveQuad(t *testing.T) (arch.Arch, arch.CallABI, arch.StubEncoder, arch.CPUFeatures) {
	t.Helper()
	a, c, s, f, err := arch.Resolve(arch.IDAMD64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("amd64 target quad must be registered by this package's init: %v", err)
	}
	return a, c, s, f
}

// TestFrozenRegIDs pins the abstract emu.Reg numbers this package assigns.
// The unicorn backend's amd64 regMap keys on these NUMBERS (it cannot import
// this package — import cycle); any drift fails here and in emu's
// TestAMD64RegMapFrozenIDs loudly instead of corrupting registers.
func TestFrozenRegIDs(t *testing.T) {
	cases := []struct {
		name string
		got  emu.Reg
		want emu.Reg
	}{
		{"RAX", RAX, 64}, {"RBX", RBX, 65}, {"RCX", RCX, 66}, {"RDX", RDX, 67},
		{"RSI", RSI, 68}, {"RDI", RDI, 69}, {"RBP", RBP, 70}, {"RSP", RSP, 71},
		{"R8", R8, 72}, {"R9", R9, 73}, {"R10", R10, 74}, {"R11", R11, 75},
		{"R12", R12, 76}, {"R13", R13, 77}, {"R14", R14, 78}, {"R15", R15, 79},
		{"RIP", RIP, 80}, {"EFLAGS", EFLAGS, 81},
		{"FS_BASE", FS_BASE, 82}, {"GS_BASE", GS_BASE, 83},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want frozen id %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestQuadRegistration(t *testing.T) {
	a, c, s, f := resolveQuad(t)
	if a == nil || c == nil || s == nil || f == nil {
		t.Fatal("Resolve must return a non-nil Arch, CallABI, StubEncoder and CPUFeatures")
	}
	if a.EngineArch() != emu.ArchAMD64 {
		t.Fatalf("EngineArch = %v, want ArchAMD64", a.EngineArch())
	}
}

// TestEmptyFeatures pins the stage behavior: the amd64 CPUFeatures
// implementation is an EMPTY feature set, so the Linux auxv bitmaps are
// AT_HWCAP=0 / AT_HWCAP2=0 (advertise no optional CPU features).
func TestEmptyFeatures(t *testing.T) {
	_, _, _, f := resolveQuad(t)
	if hwcap, hwcap2 := f.HWCAP(); hwcap != 0 || hwcap2 != 0 {
		t.Fatalf("HWCAP() = (%#x, %#x), want (0, 0) — empty feature set", hwcap, hwcap2)
	}
	for _, feat := range []arch.Feature{0, 1, 31, 1 << 20} {
		if f.Has(feat) {
			t.Fatalf("Has(%#x) = true, want false for the empty feature set", uint32(feat))
		}
	}
}

func TestArchCPUProperties(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	if a.PC() != RIP || a.SP() != RSP {
		t.Fatalf("role regs: PC=%v SP=%v, want RIP/RSP", a.PC(), a.SP())
	}
	if a.PtrSize() != 8 {
		t.Fatalf("PtrSize = %d, want 8", a.PtrSize())
	}
	if a.ByteOrder() != binary.LittleEndian {
		t.Fatal("ByteOrder must be little-endian")
	}
	caps := a.Caps()
	if caps.PointerBits != 64 || caps.VABits != 48 || caps.PageSize != 0x1000 || caps.MaxUserVA != 1<<47 {
		t.Fatalf("Caps = %+v, want 64-bit pointers / 48 VA bits / 4 KiB pages / MaxUserVA 2^47", caps)
	}
}

// TestSetTLSBase pins that SetTLSBase programs the FS base register — the
// real x86-64 TLS mechanism, never a no-op.
func TestSetTLSBase(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	b := &regRec{}
	if err := a.SetTLSBase(b, 0xD0000000); err != nil {
		t.Fatal(err)
	}
	if got := b.writes[FS_BASE]; got != 0xD0000000 {
		t.Fatalf("SetTLSBase wrote reg FS_BASE = %#x, want 0xd0000000", got)
	}
	if len(b.writes) != 1 {
		t.Fatalf("SetTLSBase must write exactly one register, wrote %v", b.writes)
	}
}

func TestNormalizeCodeAddrIdentity(t *testing.T) {
	a, _, _, _ := resolveQuad(t)
	for _, addr := range []emu.GuestAddr{0, 0x1234, 0xffffff00, 0x7fffffffffff} {
		if got := a.NormalizeCodeAddr(addr); got != addr {
			t.Fatalf("NormalizeCodeAddr(%#x) = %#x, want identity", addr, got)
		}
	}
}
