package android

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// fakeGuestMem is a byte-addressable guest-memory test double implementing
// platform.MemWriter.
type fakeGuestMem struct{ b map[uint64]byte }

func (m *fakeGuestMem) MemWrite(addr emu.GuestAddr, data []byte) error {
	if m.b == nil {
		m.b = map[uint64]byte{}
	}
	for i, v := range data {
		m.b[uint64(addr)+uint64(i)] = v
	}
	return nil
}

func (m *fakeGuestMem) u64(addr uint64) uint64 {
	var buf [8]byte
	for i := range buf {
		buf[i] = m.b[addr+uint64(i)]
	}
	return binary.LittleEndian.Uint64(buf[:])
}

// has16 reports whether [addr, addr+16) was written (the AT_RANDOM readable
// region the tests pin).
func (m *fakeGuestMem) has16(addr uint64) (nonZero bool, ok bool) {
	for i := uint64(0); i < 16; i++ {
		v, exists := m.b[addr+i]
		if !exists {
			return false, false
		}
		if v != 0 {
			nonZero = true
		}
	}
	return nonZero, true
}

// fakeFeatures is a test arch.CPUFeatures with an injectable HWCAP bitmap —
// the "change Features, both readers follow" probe for the single-source
// invariant.
type fakeFeatures struct {
	hwcap, hwcap2 uint64
	set           map[arch.Feature]bool
}

func (f fakeFeatures) Has(feat arch.Feature) bool { return f.set[feat] }
func (f fakeFeatures) HWCAP() (uint64, uint64)    { return f.hwcap, f.hwcap2 }

func startupCtx(mem *fakeGuestMem, feats arch.CPUFeatures, img *loader.Image) *platform.StartupContext {
	return &platform.StartupContext{
		Image:    img,
		Base:     0x12000000,
		AS:       memory.NewAddressSpace(memory.Layout{StackBase: 0xC0000000, StackSize: 0x80000}),
		Stack:    memory.Region{Addr: 0xC0000000, Size: 0x80000},
		Mem:      mem,
		Args:     []string{"golem"},
		Env:      []string{"A=1"},
		Features: feats,
	}
}

func auxvMap(t *testing.T, s *StartupABI) map[uint64]uint64 {
	t.Helper()
	vec := s.Auxv()
	if len(vec) == 0 {
		t.Fatal("auxv vector must not be empty after BuildInitialState")
	}
	last := vec[len(vec)-1]
	if last.Type != atNull || last.Val != 0 {
		t.Fatalf("auxv vector must end with AT_NULL(0,0), got (%d, %#x)", last.Type, last.Val)
	}
	m := map[uint64]uint64{}
	for _, en := range vec[:len(vec)-1] {
		if _, dup := m[en.Type]; dup {
			t.Fatalf("duplicate auxv type %d", en.Type)
		}
		m[en.Type] = en.Val
	}
	return m
}

// TestStartupABIBuildsAuxvBlock pins the auxv vector's content and its
// guest-memory materialization: every key/value, the AT_NULL terminator, the
// HWCAP bitmap sourced from Features, and AT_RANDOM pointing at 16 readable,
// deterministic bytes.
func TestStartupABIBuildsAuxvBlock(t *testing.T) {
	mem := &fakeGuestMem{}
	feats := fakeFeatures{hwcap: 0x1234, hwcap2: 0x5678, set: map[arch.Feature]bool{3: true}}
	img := &loader.Image{Entry: 0x500, PhdrAddr: 0x40, PhdrNum: 9}

	s := &StartupABI{}
	st, err := s.BuildInitialState(startupCtx(mem, feats, img))
	if err != nil {
		t.Fatalf("BuildInitialState: %v", err)
	}

	// InitialState: entry is the main image's relocated e_entry; SP keeps the
	// pre-P4d geometry (stack top minus the platform-owned reserve).
	if want := emu.GuestAddr(0x12000000 + 0x500); st.Entry != want {
		t.Fatalf("InitialState.Entry = %#x, want %#x", st.Entry, want)
	}
	if want := emu.GuestAddr(0xC0000000 + 0x80000 - StackTopReserve); st.SP != want {
		t.Fatalf("InitialState.SP = %#x, want %#x", st.SP, want)
	}

	av := auxvMap(t, s)
	want := map[uint64]uint64{
		atPhdr:   0x12000000 + 0x40, // loader metadata + load bias
		atPhnum:  9,
		atEntry:  0x12000000 + 0x500,
		atPagesz: 0x1000,
		atHwcap:  0x1234, // from Features.HWCAP(), not hardcoded
		atHwcap2: 0x5678,
		atSecure: 0,
	}
	for typ, v := range want {
		if av[typ] != v {
			t.Fatalf("auxv[%d] = %#x, want %#x", typ, av[typ], v)
		}
	}
	rnd, ok := av[atRandom]
	if !ok || rnd == 0 {
		t.Fatalf("auxv[AT_RANDOM] = %#x, must be present and non-zero", av[atRandom])
	}
	if rnd%16 != 0 {
		t.Fatalf("AT_RANDOM pointer %#x must be 16-aligned", rnd)
	}
	if rnd < 0xC0000000 || rnd+16 > 0xC0000000+0x80000 {
		t.Fatalf("AT_RANDOM pointer %#x must live inside the stack region", rnd)
	}
	if uint64(s.ATRandom()) != rnd {
		t.Fatalf("ATRandom() = %#x, auxv carries %#x — the two must agree", s.ATRandom(), rnd)
	}

	// The guest-memory materialization must match the vector exactly,
	// AT_NULL-terminated, and the AT_RANDOM target must be 16 written,
	// non-zero bytes from the kernel's deterministic stream.
	base := uint64(s.blockAddr)
	for i, en := range s.Auxv() {
		if got := mem.u64(base + uint64(i)*16); got != en.Type {
			t.Fatalf("block[%d].type = %d, want %d", i, got, en.Type)
		}
		if got := mem.u64(base + uint64(i)*16 + 8); got != en.Val {
			t.Fatalf("block[%d].val = %#x, want %#x", i, got, en.Val)
		}
	}
	nonZero, written := mem.has16(rnd)
	if !written || !nonZero {
		t.Fatalf("AT_RANDOM target %#x: 16 readable bytes written=%v nonZero=%v", rnd, written, nonZero)
	}
	var wantRand [16]byte
	kernel.DeterministicRandom(auxvRandomSeed, wantRand[:])
	for i := range wantRand {
		if mem.b[rnd+uint64(i)] != wantRand[i] {
			t.Fatalf("AT_RANDOM byte %d = %#x, want %#x (kernel deterministic stream)", i, mem.b[rnd+uint64(i)], wantRand[i])
		}
	}
}

// TestStartupABIEmptyFeaturesPreservesBehavior is the P4d behavior-invariant
// red line: with the (current, empty) feature set the served values are
// bit-identical to the pre-P4d hardcoded getauxval — AT_PAGESZ=4096,
// AT_HWCAP=0, AT_HWCAP2=0, AT_SECURE=0, unknown keys 0 — and without a main
// image AT_PHDR/AT_PHNUM/AT_ENTRY read 0 as they always did.
func TestStartupABIEmptyFeaturesPreservesBehavior(t *testing.T) {
	mem := &fakeGuestMem{}
	s := &StartupABI{}
	if _, err := s.BuildInitialState(startupCtx(mem, fakeFeatures{}, nil)); err != nil {
		t.Fatalf("BuildInitialState: %v", err)
	}
	av := auxvMap(t, s)
	for typ, v := range map[uint64]uint64{
		atPagesz: 0x1000,
		atHwcap:  0,
		atHwcap2: 0,
		atSecure: 0,
	} {
		if av[typ] != v {
			t.Fatalf("auxv[%d] = %#x, want %#x (pre-P4d value)", typ, av[typ], v)
		}
	}
	for _, typ := range []uint64{atPhdr, atPhnum, atEntry} {
		if got := s.Lookup(typ); got != 0 {
			t.Fatalf("Lookup(%d) = %#x without a main image, want 0", typ, got)
		}
	}
	if got := s.Lookup(999); got != 0 {
		t.Fatalf("Lookup(unknown) = %#x, want 0", got)
	}
	if got := s.Lookup(atRandom); got == 0 {
		t.Fatal("Lookup(AT_RANDOM) must point at the block's 16 bytes")
	}
}

func TestStartupABIRejects(t *testing.T) {
	mem := &fakeGuestMem{}
	feats := fakeFeatures{}

	if _, err := (&StartupABI{}).BuildInitialState(nil); err == nil {
		t.Fatal("nil context must error")
	}
	ctx := startupCtx(mem, nil, nil)
	if _, err := (&StartupABI{}).BuildInitialState(ctx); err == nil {
		t.Fatal("nil Features must error (CPUFeatures is the only HWCAP source)")
	}
	ctx = startupCtx(mem, feats, nil)
	ctx.Mem = nil
	if _, err := (&StartupABI{}).BuildInitialState(ctx); err == nil {
		t.Fatal("nil Mem must error")
	}
	ctx = startupCtx(mem, feats, nil)
	ctx.Stack = memory.Region{Addr: 0x1000, Size: 0x100} // smaller than the reserve + block
	if _, err := (&StartupABI{}).BuildInitialState(ctx); err == nil {
		t.Fatal("tiny stack region must error")
	}

	s := &StartupABI{}
	if _, err := s.BuildInitialState(startupCtx(mem, feats, nil)); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if _, err := s.BuildInitialState(startupCtx(mem, feats, nil)); err == nil {
		t.Fatal("second BuildInitialState must error (auxv is built once)")
	}
}
