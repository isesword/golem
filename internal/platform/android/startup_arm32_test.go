package android

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
)

func (m *fakeGuestMem) u32(addr uint64) uint32 {
	var buf [4]byte
	for i := range buf {
		buf[i] = m.b[addr+uint64(i)]
	}
	return binary.LittleEndian.Uint32(buf[:])
}

// TestStartupABI32BuildsAuxvBlock pins the ARM32 auxv data block: same entry
// content rules as the 64-bit ABI, but materialized as 8-byte Elf32_auxv_t
// pairs (u32 type + u32 value) — the pointer-width difference that makes a
// separate implementation necessary.
func TestStartupABI32BuildsAuxvBlock(t *testing.T) {
	mem := &fakeGuestMem{}
	feats := fakeFeatures{hwcap: 0x1234, hwcap2: 0x5678, set: map[arch.Feature]bool{3: true}}
	img := &loader.Image{Entry: 0x500, PhdrAddr: 0x40, PhdrNum: 9}

	s := &StartupABI32{}
	if err := s.BuildInitialState(startupCtx(mem, feats, img)); err != nil {
		t.Fatalf("BuildInitialState: %v", err)
	}

	vec := s.Auxv()
	if len(vec) == 0 {
		t.Fatal("auxv vector must not be empty after BuildInitialState")
	}
	if last := vec[len(vec)-1]; last.Type != atNull || last.Val != 0 {
		t.Fatalf("auxv must end with AT_NULL(0,0), got (%d, %#x)", last.Type, last.Val)
	}

	// The guest-memory materialization must match the vector exactly, in
	// 8-BYTE pairs (the Elf32_auxv_t wire format).
	base := uint64(s.blockAddr)
	for i, en := range vec {
		if got := uint64(mem.u32(base + uint64(i)*8)); got != en.Type {
			t.Fatalf("block[%d].type = %d, want %d", i, got, en.Type)
		}
		if got := uint64(mem.u32(base + uint64(i)*8 + 4)); got != en.Val {
			t.Fatalf("block[%d].val = %#x, want %#x", i, got, en.Val)
		}
	}

	// AT_RANDOM: 16 readable, deterministic bytes; pointer inside the stack.
	rnd := s.Lookup(atRandom)
	if rnd == 0 {
		t.Fatal("Lookup(AT_RANDOM) = 0, want a pointer into the block")
	}
	if rnd < 0xC0000000 || rnd+16 > 0xC0000000+0x80000 {
		t.Fatalf("AT_RANDOM pointer %#x must live inside the stack region", rnd)
	}
	if uint64(s.ATRandom()) != rnd {
		t.Fatalf("ATRandom() = %#x, auxv carries %#x — the two must agree", s.ATRandom(), rnd)
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

	// Same content rules as 64-bit: HWCAP from Features, PHDR/ENTRY = image
	// metadata + bias.
	for typ, v := range map[uint64]uint64{
		atPhdr:   0x12000000 + 0x40,
		atPhnum:  9,
		atEntry:  0x12000000 + 0x500,
		atPagesz: 0x1000,
		atHwcap:  0x1234,
		atHwcap2: 0x5678,
		atSecure: 0,
	} {
		if got := s.Lookup(typ); got != v {
			t.Fatalf("Lookup(%d) = %#x, want %#x", typ, got, v)
		}
	}
}

// TestStartupABI32Rejects mirrors the 64-bit ABI's contract violations.
func TestStartupABI32Rejects(t *testing.T) {
	mem := &fakeGuestMem{}
	if err := (&StartupABI32{}).BuildInitialState(nil); err == nil {
		t.Fatal("nil context must error")
	}
	ctx := startupCtx(mem, nil, nil)
	if err := (&StartupABI32{}).BuildInitialState(ctx); err == nil {
		t.Fatal("nil Features must error (CPUFeatures is the only HWCAP source)")
	}
	ctx = startupCtx(mem, fakeFeatures{}, nil)
	ctx.Mem = nil
	if err := (&StartupABI32{}).BuildInitialState(ctx); err == nil {
		t.Fatal("nil Mem must error")
	}
	s := &StartupABI32{}
	if err := s.BuildInitialState(startupCtx(mem, fakeFeatures{}, nil)); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if err := s.BuildInitialState(startupCtx(mem, fakeFeatures{}, nil)); err == nil {
		t.Fatal("second BuildInitialState must error (auxv is built once)")
	}
}
