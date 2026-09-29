package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

// auxvBE is a minimal emu.Backend for hostGetauxval tests: programmable
// argument registers, recorded register writes, and a byte-addressable guest
// memory for the StartupABI's auxv-block materialization. Everything else
// panics via the nil embedded interface.
type auxvBE struct {
	emu.Backend
	args   map[emu.Reg]uint64
	writes map[emu.Reg]uint64
	mem    map[uint64]byte
}

func (b *auxvBE) RegRead(r emu.Reg) (uint64, error) { return b.args[r], nil }

func (b *auxvBE) RegWrite(r emu.Reg, v uint64) error {
	if b.writes == nil {
		b.writes = map[emu.Reg]uint64{}
	}
	b.writes[r] = v
	return nil
}

func (b *auxvBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	if b.mem == nil {
		b.mem = map[uint64]byte{}
	}
	for i, v := range data {
		b.mem[uint64(addr)+uint64(i)] = v
	}
	return nil
}

// hwcapFeatures injects a non-empty HWCAP bitmap — the probe that proves both
// auxv readers (the data block AND the interposed getauxval) follow the
// Target's CPUFeatures instead of any hardcoded value.
type hwcapFeatures struct{ hwcap, hwcap2 uint64 }

func (f hwcapFeatures) Has(arch.Feature) bool   { return false }
func (f hwcapFeatures) HWCAP() (uint64, uint64) { return f.hwcap, f.hwcap2 }

// Linux auxv keys the guest may query (mirrors platform/android's at* —
// restated here so the test fails if either side drifts).
const (
	auxvPhdr   = 3
	auxvPhnum  = 5
	auxvPagesz = 6
	auxvEntry  = 9
	auxvHwcap  = 16
	auxvSecure = 23
	auxvRandom = 25
	auxvHwcap2 = 26
)

// getauxval drives the interposed host function for one query.
func getauxval(t *testing.T, e *Emulator, be *auxvBE, typ uint64) uint64 {
	t.Helper()
	be.args = map[emu.Reg]uint64{arm64.X0: typ}
	hostGetauxval(e, be)
	return be.writes[arm64.X0]
}

// TestGetauxvalServesStartupABIVector pins the P4d single-source invariant at
// the emulator level: with a non-empty injected Features, getauxval answers
// come from the StartupABI-built vector (HWCAP from Features) — and the two
// agree key by key.
func TestGetauxvalServesStartupABIVector(t *testing.T) {
	be := &auxvBE{}
	e := newTestEmulator(t, be)
	e.target.Features = hwcapFeatures{hwcap: 0xABCD, hwcap2: 0x1234}

	for typ, want := range map[uint64]uint64{
		auxvPagesz: 0x1000,
		auxvHwcap:  0xABCD, // Features-sourced
		auxvHwcap2: 0x1234,
		auxvSecure: 0,
	} {
		if got := getauxval(t, e, be, typ); got != want {
			t.Fatalf("getauxval(%d) = %#x, want %#x", typ, got, want)
		}
		if got := getauxval(t, e, be, typ); got != e.startup.Lookup(typ) {
			t.Fatalf("getauxval(%d) = %#x, StartupABI vector carries %#x — same-source invariant broken",
				typ, got, e.startup.Lookup(typ))
		}
	}

	// AT_RANDOM: a pointer into the block, 16 written non-zero bytes.
	rnd := getauxval(t, e, be, auxvRandom)
	if rnd == 0 || rnd != uint64(e.startup.ATRandom()) {
		t.Fatalf("getauxval(AT_RANDOM) = %#x, StartupABI ATRandom = %#x", rnd, e.startup.ATRandom())
	}
	nonZero := false
	for i := uint64(0); i < 16; i++ {
		v, ok := be.mem[rnd+i]
		if !ok {
			t.Fatalf("AT_RANDOM byte %d at %#x was never written", i, rnd+i)
		}
		if v != 0 {
			nonZero = true
		}
	}
	if !nonZero {
		t.Fatal("AT_RANDOM target must be 16 non-zero deterministic bytes")
	}

	// Lazy bionic-only build (no LoadLibrary yet): the loader-metadata keys
	// keep the historical default 0, as do unknown keys.
	for _, typ := range []uint64{auxvPhdr, auxvPhnum, auxvEntry, 4242} {
		if got := getauxval(t, e, be, typ); got != 0 {
			t.Fatalf("getauxval(%d) = %#x without a main image, want 0", typ, got)
		}
	}
}

// TestGetauxvalEmptyFeaturesPreservesBehavior is the P4d behavior-invariant
// red line at the emulator level: with the Target's real (empty) arm64
// CPUFeatures, getauxval answers are bit-identical to the pre-P4d hardcoded
// table — AT_PAGESZ=4096, AT_HWCAP=0, AT_HWCAP2=0, AT_SECURE=0, unknown=0 —
// and AT_RANDOM still yields a valid pointer.
func TestGetauxvalEmptyFeaturesPreservesBehavior(t *testing.T) {
	be := &auxvBE{}
	e := newTestEmulator(t, be)

	for typ, want := range map[uint64]uint64{
		auxvPagesz: 0x1000,
		auxvHwcap:  0,
		auxvHwcap2: 0,
		auxvSecure: 0,
		777:        0,
	} {
		if got := getauxval(t, e, be, typ); got != want {
			t.Fatalf("getauxval(%d) = %#x, want %#x (pre-P4d value)", typ, got, want)
		}
	}
	if got := getauxval(t, e, be, auxvRandom); got == 0 {
		t.Fatal("getauxval(AT_RANDOM) must be a valid pointer")
	}
}
