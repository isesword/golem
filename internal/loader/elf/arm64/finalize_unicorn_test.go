//go:build unicorn && (darwin || linux)

package arm64_test

import (
	debugelf "debug/elf"
	"encoding/binary"
	"testing"

	archarm64 "github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// .5 / invariant 11 on a REAL backend: FinalizeImage is the RW→RX boundary
// of the load lifecycle (DESIGN.md §3.9). A .text page the linker wrote
// during relocation (legal pre-finalize) must reject GUEST writes after
// Plan.Apply completes, while the RW segment stays writable.
//
// Verified nuance: unicorn's HOST-side uc_mem_write bypasses guest page
// protection entirely (probe: host MemWrite succeeds on an RX page), so the
// enforcement this test exercises is the guest-executed store — which is the
// writer invariant 11 actually cares about (guest code / a runaway pointer
// must not be able to scribble over .text; host layers are bound by
// convention plus the absence of any write path, checked by the.5d
// interposition tests).
func TestFinalizeImageMakesTextImmutable(t *testing.T) {
	be, err := emu.NewNamed("unicorn", emu.ArchARM64)
	if err != nil {
		t.Skipf("unicorn backend unavailable: %v", err)
	}
	defer be.Close()

	// The RELATIVE relocation targets the RX segment, defeating shareability —
	// the page takes the map-RWX → relocate → re-protect-RX path, which is
	// exactly the lifecycle boundary under test.
	img := synthImage(
		[]loader.Sym{{}},
		[]loader.Reloc{{Offset: 0x0, Type: uint32(debugelf.R_AARCH64_RELATIVE), Addend: 0x40}},
	)
	plan, err := img.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Maps[0].Shareable {
		t.Fatal("setup: the relocated RX segment must be non-shareable")
	}

	const base = uint64(0x12000000)
	if err := plan.ApplyPrivate(be, base, loader.NewDynamicLinker().GlobalResolver()); err != nil {
		t.Fatal(err)
	}
	// The relocation itself landed (pre-finalize write was legal).
	b, err := be.MemRead(emu.GuestAddr(base), 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != base+0x40 {
		t.Fatalf("RELATIVE @base = %#x, want %#x", got, base+0x40)
	}

	// Guest store program: mov w0, #0x1234 ; str w0, [x1] ; ret. Lives in its
	// own RWX scratch page (not part of the image, not finalized).
	code := []byte{
		0x80, 0x46, 0x82, 0x52, // mov w0, #0x1234
		0x20, 0x00, 0x00, 0xb9, // str w0, [x1]
		0xc0, 0x03, 0x5f, 0xd6, // ret (unreached: until stops first)
	}
	const codePage = uint64(0x70000000)
	if err := be.MemMap(emu.GuestAddr(codePage), 0x1000, emu.ProtAll); err != nil {
		t.Fatal(err)
	}
	if err := be.MemWrite(emu.GuestAddr(codePage), code); err != nil {
		t.Fatal(err)
	}
	store := func(target uint64) error {
		if err := be.RegWrite(archarm64.X1, target); err != nil {
			t.Fatal(err)
		}
		return be.Start(emu.GuestAddr(codePage), emu.GuestAddr(codePage+8))
	}

	// Post-finalize: a guest store into the RX segment must FAULT...
	if err := store(base + 0x100); err == nil {
		t.Fatal("guest store into finalized RX segment must fault (invariant 11)")
	}
	// ...while the RW segment stays writable by guest code.
	if err := store(base + 0x1000); err != nil {
		t.Fatalf("guest store into RW segment after finalize: %v", err)
	}
	rb, err := be.MemRead(emu.GuestAddr(base+0x1000), 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(rb); got != 0x1234 {
		t.Fatalf("RW segment read-back = %#x, want 0x1234", got)
	}
}
