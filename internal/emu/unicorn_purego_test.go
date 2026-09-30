//go:build unicorn && (darwin || linux)

package emu

import "testing"

// Smoke test for the purego backend: registers, memory, code hooks with C→Go→C
// nesting (RegRead/MemRead from INSIDE a code hook), demand mapping from a
// mem-invalid hook, batch GP reads, and context save/restore.
func TestUnicornPuregoSmoke(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	const base = 0x100000
	if err := be.MemMap(base, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}

	// three× ADD X0,X0,#1 (0x91000400), then RET (0xD65F03C0)
	const adds = 3
	code := make([]uint32, adds+1)
	for i := 0; i < adds; i++ {
		code[i] = 0x91000400
	}
	code[adds] = 0xD65F03C0
	for i, insn := range code {
		var b [4]byte
		b[0] = byte(insn)
		b[1] = byte(insn >> 8)
		b[2] = byte(insn >> 16)
		b[3] = byte(insn >> 24)
		if err := be.MemWrite(GuestAddr(base+uint64(i*4)), b[:]); err != nil {
			t.Fatal(err)
		}
	}

	if err := be.RegWrite(regX0, 5); err != nil {
		t.Fatal(err)
	}

	// Code hook that calls BACK into the engine (RegRead) while unicorn is
	// mid-emulation — the nesting path every real consumer depends on.
	hookFires := 0
	sawX0 := []uint64{}
	ih, ok := be.(InstructionHooker) // capability probe (P2.5a)
	if !ok {
		t.Fatal("backend lacks the InstructionHooker capability")
	}
	h, err := ih.HookCode(base, base+GuestAddr(adds*4-1), func(b Backend, addr GuestAddr, size uint32) {
		hookFires++
		if v, err := b.RegRead(regX0); err == nil {
			sawX0 = append(sawX0, v)
		}
		if _, err := b.MemRead(base, 4); err != nil {
			t.Errorf("nested MemRead from code hook: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := be.Start(base, base+GuestAddr(adds*4)); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(); err != nil {
		t.Fatal(err)
	}

	if hookFires != adds {
		t.Errorf("code hook fired %d times, want %d", hookFires, adds)
	}
	if got, _ := be.RegRead(regX0); got != 5+adds {
		t.Errorf("final X0 = %d, want %d", got, 5+adds)
	}

	// Batch GP register read must agree with the individually-read X0
	// (RegFileReader capability, P7.5c).
	rr, ok := be.(RegFileReader)
	if !ok {
		t.Fatal("the arm64 unicorn backend must implement RegFileReader")
	}
	gp, err := rr.ReadGPRegs()
	if err != nil {
		t.Fatal(err)
	}
	if gp[0] != 5+adds {
		t.Errorf("ReadGPRegs X0 = %d, want %d", gp[0], 5+adds)
	}

	// Demand mapping: LDR X1,[X2] from unmapped memory; the invalid-mem hook
	// maps the page and writes a value, the load must complete.
	const dataPage = 0x200000
	ldr := uint32(0xF9400000 | 2<<5 | 1<<0) // LDR X1,[X2]
	var lb [4]byte
	lb[0], lb[1], lb[2], lb[3] = byte(ldr), byte(ldr>>8), byte(ldr>>16), byte(ldr>>24)
	if err := be.MemWrite(base+0x100, lb[:]); err != nil {
		t.Fatal(err)
	}
	const wantVal = uint64(0xDEADBEEFCAFEBABE)
	inv, ok := be.(InvalidMemHooker) // capability probe (P2.5a)
	if !ok {
		t.Fatal("backend lacks the InvalidMemHooker capability")
	}
	mh, err := inv.HookMemInvalid(func(b Backend, typ int, addr GuestAddr, size int, value int64) bool {
		if err := b.MemMap(addr&^0xFFF, 0x1000, ProtRead|ProtWrite); err != nil {
			return false
		}
		var vb [8]byte
		for i := 0; i < 8; i++ {
			vb[i] = byte(wantVal >> (8 * i))
		}
		return b.MemWrite(addr&^0xFFF, vb[:]) == nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mh.Remove()
	if err := be.RegWrite(regX2, dataPage); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(base+0x100, base+0x104); err != nil {
		t.Fatalf("demand-map run failed: %v", err)
	}
	if got, _ := be.RegRead(regX1); got != wantVal {
		t.Errorf("X1 after demand-mapped load = %#x, want %#x", got, wantVal)
	}

	// Context save/restore round-trip.
	cm, ok := be.(ContextManager) // capability probe (P2.5a)
	if !ok {
		t.Fatal("backend lacks the ContextManager capability")
	}
	ctx, err := cm.SaveContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := be.RegWrite(regX0, 0x1234); err != nil {
		t.Fatal(err)
	}
	if err := cm.RestoreContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ctx.Free(); err != nil {
		t.Fatal(err)
	}
	if got, _ := be.RegRead(regX0); got != 5+adds {
		t.Errorf("X0 after restore = %#x, want %d", got, 5+adds)
	}

	ci, ok := be.(CacheInvalidator) // capability probe (P2.5a)
	if !ok {
		t.Fatal("backend lacks the CacheInvalidator capability")
	}
	if err := ci.FlushCache(); err != nil {
		t.Fatal(err)
	}
}
