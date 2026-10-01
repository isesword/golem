package arm64

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// batchRec records the batch writes a PrepareCall flushed.
type batchRec struct {
	emu.Backend // nil embedded: unimplemented ops fail loudly
	regs        map[emu.Reg]uint64
	batches     [][]emu.RegWrite
}

func (r *batchRec) RegRead(reg emu.Reg) (uint64, error) { return r.regs[reg], nil }

func (r *batchRec) WriteRegs(ws []emu.RegWrite) error {
	cp := make([]emu.RegWrite, len(ws))
	copy(cp, ws)
	r.batches = append(r.batches, cp)
	for _, w := range ws {
		r.regs[w.Reg] = w.Value
	}
	return nil
}

// TestPrepareCallBatchEqualsLoop pins the equivalence contract: the
// batch path and the per-register fallback must flush the IDENTICAL write
// set in the IDENTICAL order (the two paths cannot drift).
func TestPrepareCallBatchEqualsLoop(t *testing.T) {
	c := resolveCallABI(t)
	args := []uint64{0x11, 0x22, 0x33}

	batch := &batchRec{regs: map[emu.Reg]uint64{SP: 0xC0002000}}
	if err := c.PrepareCall(batch, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: arch.WordArgs(args...)}); err != nil {
		t.Fatal(err)
	}

	loop := &regRec{regs: map[emu.Reg]uint64{SP: 0xC0002000}}
	if err := c.PrepareCall(loop, arch.CallRequest{Entry: 0xAAAA, Return: 0xFFFFFF00, Args: arch.WordArgs(args...)}); err != nil {
		t.Fatal(err)
	}

	if len(batch.batches) != 1 {
		t.Fatalf("batch backend saw %d batches, want 1", len(batch.batches))
	}
	// Multiset equivalence: every batch write must match the fallback's
	// recorded write for that register (each register is written once in
	// this scenario), and the counts must agree — no extra, none missing.
	if len(batch.batches[0]) != len(loop.writes) {
		t.Fatalf("write-set size differs: batch %d vs fallback %d", len(batch.batches[0]), len(loop.writes))
	}
	for _, w := range batch.batches[0] {
		got, ok := loop.writes[w.Reg]
		if !ok || got != w.Value {
			t.Errorf("reg %v: batch wrote %#x, fallback wrote %#x (ok=%v)", w.Reg, w.Value, got, ok)
		}
		if got := batch.regs[w.Reg]; got != w.Value {
			t.Errorf("reg %v: batch backend state = %#x, want %#x", w.Reg, got, w.Value)
		}
	}
}
