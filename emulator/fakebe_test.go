package emulator

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// faultBE is an emu.Backend test double with per-operation fault injection,
// letting privatize/Replace semantics be tested without a real CPU engine.
// Only the operations privatize/Replace touch are implemented; the embedded
// nil interface panics if anything else is ever invoked.
type faultBE struct {
	emu.Backend // nil embedded: calling an unimplemented op fails loudly

	unmapErr  error // MemUnmap fails while set
	mapErr    error // MemMap fails while set
	writeErr  error // MemWrite fails while set
	flushErr  error // FlushCache fails while set
	memWrites []struct {
		addr uint64
		data []byte
	}
	flushes  int
	unmapped []struct{ addr, size uint64 }
}

func (f *faultBE) MemUnmap(addr, size uint64) error {
	f.unmapped = append(f.unmapped, struct{ addr, size uint64 }{addr, size})
	return f.unmapErr
}
func (f *faultBE) MemMap(addr, size uint64, prot int) error { return f.mapErr }
func (f *faultBE) MemWrite(addr uint64, data []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	b := make([]byte, len(data))
	copy(b, data)
	f.memWrites = append(f.memWrites, struct {
		addr uint64
		data []byte
	}{addr, b})
	return nil
}
func (f *faultBE) FlushCache() error { f.flushes++; return f.flushErr }

func testPlan(t *testing.T, content []byte) *loader.Plan {
	t.Helper()
	p := &loader.Plan{
		Maps: []loader.MapOp{{
			Addr:      0x1000,
			Size:      uint64(len(content)),
			Prot:      ProtRead,
			Shareable: true,
			Content:   content,
		}},
	}
	return p
}

func TestPrivatizeFaultIsolation(t *testing.T) {
	content := []byte("ORIGINAL-CONTENT")
	plan := testPlan(t, content)

	t.Run("unmap failure keeps the range tracked as shared", func(t *testing.T) {
		be := &faultBE{unmapErr: errors.New("no unmap for you")}
		e := &Emulator{be: be, shared: []sharedRange{{addr: 0x1000, size: uint64(len(content)), plan: plan, mapIdx: 0}}}
		err := e.privatize(0x1000, 8)
		if err == nil {
			t.Fatal("expected the unmap error to surface")
		}
		if len(e.shared) != 1 {
			t.Fatalf("failed-unmap range must stay tracked as shared, got %d ranges", len(e.shared))
		}
	})

	t.Run("unmap ok + map failure drops the range from shared tracking", func(t *testing.T) {
		be := &faultBE{mapErr: errors.New("no map for you")}
		e := &Emulator{be: be, shared: []sharedRange{{addr: 0x1000, size: uint64(len(content)), plan: plan, mapIdx: 0}}}
		err := e.privatize(0x1000, 8)
		if err == nil {
			t.Fatal("expected the re-map error to surface")
		}
		if len(e.shared) != 0 {
			t.Fatalf("unmapped-but-broken range must drop out of shared tracking, got %d", len(e.shared))
		}
	})

	t.Run("success restores content and clears tracking", func(t *testing.T) {
		be := &faultBE{}
		e := &Emulator{be: be, shared: []sharedRange{{addr: 0x1000, size: uint64(len(content)), plan: plan, mapIdx: 0}}}
		if err := e.privatize(0x1000, 8); err != nil {
			t.Fatal(err)
		}
		if len(e.shared) != 0 {
			t.Fatalf("privatized range must leave shared tracking, got %d", len(e.shared))
		}
		if len(be.memWrites) == 0 || string(be.memWrites[len(be.memWrites)-1].data) != string(content) {
			t.Fatal("original content must be restored into the private copy")
		}
	})
}

func TestReplaceFailureLeavesNoHookRegistration(t *testing.T) {
	be := &faultBE{flushErr: errors.New("flush refused")}
	e := &Emulator{be: be, replaced: map[uint64]hostFn{}}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Replace must panic when flush fails (stale translation = silent no-op hook)")
		}
		if _, ok := e.replaced[0x2000]; ok {
			t.Fatal("failed Replace must not register the hook")
		}
		if be.flushes == 0 {
			t.Fatal("FlushCache must have been attempted")
		}
	}()
	e.Replace(0x2000, func(h *Hook) uint64 { return 1 })
}
