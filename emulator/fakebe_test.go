package emulator

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// faultBE is an emu.Backend test double with per-operation fault injection,
// letting privatize/Replace semantics be tested without a real CPU engine.
// It keeps a simple page store so MemRead/MemWrite round-trip like a real
// engine; operations not implemented panic via the nil embedded interface.
type faultBE struct {
	emu.Backend // nil embedded: calling an unimplemented op fails loudly

	unmapErr     error // MemUnmap fails while set
	mapErr       error // MemMap fails while set
	mapPtrErr    error // MemMapPtr fails while set
	writeErr     error // MemWrite fails while set
	writeOnCount int   // fail the Nth write (1-based); 0 = only when writeErr set
	writes       int
	flushErr     error // FlushCache fails while set

	regions   map[uint64][]byte // page addr -> bytes
	memWrites []struct {
		addr uint64
		data []byte
	}
	flushes  int
	unmapped []struct{ addr, size uint64 }
}

func newFaultBE() *faultBE { return &faultBE{regions: map[uint64][]byte{}} }

func (f *faultBE) ensure(a uint64, size uint64) []byte {
	pg := a &^ 0xfff
	if _, ok := f.regions[pg]; !ok {
		f.regions[pg] = make([]byte, 0x1000)
	}
	off := a - pg
	if off+size > 0x1000 {
		size = 0x1000 - off
	}
	return f.regions[pg][off : off+size]
}

func (f *faultBE) MemUnmap(addr, size uint64) error {
	f.unmapped = append(f.unmapped, struct{ addr, size uint64 }{addr, size})
	if f.unmapErr != nil {
		return f.unmapErr
	}
	for pg := addr &^ 0xfff; pg < addr+size; pg += 0x1000 {
		delete(f.regions, pg)
	}
	return nil
}
func (f *faultBE) MemMap(addr, size uint64, prot int) error {
	if f.mapErr != nil {
		return f.mapErr
	}
	for pg := addr &^ 0xfff; pg < addr+size; pg += 0x1000 {
		f.regions[pg] = make([]byte, 0x1000)
	}
	return nil
}
func (f *faultBE) MemMapPtr(addr, size uint64, prot int, host unsafe.Pointer) error {
	if f.mapPtrErr != nil {
		return f.mapPtrErr
	}
	buf := unsafe.Slice((*byte)(host), size)
	for off := uint64(0); off < size; off += 0x1000 {
		end := uint64(len(buf)) - off
		if end > 0x1000 {
			end = 0x1000
		}
		page := make([]byte, 0x1000)
		copy(page, buf[off:off+end])
		f.regions[addr+off] = page
	}
	return nil
}
func (f *faultBE) MemWrite(addr uint64, data []byte) error {
	f.writes++
	if f.writeOnCount > 0 && f.writes >= f.writeOnCount {
		return errors.New("write refused (count-gated)")
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	b := make([]byte, len(data))
	copy(b, data)
	f.memWrites = append(f.memWrites, struct {
		addr uint64
		data []byte
	}{addr, b})
	copy(f.ensure(addr, uint64(len(data))), data)
	return nil
}
func (f *faultBE) MemRead(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := uint64(0); i < size; i++ {
		out[i] = f.ensure(addr+i, 1)[0]
	}
	return out, nil
}
func (f *faultBE) FlushCache() error { f.flushes++; return f.flushErr }

func testPlan(t *testing.T, content []byte) *loader.Plan {
	t.Helper()
	buf, err := syscall.Mmap(-1, 0, len(content), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	copy(buf, content)
	return &loader.Plan{
		Maps: []loader.MapOp{{
			Addr:      0x1000,
			Size:      uint64(len(content)),
			Prot:      ProtRead,
			Shareable: true,
			Content:   buf,
		}},
	}
}

func newSharedEmu(t *testing.T, be emu.Backend, plan *loader.Plan, content []byte) *Emulator {
	t.Helper()
	ptr, sz, err := plan.SharedBuffer(0)
	if err != nil {
		t.Fatal(err)
	}
	return &Emulator{
		be:       be,
		replaced: map[uint64]hostFn{},
		shared: []sharedRange{{
			addr: 0x1000, size: uint64(len(content)),
			plan: plan, mapIdx: 0, hostPtr: ptr, hostLen: sz,
		}},
	}
}

// --- privatize fault isolation: success / recoverable / tracked-as-shared ---

func TestPrivatizeFaultIsolation(t *testing.T) {
	content := []byte("ORIGINAL-CONTENT")
	plan := testPlan(t, content)

	t.Run("unmap failure keeps the range tracked as shared", func(t *testing.T) {
		be := newFaultBE()
		be.unmapErr = errors.New("no unmap for you")
		e := newSharedEmu(t, be, plan, content)
		err := e.privatize(0x1000, 8)
		if err == nil {
			t.Fatal("expected the unmap error to surface")
		}
		if len(e.shared) != 1 {
			t.Fatalf("failed-unmap range must stay tracked as shared, got %d ranges", len(e.shared))
		}
		if e.poisonErr != nil {
			t.Fatalf("recoverable failure must not poison: %v", e.poisonErr)
		}
	})

	t.Run("remap failure rolls back to the shared mapping (recoverable)", func(t *testing.T) {
		be := newFaultBE()
		be.mapErr = errors.New("no map for you")
		e := newSharedEmu(t, be, plan, content)
		err := e.privatize(0x1000, 8)
		if err == nil {
			t.Fatal("expected the re-map error to surface")
		}
		if len(e.shared) != 1 {
			t.Fatalf("rolled-back range must stay tracked as shared, got %d", len(e.shared))
		}
		if e.poisonErr != nil {
			t.Fatalf("successful rollback must not poison: %v", e.poisonErr)
		}
		// the shared buffer content must be live at the guest address again
		got, err := be.MemRead(0x1000, uint64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(content) {
			t.Fatalf("guest pages must show shared content after rollback, got %q", got)
		}
	})

	t.Run("rollback failure poisons the emulator", func(t *testing.T) {
		be := newFaultBE()
		be.mapErr = errors.New("no map for you")
		be.mapPtrErr = errors.New("no ptr map either")
		e := newSharedEmu(t, be, plan, content)
		err := e.privatize(0x1000, 8)
		if err == nil {
			t.Fatal("expected an error")
		}
		if e.poisonErr == nil {
			t.Fatal("unrecoverable rollback must poison the emulator")
		}
	})

	t.Run("success restores content and clears tracking", func(t *testing.T) {
		be := newFaultBE()
		e := newSharedEmu(t, be, plan, content)
		if err := e.privatize(0x1000, 8); err != nil {
			t.Fatal(err)
		}
		if len(e.shared) != 0 {
			t.Fatalf("privatized range must leave shared tracking, got %d", len(e.shared))
		}
		if e.poisonErr != nil {
			t.Fatal("success must not poison")
		}
		got, err := be.MemRead(0x1000, uint64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(content) {
			t.Fatalf("private copy must hold the original content, got %q", got)
		}
	})
}

// --- Replace three-state semantics ---

func TestReplaceRecoverableFlushFailureRestoresOriginal(t *testing.T) {
	content := []byte("ORIGINAL-CONTENT")
	plan := testPlan(t, content)
	be := newFaultBE()
	// the private remap succeeds, the flush fails once: ReplaceE must restore
	// the original instructions and return an error WITHOUT poisoning.
	be.flushErr = errors.New("flush refused")
	e := newSharedEmu(t, be, plan, content)
	err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 })
	if err == nil {
		t.Fatal("flush failure must surface as an error")
	}
	if e.poisonErr != nil {
		t.Fatalf("restored rollback must not poison: %v", e.poisonErr)
	}
	if _, ok := e.replaced[0x1000]; ok {
		t.Fatal("failed ReplaceE must not register the hook")
	}
	got, err := be.MemRead(0x1000, uint64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("original instructions must be restored, got %q", got)
	}
}

func TestReplacePatchWriteFailurePoisons(t *testing.T) {
	content := []byte("ORIGINAL-CONTENT")
	plan := testPlan(t, content)
	be := newFaultBE()
	e := newSharedEmu(t, be, plan, content)
	// The patch write must fail AFTER privatize consumed its own content
	// write: arm the fault from inside fn's sibling — simplest is arming it
	// once the first (privatize) write has landed.
	be.writeOnCount = 2 // fail the 2nd write (1st = privatize content restore)
	err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 })
	if err == nil {
		t.Fatal("patch-write failure must surface")
	}
	if e.poisonErr == nil {
		t.Fatal("unverifiable patch write must poison the emulator")
	}
	// every later call must be rejected by the poison guard
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 }); err == nil {
		t.Fatal("calls after poison must fail")
	}
}

func TestReplaceSuccess(t *testing.T) {
	content := []byte("ORIGINAL-CONTENT")
	plan := testPlan(t, content)
	be := newFaultBE()
	e := newSharedEmu(t, be, plan, content)
	if err := e.ReplaceE(0x1000, func(h *Hook) uint64 { return 7 }); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.replaced[0x1000]; !ok {
		t.Fatal("success must register the hook")
	}
	// SVC trap bytes landed at the target
	got, err := be.MemRead(0x1000, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x01 || got[1] != 0x00 || got[2] != 0x00 || got[3] != 0xd4 {
		t.Fatalf("patch bytes not in place: % x", got)
	}
}

// os referenced to keep the import set stable if tests evolve
var _ = os.Getpagesize
