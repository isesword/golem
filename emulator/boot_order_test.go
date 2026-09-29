package emulator

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"unsafe"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// P4e boot-sequence invariant tests (DESIGN.md §4 "三条禁止条件" + TCG
// timing). An instrumented fake CPU backend is registered under a test-only
// engine name, so the FULL New() boot — probe, target resolution, layout,
// backend creation, region mapping, image load/link/finalize, StartupABI —
// runs against a backend that records every operation in order. No unicorn
// tag required; these tests run in a pure-Go build.
//
// Locked invariants:
//
//   - the probe/target resolution precedes backend creation (a failed probe
//     must leave NO engine behind);
//   - the TCG-buffer step sits immediately after backend creation, before
//     any guest mapping or execution (a failing TCG step fails New before
//     the first MemMap);
//   - no guest execution (Start) before every image's FinalizeImage
//     (MemProtect RW→RX);
//   - with a main image, the StartupABI auxv-block write lands after that
//     image's FinalizeImage and before its init code runs (first Start).

// bootEvent is one recorded backend operation, in call order.
type bootEvent struct {
	op         string // create | map | mapptr | protect | write | start | close
	addr, size uint64
}

// bootBE is an in-memory emu.Backend (sparse pages + MemMapPtr host aliases,
// the same model as the loader linker's memBE) that appends every mutating
// operation to an event log. It also implements the two hook capabilities
// New probes for (InterruptHooker / InvalidMemHooker); the hooks are stored,
// never fired — the fake executes no instructions.
type bootBE struct {
	pages  map[uint64][]byte
	ptrs   []bootPtrRange
	regs   map[emu.Reg]uint64
	events []bootEvent
	intr   emu.InterruptHookFunc
	inv    emu.MemInvalidHookFunc
}

type bootPtrRange struct {
	addr, size uint64
	buf        []byte
}

type bootHook struct{}

func (bootHook) Remove() error { return nil }

func newBootBE() *bootBE {
	return &bootBE{pages: map[uint64][]byte{}, regs: map[emu.Reg]uint64{}}
}

func (b *bootBE) log(op string, addr, size uint64) {
	b.events = append(b.events, bootEvent{op: op, addr: addr, size: size})
}

func (b *bootBE) page(a uint64) []byte {
	pg := a &^ 0xfff
	for _, pr := range b.ptrs { // aliased host buffers (uc_mem_map_ptr semantics)
		if pg >= pr.addr && pg+0x1000 <= pr.addr+pr.size {
			return pr.buf[pg-pr.addr : pg-pr.addr+0x1000]
		}
	}
	pgm := b.pages[pg]
	if pgm == nil {
		pgm = make([]byte, 0x1000)
		b.pages[pg] = pgm
	}
	return pgm
}

func (b *bootBE) RegRead(r emu.Reg) (uint64, error) { return b.regs[r], nil }
func (b *bootBE) RegWrite(r emu.Reg, v uint64) error {
	b.regs[r] = v
	return nil
}
func (b *bootBE) ReadGPRegs() ([34]uint64, error) { return [34]uint64{}, nil }

func (b *bootBE) MemMap(addr emu.GuestAddr, size uint64, _ int) error {
	b.log("map", uint64(addr), size)
	a0 := uint64(addr) // GuestAddr→raw: the fake's page-table arithmetic uses uint64
	for a := a0 &^ 0xfff; a < a0+size; a += 0x1000 {
		b.page(a)
	}
	return nil
}

func (b *bootBE) MemMapPtr(addr emu.GuestAddr, size uint64, _ int, host unsafe.Pointer) error {
	b.log("mapptr", uint64(addr), size)
	b.ptrs = append(b.ptrs, bootPtrRange{uint64(addr), size, unsafe.Slice((*byte)(host), size)})
	return nil
}

func (b *bootBE) MemUnmap(emu.GuestAddr, uint64) error { return nil }

func (b *bootBE) MemProtect(addr emu.GuestAddr, size uint64, _ int) error {
	b.log("protect", uint64(addr), size)
	return nil
}

func (b *bootBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	b.log("write", uint64(addr), uint64(len(data)))
	a0 := uint64(addr) // GuestAddr→raw
	for i, v := range data {
		a := a0 + uint64(i)
		b.page(a)[a&0xfff] = v
	}
	return nil
}

func (b *bootBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	a0 := uint64(addr) // GuestAddr→raw
	out := make([]byte, size)
	for i := range out {
		a := a0 + uint64(i)
		out[i] = b.page(a)[a&0xfff]
	}
	return out, nil
}

func (b *bootBE) InstallTrap(emu.TrapKind, emu.TrapHandler) (emu.HookHandle, error) {
	return bootHook{}, nil
}

func (b *bootBE) Start(begin, until emu.GuestAddr) error {
	b.log("start", uint64(begin), uint64(until))
	return nil // the fake executes nothing; the caller's LR sentinel is never reached
}

func (b *bootBE) StartCount(begin, until emu.GuestAddr, _ uint64) error {
	return b.Start(begin, until)
}

func (b *bootBE) Stop() error { return nil }

func (b *bootBE) Close() error {
	b.log("close", 0, 0)
	return nil
}

// Capability probes New performs (P2.5a): without these two, New fails.
func (b *bootBE) HookInterrupt(fn emu.InterruptHookFunc) (emu.HookHandle, error) {
	b.intr = fn
	return bootHook{}, nil
}
func (b *bootBE) HookMemInvalid(fn emu.MemInvalidHookFunc) (emu.HookHandle, error) {
	b.inv = fn
	return bootHook{}, nil
}

// bootEngine is the test-only engine name the bootBE factory registers under.
const bootEngine = "bootorder-fake"

// bootFactoryState records every backend the test factory builds, so tests
// can count creations (probe-before-backend) and inspect the event log of
// the backend a boot ran against.
var bootFactoryState struct {
	mu      sync.Mutex
	created []*bootBE
}

func init() {
	emu.Register(bootEngine, func(a emu.Arch) (emu.Backend, error) {
		if a != emu.ArchARM64 {
			return nil, fmt.Errorf("%s: %w (arch %d)", bootEngine, emu.ErrUnsupported, a)
		}
		be := newBootBE()
		be.log("create", 0, 0)
		bootFactoryState.mu.Lock()
		bootFactoryState.created = append(bootFactoryState.created, be)
		bootFactoryState.mu.Unlock()
		return be, nil
	})
}

func bootBackendCount() int {
	bootFactoryState.mu.Lock()
	defer bootFactoryState.mu.Unlock()
	return len(bootFactoryState.created)
}

// bootBackendSince returns the backends created since marker `before`.
func bootBackendSince(t *testing.T, before int) []*bootBE {
	t.Helper()
	bootFactoryState.mu.Lock()
	defer bootFactoryState.mu.Unlock()
	return append([]*bootBE(nil), bootFactoryState.created[before:]...)
}

// firstIndex returns the index of the first event matching pred, or -1.
func firstIndex(events []bootEvent, pred func(bootEvent) bool) int {
	for i, ev := range events {
		if pred(ev) {
			return i
		}
	}
	return -1
}

// lastIndex returns the index of the last event matching pred, or -1.
func lastIndex(events []bootEvent, pred func(bootEvent) bool) int {
	for i := len(events) - 1; i >= 0; i-- {
		if pred(events[i]) {
			return i
		}
	}
	return -1
}

func isOp(op string) func(bootEvent) bool { return func(ev bootEvent) bool { return ev.op == op } }

// auxvWriteIdx locates the StartupABI's auxv-block materialization: the one
// MemWrite landing in the top page of the initial stack region (the block
// sits just below android.StackTopReserve; nothing else writes there during
// boot — TLS bookkeeping writes go to the TLS region).
func auxvWriteIdx(t *testing.T, e *Emulator, events []bootEvent) int {
	t.Helper()
	stackTop := e.layout.StackBase + e.layout.StackSize
	idx := firstIndex(events, func(ev bootEvent) bool {
		return ev.op == "write" && ev.addr >= stackTop-0x1000 && ev.addr+ev.size <= stackTop
	})
	if idx < 0 {
		t.Fatalf("no auxv-block write found in top stack page [0x%x, 0x%x)", stackTop-0x1000, stackTop)
	}
	return idx
}

// TestBootProbePrecedesBackend locks §4's first prohibition: a failed
// probe / target resolution must happen BEFORE any backend exists — no
// engine is created for a boot that never reaches stage 5.
func TestBootProbePrecedesBackend(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "notelf.so")
	if err := os.WriteFile(bad, []byte("MZ not an elf at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]Config{
		"missing SOPath":    {SOPath: filepath.Join(t.TempDir(), "nope.so"), Engine: bootEngine},
		"non-ELF SOPath":    {SOPath: bad, Engine: bootEngine},
		"unregistered arch": {Arch: arch.ID(0x0DEF), Engine: bootEngine},
	}
	for name, cfg := range cases {
		before := bootBackendCount()
		if _, err := New(cfg); err == nil {
			t.Fatalf("%s: New must fail", name)
		}
		if got := bootBackendCount(); got != before {
			t.Fatalf("%s: %d backend(s) created although the probe/target stage failed — §4 violated", name, got-before)
		}
	}
}

// TestBootTCGStepPrecedesMappingAndExecution pins the TCG step's position in
// the sequence: it runs immediately after backend creation (§4 stage 6) and
// fails fast — a backend that rejects the sizing (the fake is not unicorn)
// must leave New errored with ZERO guest mappings, ZERO loads and ZERO
// executions behind it. The positive path (sized buffer accepted, guest code
// runs afterwards) is the unicorn-tagged regression test in
// boot_order_unicorn_test.go.
func TestBootTCGStepPrecedesMappingAndExecution(t *testing.T) {
	before := bootBackendCount()
	_, err := New(Config{Engine: bootEngine, AssetRoot: "../assets", TCGBufferMiB: 16})
	if err == nil {
		t.Fatal("New with TCGBufferMiB on a non-unicorn engine must error (no silent ignore)")
	}
	created := bootBackendSince(t, before)
	if len(created) != 1 {
		t.Fatalf("expected exactly 1 backend created before the TCG failure, got %d", len(created))
	}
	for _, ev := range created[0].events {
		if ev.op == "map" || ev.op == "mapptr" || ev.op == "protect" || ev.op == "start" {
			t.Fatalf("TCG failure left boot progress behind: event %+v — the sizing step must precede all mapping/execution", ev)
		}
	}
}

// TestBootFinalizePrecedesExecution locks §4's second prohibition on the
// standard main-image boot: every FinalizeImage (MemProtect RW→RX) and the
// StartupABI auxv-block build happen before the FIRST guest execution — and,
// with a main image, the auxv build lands after the last finalize. native.so
// carries no init code, so New itself performs zero Starts; the first
// execution is the explicit CallSymbol afterwards, which the ordering
// assertions then cover too.
func TestBootFinalizePrecedesExecution(t *testing.T) {
	before := bootBackendCount()
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		Engine:    bootEngine,
	})
	if err != nil {
		t.Fatalf("boot on fake backend: %v", err)
	}
	defer e.Close()
	created := bootBackendSince(t, before)
	if len(created) != 1 {
		t.Fatalf("expected exactly 1 backend, got %d", len(created))
	}
	be := created[0]

	if be.events[0].op != "create" {
		t.Fatalf("first backend event = %q, want create (factory runs before anything touches the backend)", be.events[0].op)
	}
	protectIdx := lastIndex(be.events, isOp("protect"))
	if protectIdx < 0 {
		t.Fatal("no MemProtect recorded — FinalizeImage never ran")
	}
	auxvIdx := auxvWriteIdx(t, e, be.events)
	if auxvIdx < protectIdx {
		t.Fatalf("StartupABI auxv build (event %d) precedes the last FinalizeImage (event %d) — §4 violated", auxvIdx, protectIdx)
	}
	if idx := firstIndex(be.events, isOp("start")); idx >= 0 {
		t.Fatalf("guest execution started during New (event %d) before any user call — finalize/startup ordering cannot hold", idx)
	}

	// The first real guest execution: every finalize and the auxv build must
	// already be behind it.
	if _, err := e.CallSymbol("add", 2, 3); err != nil {
		t.Fatalf("CallSymbol: %v", err)
	}
	startIdx := firstIndex(be.events, isOp("start"))
	if startIdx < 0 {
		t.Fatal("CallSymbol produced no Start on the fake backend")
	}
	if startIdx < protectIdx || startIdx < auxvIdx {
		t.Fatalf("first guest execution (event %d) precedes finalize (%d) or auxv build (%d)", startIdx, protectIdx, auxvIdx)
	}
}

// TestBootStartupABIAfterFinalizeBeforeInit locks §4's third prohibition
// with a main image that HAS init code: a copy of the bundled bionic libc.so
// (it carries an 11-entry init_array) booted as Config.SOPath. LoadLibrary's
// contract is LoadModule (…→FinalizeImage) → StartupABI build → RunInit —
// the event log must show exactly that: last MemProtect (finalize) < auxv
// block write < first Start (init_array entry).
func TestBootStartupABIAfterFinalizeBeforeInit(t *testing.T) {
	src, err := os.ReadFile("../assets/android/sdk23/lib64/libc.so")
	if err != nil {
		t.Fatalf("read bionic libc: %v", err)
	}
	main := filepath.Join(t.TempDir(), "libwithinit.so")
	if err := os.WriteFile(main, src, 0o644); err != nil {
		t.Fatal(err)
	}

	before := bootBackendCount()
	e, err := New(Config{SOPath: main, AssetRoot: "../assets", Engine: bootEngine})
	if err != nil {
		t.Fatalf("boot with init-bearing main image: %v", err)
	}
	defer e.Close()
	be := bootBackendSince(t, before)[0]

	if e.main == nil || e.main.Img.InitArrayLen == 0 {
		t.Fatal("test premise broken: the main image must carry an init_array")
	}
	protectIdx := lastIndex(be.events, isOp("protect"))
	auxvIdx := auxvWriteIdx(t, e, be.events)
	startIdx := firstIndex(be.events, isOp("start"))
	if startIdx < 0 {
		t.Fatal("init-bearing main image produced no Start — RunInit never ran")
	}
	if !(protectIdx < auxvIdx && auxvIdx < startIdx) {
		t.Fatalf("§4 order violated: last finalize=%d, StartupABI build=%d, first init execution=%d (want finalize < startup < init)",
			protectIdx, auxvIdx, startIdx)
	}
}
