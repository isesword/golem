package emulator

import (
	"debug/elf"
	"fmt"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
)

// Snapshot is a full, restorable image of one emulator's mutable guest+host
// state, captured after boot/init. Restoring it rewinds the instance to that
// exact point, so a pooled emulator can serve many calls while each call starts
// from the same pristine state a freshly-booted process would have.
//
// This is the cure for signature/output drift when reusing an emulator: an
// obfuscated .so accumulates state across calls — globals in .data/.bss, heap
// contents and allocation addresses (which shift as the monotonic arena grows),
// leftover stack bytes, the exit latch, JNI handles — so call N diverges from a
// clean call 1. It is unidbg's classic "save/restore context" pattern.
//
// Not safe for concurrent use: hold the emulator exclusively (as a worker pool
// does — one request per instance at a time) around Snapshot and Restore.
type Snapshot struct {
	cpu         emu.CPUContext  // full register file (GP + SIMD + SP/PC/PSTATE/TPIDR)
	writable    []memWrite      // bytes of every writable guest region at snapshot time
	layout      []memory.Region // mmap-arena allocator table
	mmapTop     uint64          // mmap-arena cursor
	arena       allocArena      // scratch-arena cursor (chunk base/off/size)
	kstate      kernel.State    // brk / exit latch / fds / FS overlay
	vmstate     dvm.VMState     // JNI object-handle table
	nextFiberID int
	// The AddressSpace module/stub bump cursors (e.as) are deliberately NOT
	// captured: restore does not roll back module/stub VA allocation — the
	// same semantics the legacy module/stub cursor fields had (they lived
	// outside the snapshot too). Modules loaded and stubs emitted after the
	// snapshot keep their addresses across a Restore.
}

type memWrite struct {
	addr uint64
	prot int
	data []byte
}

type memRange struct {
	addr uint64
	size uint64
	prot int
}

func pageDown(x uint64) uint64 { return x &^ 0xfff }
func pageUp(x uint64) uint64   { return (x + 0xfff) &^ 0xfff }

// writableGuestRanges lists every writable guest region whose bytes can change
// during a call and therefore must be captured and restored. These live in
// different maps — most are backed on the CPU engine directly and are NOT in the
// mmap-arena allocator (Space) — so they're assembled explicitly:
//
//   - stack, TLS, import-stub trampolines (fixed regions mapped at boot),
//   - each module's writable (.data/.bss) segments — the accumulating globals,
//   - the brk heap [BrkBase, BrkTop),
//   - the mmap arena (host scratch + guest mmap, the only Space-tracked set).
func (e *Emulator) writableGuestRanges() []memRange {
	l := e.layout
	rs := []memRange{
		{l.StackBase, l.StackSize, emu.ProtRead | emu.ProtWrite},
		{l.TLSBase, l.TLSSize, emu.ProtRead | emu.ProtWrite},
		{l.StubBase, l.StubSize, emu.ProtAll},
	}
	for _, m := range e.modules {
		for _, s := range m.Img.Segments {
			if s.Flags&elf.PF_W == 0 {
				continue // .text/.rodata never change across calls
			}
			va := m.Base + pageDown(s.Vaddr)
			rs = append(rs, memRange{va, pageUp(s.Vaddr+s.MemSz) - pageDown(s.Vaddr), emu.ProtRead | emu.ProtWrite})
		}
	}
	if top := e.kctx.BrkTop(); top > kernel.BrkBase {
		rs = append(rs, memRange{kernel.BrkBase, top - kernel.BrkBase, emu.ProtRead | emu.ProtWrite})
	}
	for _, r := range e.mem.Regions() {
		if r.Prot&emu.ProtWrite == 0 {
			continue
		}
		size := r.Size
		if r.Desc == "arena" && r.Addr == e.alloc.base {
			// Only the carved prefix of the current arena chunk can hold guest
			// bytes; dumping the whole chunk would memcpy untouched VA on every
			// Save. Past chunks are fully carved — dump them whole.
			if size = (e.alloc.off + 0xfff) &^ 0xfff; size == 0 {
				continue
			}
		}
		rs = append(rs, memRange{r.Addr, size, r.Prot})
	}
	return rs
}

// Snapshot captures the current guest state. Take it once, right after New()
// (which has already run init_array + JNI_OnLoad) and after any Replace/patch
// setup, then Restore before each reused call. The returned Snapshot owns a
// backend CPU context; release it with Free when the emulator is discarded.
func (e *Emulator) Snapshot() (*Snapshot, error) {
	cm, ok := e.be.(emu.ContextManager)
	if !ok { // capability probe: engine cannot snapshot CPU state
		return nil, fmt.Errorf("snapshot: save cpu: %w (engine %q)", emu.ErrUnsupported, e.engine)
	}
	cpu, err := cm.SaveContext()
	if err != nil {
		return nil, fmt.Errorf("snapshot: save cpu: %w", err)
	}
	var writable []memWrite
	for _, r := range e.writableGuestRanges() {
		data, err := e.be.MemRead(emu.GuestAddr(r.addr), r.size)
		if err != nil {
			continue // unmapped hole (e.g. a gap between segments) — nothing to restore
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		writable = append(writable, memWrite{addr: r.addr, prot: r.prot, data: buf})
	}
	regs := e.mem.Regions()
	layout := make([]memory.Region, len(regs))
	copy(layout, regs)

	return &Snapshot{
		cpu:         cpu,
		writable:    writable,
		layout:      layout,
		mmapTop:     e.mem.MmapTop(),
		arena:       e.alloc,
		kstate:      e.kctx.Snapshot(),
		vmstate:     e.vm.Snapshot(),
		nextFiberID: e.nextFiberID,
	}, nil
}

// Restore rewinds the emulator to snap. Call it before each reused invocation
// (before writing this call's arguments) so the call runs against pristine
// state. Cost is a memcpy of the writable footprint through the backend — a few
// milliseconds, negligible against a real sign.
func (e *Emulator) Restore(snap *Snapshot) error {
	if snap == nil {
		return fmt.Errorf("restore: nil snapshot")
	}
	// Poisoned = untrustworthy address space; rebuilding a snapshot on top of
	// it would launder the inconsistency into "restored" state .
	if e.poisonErr != nil {
		return fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	// 1) Unmap arena regions the guest mapped after the snapshot (scratch allocs,
	//    guest mmaps) so the address space matches the snapshot again.
	snapSet := make(map[uint64]uint64, len(snap.layout))
	for _, r := range snap.layout {
		snapSet[r.Addr] = r.Size
	}
	for _, r := range e.mem.Regions() {
		if sz, ok := snapSet[r.Addr]; !ok || sz != r.Size {
			_ = e.be.MemUnmap(emu.GuestAddr(r.Addr), r.Size)
		}
	}
	// 2) Restore the arena allocator table + cursor. If the cursor's chunk was
	//    mapped after the snapshot, Restore's unmap pass above already dropped
	//    it — reset the cursor so the next Alloc maps a fresh chunk instead of
	//    carving into unmapped VA.
	e.mem.SetLayout(snap.layout, snap.mmapTop)
	// classRefs caches GLOBAL handles; handles created after the snapshot die
	// with the rewind (and their numbers get reissued), so the cache must be
	// dropped — it is a pure interning cache and rebuilds lazily.
	e.classRefs = map[string]dvm.Ref{}
	e.alloc = snap.arena
	if e.alloc.base != 0 {
		if _, ok := e.mem.Find(e.alloc.base); !ok {
			e.alloc = allocArena{}
		}
	}
	// 3) Restore kernel state — this also unmaps brk pages grown during the call,
	//    freeing those addresses before we write the snapshot brk bytes back.
	e.kctx.Restore(snap.kstate)
	// 4) Restore writable memory bytes: stack, TLS, stubs, .data/.bss, brk, arena.
	//    Re-map defensively if a region was unmapped or split mid-call.
	for _, w := range snap.writable {
		if err := e.be.MemWrite(emu.GuestAddr(w.addr), w.data); err != nil {
			_ = e.be.MemMap(emu.GuestAddr(w.addr), uint64(len(w.data)), w.prot)
			if err := e.be.MemWrite(emu.GuestAddr(w.addr), w.data); err != nil {
				return fmt.Errorf("restore: write 0x%x: %w", w.addr, err)
			}
		}
	}
	// 5) Restore the CPU register file (incl. SP → a fresh, dirty-free stack top,
	//    TPIDR, PSTATE). CallFunc overwrites X0..X7/LR/PC for the next call.
	cm, ok := e.be.(emu.ContextManager)
	if !ok { // capability probe: engine cannot restore CPU state
		return fmt.Errorf("restore: cpu: %w (engine %q)", emu.ErrUnsupported, e.engine)
	}
	if err := cm.RestoreContext(snap.cpu); err != nil {
		return fmt.Errorf("restore: cpu: %w", err)
	}
	// 6) Restore JNI object handles and reset per-run scheduler / JNI scratch.
	e.vm.Restore(snap.vmstate)
	e.fibers = nil
	e.curFiber = nil
	e.nextFiberID = snap.nextFiberID
	e.threadCap, e.threadOps, e.yieldReason, e.yieldAddr = 0, 0, 0, 0
	e.scCount = 0
	e.pendingExc = false
	e.arrayPins = map[uint64]pinEntry{}
	e.pinGen++
	return nil
}

// Free releases the snapshot's backend CPU context. Call it when the emulator
// (and thus this snapshot) is being discarded, e.g. on pool renewal or Close.
func (s *Snapshot) Free() {
	if s != nil && s.cpu != nil {
		_ = s.cpu.Free()
		s.cpu = nil
	}
}
