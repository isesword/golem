package emulator

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
)

// capabilityErr rewrites an engine-capability failure (an error wrapping
// emu.ErrUnsupported) into one that names the operation and the engine;
// ordinary backend errors pass through unchanged. This replaces engine-NAME
// gating ("if engine != unicorn") with capability gating, so a future backend
// without per-instruction hooks degrades through emu.ErrUnsupported instead
// of a string check.
func (e *Emulator) capabilityErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, emu.ErrUnsupported) {
		return fmt.Errorf("%s: %w (engine %q)", op, err, e.engine)
	}
	return err
}

// capabilityUnavailable is the probe half of capability gating (P2.5a,
// DESIGN.md invariant 14): the engine does not implement the capability
// interface backing op at all. The error wraps emu.ErrUnsupported so callers
// keep ONE errors.Is degrade path whether the capability is absent (type
// assertion failed) or present but refused (backend returned ErrUnsupported).
func (e *Emulator) capabilityUnavailable(op string) error {
	return fmt.Errorf("%s: %w (engine %q)", op, emu.ErrUnsupported, e.engine)
}

// Guest memory protection bits (mirror the CPU backend's UC_PROT_*).
const (
	ProtNone  = emu.ProtNone
	ProtRead  = emu.ProtRead
	ProtWrite = emu.ProtWrite
	ProtExec  = emu.ProtExec
	ProtAll   = emu.ProtAll
)

// allocArena carves call-scratch allocations out of large pre-mapped chunks.
// Mapping a fresh region per allocation (the old behavior) made every Alloc
// pay a uc_mem_map whose cost grows with the engine's region count — on a
// long-lived emulator that degraded per-call latency linearly (14ms → seconds
// over a few thousand calls). Chunks are never reused (no free), so there is
// no aliasing hazard for pointers the guest retains across calls; the cost is
// virtual address space, which a 64-bit guest has to spare.
type allocArena struct {
	base uint64 // current chunk base (0 = none)
	off  uint64 // allocation cursor inside the chunk
	size uint64 // current chunk size
}

const (
	arenaChunk    = 4 << 20 // map 4 MiB per chunk
	arenaMaxAlloc = 2 << 20 // larger allocs get their own region (e.g. fiber stacks)
)

// Alloc returns the base of at least `size` bytes of guest memory with the
// given protection. RW sizes up to arenaMaxAlloc are carved from the arena;
// anything else maps a dedicated region as before.
//
// The backing uc_mem_map failure is returned as an error AND the address-
// space bookkeeping is rolled back (no phantom region, no consumed VA); a
// failed ROLLBACK poisons the emulator (the space is inconsistent — P7.5b:
// armed for real, not just claimed in the message). Call sites that cannot
// propagate errors (guest-initiated JNI up-calls) use MustAlloc instead.
func (e *Emulator) Alloc(size uint64, prot int) (uint64, error) {
	if e.poisonErr != nil {
		return 0, fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	return e.doAlloc(size, prot)
}

// MustAlloc is Alloc with panic-on-error — reserved for call sites inside
// guest-initiated up-calls (jni_dispatch) where no error channel exists.
// The panic lands in the guest-callback guard, which poisons the emulator.
func (e *Emulator) MustAlloc(size uint64, prot int) uint64 {
	if e.poisonErr != nil {
		panic(fmt.Sprintf("emulator: MustAlloc(%#x, %d): %v", size, prot, e.poisonErr))
	}
	a, err := e.doAlloc(size, prot)
	if err != nil {
		panic(fmt.Sprintf("emulator: MustAlloc(%#x, %d): %v — guest memory mapping failed", size, prot, err))
	}
	return a
}

func (e *Emulator) doAlloc(size uint64, prot int) (uint64, error) {
	if prot == ProtRead|ProtWrite && 0 < size && size <= arenaMaxAlloc {
		size = (size + 15) &^ 15
		a := &e.alloc
		if a.base == 0 || a.off+size > a.size {
			chunk := arenaChunk
			if uint64(chunk) < size {
				chunk = int((size + 0xfff) &^ 0xfff)
			}
			base := e.mem.Mmap(uint64(chunk), prot, "arena")
			if err := e.be.MemMap(emu.GuestAddr(base), uint64(chunk), prot); err != nil {
				// transaction: the bookkeeping region must not outlive a
				// failed backend map; if the rollback itself fails the
				// address space is inconsistent — POISON FOR REAL (P7.5b:
				// the message used to claim this without arming it).
				if rb := e.mem.RollbackLast(base, uint64(chunk)); rb != nil {
					return 0, e.poison(fmt.Sprintf("map arena chunk %#x", base),
						fmt.Errorf("%w (rollback also failed: %v — address space inconsistent)", err, rb))
				}
				return 0, fmt.Errorf("map arena chunk %#x: %w", base, err)
			}
			*a = allocArena{base: base, off: 0, size: uint64(chunk)}
		}
		addr := a.base + a.off
		a.off += size
		return addr, nil
	}
	a := e.mem.Mmap(size, prot, "alloc")
	if err := e.be.MemMap(emu.GuestAddr(a), (size+0xfff)&^0xfff, prot); err != nil {
		if rb := e.mem.RollbackLast(a, (size+0xfff)&^0xfff); rb != nil {
			return 0, e.poison(fmt.Sprintf("map %#x", a),
				fmt.Errorf("%w (rollback also failed: %v — address space inconsistent)", err, rb))
		}
		return 0, fmt.Errorf("map %#x: %w", a, err)
	}
	return a, nil
}

// Malloc maps a fresh read/write guest region and returns its base.
func (e *Emulator) Malloc(size uint64) (uint64, error) { return e.Alloc(size, ProtRead|ProtWrite) }

// WriteScratch copies bytes into a fresh RW region and returns the address.
// Panics on failure: its callers live inside guest-initiated JNI up-calls
// where no error channel exists (use Alloc directly where errors propagate).
func (e *Emulator) WriteScratch(data []byte) uint64 {
	a := e.MustAlloc(uint64(len(data))+16, ProtRead|ProtWrite)
	if err := e.be.MemWrite(emu.GuestAddr(a), data); err != nil {
		panic(fmt.Sprintf("emulator: WriteScratch: %v", err))
	}
	return a
}

// WriteBytes writes raw bytes to guest memory at addr.
func (e *Emulator) WriteBytes(addr uint64, data []byte) error {
	return e.be.MemWrite(emu.GuestAddr(addr), data)
}

// ReadBytes reads n bytes from guest memory at addr.
func (e *Emulator) ReadBytes(addr, n uint64) ([]byte, error) {
	return e.be.MemRead(emu.GuestAddr(addr), n)
}

// WriteCString writes s followed by a NUL terminator at addr.
func (e *Emulator) WriteCString(addr uint64, s string) error {
	return e.be.MemWrite(emu.GuestAddr(addr), append([]byte(s), 0))
}

// WriteCStringAlloc allocates a region, writes s+NUL, and returns its address.
func (e *Emulator) WriteCStringAlloc(s string) uint64 { return e.WriteScratch(append([]byte(s), 0)) }

// ReadU32 / ReadU64 read a little-endian integer from guest memory.
func (e *Emulator) ReadU32(addr uint64) (uint32, error) {
	b, err := e.be.MemRead(emu.GuestAddr(addr), 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (e *Emulator) ReadU64(addr uint64) (uint64, error) {
	b, err := e.be.MemRead(emu.GuestAddr(addr), 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// WriteU32 / WriteU64 write a little-endian integer to guest memory.
func (e *Emulator) WriteU32(addr uint64, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return e.be.MemWrite(emu.GuestAddr(addr), b[:])
}
func (e *Emulator) WriteU64(addr uint64, v uint64) error { return putU64(e.be, addr, v) }

// ReadCStr reads a NUL-terminated string from guest memory.
func (e *Emulator) ReadCStr(addr uint64) (string, error) {
	var out []byte
	for {
		b, err := e.be.MemRead(emu.GuestAddr(addr+uint64(len(out))), 64)
		if err != nil {
			return "", err
		}
		for _, c := range b {
			if c == 0 {
				return string(out), nil
			}
			out = append(out, c)
		}
		if len(out) > 1<<20 {
			return string(out), nil
		}
	}
}

// ReadCString is an alias for ReadCStr (unidbg-style naming).
func (e *Emulator) ReadCString(addr uint64) (string, error) { return e.ReadCStr(addr) }

// ---- function replacement (native hook) -----------------------------------

// Hook is the context passed to a Replace callback: read the incoming args and
// reach the emulator for memory access; the callback's return value becomes the
// call's result (written back per the target's CallABI).
type Hook struct{ e *Emulator }

// Emu returns the emulator, for memory access inside a Replace callback.
func (h *Hook) Emu() *Emulator { return h.e }

// Arg returns integer argument i (0-based) of the in-flight guest call, read
// through the CallABI (register portion first, then the stack spill area —
// valid at function entry, where interposition entry hooks fire).
func (h *Hook) Arg(i int) uint64 {
	if i < 0 {
		return 0
	}
	args, err := h.e.callABI.ReadArgs(h.e.be, i+1)
	if err != nil || len(args) <= i {
		return 0
	}
	return args[i]
}

// Reg returns (value, ok) for register-file index i — AArch64 order: 0..30 =
// x0..x30, 31 = SP, 32 = PC, 33 = NZCV — via the RegFileReader capability.
// ok=false means "this engine/arch has no register-file dump" (or i out of
// range): a genuine zero value and a missing register stay distinguishable
// (P7.5c — this used to answer a silent 0 for both). For call ARGUMENTS use
// Arg: it covers registers and stack spill alike through the CallABI.
func (h *Hook) Reg(i int) (uint64, bool) {
	rr, ok := h.e.be.(emu.RegFileReader)
	if !ok {
		return 0, false
	}
	regs, err := rr.ReadGPRegs()
	if err != nil || i < 0 || i >= len(regs) {
		return 0, false
	}
	return regs[i], true
}

// SetArg sets integer argument register i — e.g. to rewrite an argument from
// an inline hook. Register-shaped introspection only (the optional
// arch.CallABIIntrospector capability): an argument beyond the register
// portion lives on the stack and must be rewritten in guest memory instead.
func (h *Hook) SetArg(i int, v uint64) {
	intro, ok := h.e.callABI.(arch.CallABIIntrospector)
	if !ok {
		return
	}
	if r, ok := intro.ArgReg(i); ok {
		_ = h.e.be.RegWrite(r, v)
	}
}

// PC / SP read those registers (handy inside an inline hook).
func (h *Hook) PC() uint64 { v, _ := h.e.be.RegRead(h.e.pcReg); return v }
func (h *Hook) SP() uint64 { v, _ := h.e.be.RegRead(h.e.spReg); return v }

// SetPC redirects execution (e.g. skip an instruction, jump elsewhere).
func (h *Hook) SetPC(v uint64) { _ = h.e.be.RegWrite(h.e.pcReg, v) }

// RegRead / RegWrite / MemRead / MemWrite make *Hook satisfy
// interpose.CallContext (P2.5d): the interpose package cannot import
// emulator, so the interposition callback contract is defined there and the
// Hook — the emulator's own callback context — adapts to it.
func (h *Hook) RegRead(r emu.Reg) (uint64, error)  { return h.e.be.RegRead(r) }
func (h *Hook) RegWrite(r emu.Reg, v uint64) error { return h.e.be.RegWrite(r, v) }
func (h *Hook) MemWrite(a emu.GuestAddr, d []byte) error {
	return h.e.be.MemWrite(a, d)
}
func (h *Hook) MemRead(a emu.GuestAddr, n uint64) ([]byte, error) {
	return h.e.be.MemRead(a, n)
}

// ReplaceFunc is a Go stand-in for a native function; its return value is the
// function's return (X0).
type ReplaceFunc func(h *Hook) uint64

// Replace makes calls to the function at addr run fn instead. Since P2.5d
// (DESIGN.md §3.8, invariant 11) this is FUNCTION INTERPOSITION, not a code
// patch: guest .text is immutable, so instead of overwriting the entry with a
// trampoline the emulator binds fn in the InterposeTable and installs a
// per-entry execution hook (emu.InstructionHooker.HookCode on exactly
// [addr, addr]). When guest PC reaches addr the hook fires BEFORE the first
// instruction executes: fn runs, its result is written back via
// CallABI.WriteResult, and CallABI.ReturnFromCall hands control to the guest
// caller — the original function body never executes.
//
// Interposition needs per-instruction code hooks; an engine without the
// InstructionHooker capability fails ReplaceE with an error wrapping
// emu.ErrUnsupported. Replacing an already-replaced address is an error (an
// interposed entry owns exactly one hook).
func (e *Emulator) ReplaceE(addr uint64, fn ReplaceFunc) error {
	// Adapt the ReplaceFunc to an interpose.HostFunc: the callback context is
	// the Hook, which satisfies interpose.CallContext.
	hf := interpose.HostFunc(func(ctx interpose.CallContext) uint64 {
		return fn(ctx.(*Hook))
	})
	return e.interposeE(addr, hf)
}

// interposeE is ReplaceE for an already-adapted interpose.HostFunc — the
// form platform configs (android.Config.ReplaceFns) carry, so New's
// exported-symbol replacement pass does not round-trip through ReplaceFunc.
func (e *Emulator) interposeE(addr uint64, hf interpose.HostFunc) error {
	if e.poisonErr != nil {
		return fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	ih, ok := e.be.(emu.InstructionHooker)
	if !ok {
		return e.capabilityUnavailable("Replace")
	}
	// Duplicate pre-check: an interposed entry owns exactly one hook — a
	// second Replace on the same address would stack hooks that both fire.
	if _, dup := e.itab.LookupAddress(emu.GuestAddr(addr)); dup {
		return fmt.Errorf("Replace %#x: address already interposed", addr)
	}
	// Performance constraint (DESIGN.md §8): the hook covers exactly the one
	// entry address, never a range. Installed BEFORE binding so a failed
	// ReplaceE leaves no state at all (an unbound entry hook is a benign
	// no-op: onInterpose's LookupAddress misses and the guest runs on).
	hook, err := ih.HookCode(emu.GuestAddr(addr), emu.GuestAddr(addr), e.guardCode(e.onInterpose))
	if err != nil {
		return e.capabilityErr("Replace", err)
	}
	// Unicorn instruments hook callouts into translated blocks AT TRANSLATION
	// TIME: a TB translated before this hook was added (the function already
	// ran once) would never fire it, so the affected code-cache range must be
	// flushed after installing the hook — through the CodeCacheController
	// capability (P3.5), not a backend-specific call. A failed flush leaves
	// the hook installed-but-inert — remove it so a retry does not stack
	// hooks. An engine with hooks but no CodeCacheController capability
	// presumably does not cache translations (nothing to invalidate), so
	// absence is tolerated.
	if cc, ok := e.be.(emu.CodeCacheController); ok {
		if err := cc.FlushCodeCache(emu.GuestAddr(addr), emu.GuestAddr(addr)+1); err != nil {
			_ = hook.Remove()
			return e.capabilityErr("Replace", err)
		}
	}
	if err := e.itab.BindAddress(emu.GuestAddr(addr), hf); err != nil {
		_ = hook.Remove()
		return err // unreachable after the pre-check (single-threaded)
	}
	return nil
}

// onInterpose is the single dispatch behind every interposition entry hook:
// look the entry up in the InterposeTable, run the host function, write its
// result back per the CallABI and return to the guest caller. Runs inside the
// engine's callback trampoline, guarded like every backend callback.
func (e *Emulator) onInterpose(b emu.Backend, addr uint64, _ uint32) {
	hf, ok := e.itab.LookupAddress(emu.GuestAddr(addr))
	if !ok {
		return // hook outlived its binding (cannot happen today; keep it benign)
	}
	ret := hf(&Hook{e})
	if err := e.callABI.WriteResult(b, arch.CallResult{Value: ret}); err != nil && e.cfg.Verbose {
		fmt.Printf("[interpose] %#x: WriteResult: %v\n", addr, err)
	}
	if err := e.callABI.ReturnFromCall(b); err != nil && e.cfg.Verbose {
		fmt.Printf("[interpose] %#x: ReturnFromCall: %v\n", addr, err)
	}
}

// Replace is ReplaceE with panic-on-error, for call sites that cannot
// propagate errors. Prefer ReplaceE.
func (e *Emulator) Replace(addr uint64, fn ReplaceFunc) {
	if err := e.ReplaceE(addr, fn); err != nil {
		panic(err.Error())
	}
}

// ReplaceSymbol is Replace by exported symbol name.
func (e *Emulator) ReplaceSymbol(name string, fn ReplaceFunc) error {
	addr, ok := e.Sym(name)
	if !ok {
		return fmt.Errorf("symbol %q not found", name)
	}
	return e.ReplaceE(addr, fn)
}

// ---- inline hooks ----------------------------------------------------------

// HookAddr installs an inline hook that fires every time guest PC reaches addr
// (mid-function, not just at the entry like Replace). The callback reads/edits
// registers via *Hook — rewrite an argument, capture a value, or SetPC to skip
// or redirect. Returns a remover.
//
// Inline hooks need per-instruction code hooks; an engine without the
// InstructionHooker capability returns an error wrapping emu.ErrUnsupported.
// (Replace uses the same capability since P2.5d — entry interception is an
// execution hook too, no longer an SVC trap patch.)
func (e *Emulator) HookAddr(addr uint64, fn func(h *Hook)) (func(), error) {
	ih, ok := e.be.(emu.InstructionHooker)
	if !ok {
		return nil, e.capabilityUnavailable("HookAddr")
	}
	h, err := ih.HookCode(emu.GuestAddr(addr), emu.GuestAddr(addr), e.guardCode(func(b emu.Backend, a uint64, size uint32) {
		fn(&Hook{e})
	}))
	if err != nil {
		return nil, e.capabilityErr("HookAddr", err)
	}
	return func() { _ = h.Remove() }, nil
}

// HookSymbol is HookAddr by exported symbol name.
func (e *Emulator) HookSymbol(name string, fn func(h *Hook)) (func(), error) {
	addr, ok := e.Sym(name)
	if !ok {
		return nil, fmt.Errorf("symbol %q not found", name)
	}
	return e.HookAddr(addr, fn)
}

// HookRange installs a per-instruction hook over [start,end); fn gets the Hook
// and the current PC. Like HookAddr but for a whole region (needs an engine
// with per-instruction code hooks; see HookAddr).
func (e *Emulator) HookRange(start, end uint64, fn func(h *Hook, addr uint64)) (func(), error) {
	ih, ok := e.be.(emu.InstructionHooker)
	if !ok {
		return nil, e.capabilityUnavailable("HookRange")
	}
	h, err := ih.HookCode(emu.GuestAddr(start), emu.GuestAddr(end), e.guardCode(func(b emu.Backend, a uint64, size uint32) {
		fn(&Hook{e}, a)
	}))
	if err != nil {
		return nil, e.capabilityErr("HookRange", err)
	}
	return func() { _ = h.Remove() }, nil
}

// HookMemRead fires on every valid memory READ in [start,end]; fn gets the Hook
// (h.PC() = the reading instruction) and the read (addr,size). Needs an engine
// with memory-access hooks (errors wrap emu.ErrUnsupported otherwise).
func (e *Emulator) HookMemRead(start, end uint64, fn func(h *Hook, addr uint64, size int)) (func(), error) {
	mh, ok := e.be.(emu.MemReadHooker)
	if !ok {
		return nil, e.capabilityUnavailable("HookMemRead")
	}
	h, err := mh.HookMemRead(emu.GuestAddr(start), emu.GuestAddr(end), e.guardMemRead(func(b emu.Backend, addr uint64, size int) {
		fn(&Hook{e}, addr, size)
	}))
	if err != nil {
		return nil, e.capabilityErr("HookMemRead", err)
	}
	return func() { _ = h.Remove() }, nil
}

// HookMemWrite fires on every valid memory WRITE in [start,end]; fn gets the Hook
// (h.PC() = the writing instruction), the (addr,size), and the value being
// written. Needs an engine with memory-access hooks (see HookMemRead).
func (e *Emulator) HookMemWrite(start, end uint64, fn func(h *Hook, addr uint64, size int, value int64)) (func(), error) {
	mh, ok := e.be.(emu.MemWriteHooker)
	if !ok {
		return nil, e.capabilityUnavailable("HookMemWrite")
	}
	h, err := mh.HookMemWrite(emu.GuestAddr(start), emu.GuestAddr(end), e.guardMemWrite(func(b emu.Backend, addr uint64, size int, value int64) {
		fn(&Hook{e}, addr, size, value)
	}))
	if err != nil {
		return nil, e.capabilityErr("HookMemWrite", err)
	}
	return func() { _ = h.Remove() }, nil
}

// ---- tracing ---------------------------------------------------------------

// Trace prints every executed instruction's PC (with nearest symbol) in
// [start,end). Returns a remover. Requires a backend with per-instruction
// code hooks.

func (e *Emulator) Trace(start, end uint64) (func(), error) {
	ih, ok := e.be.(emu.InstructionHooker)
	if !ok {
		return nil, e.capabilityUnavailable("Trace")
	}
	h, err := ih.HookCode(emu.GuestAddr(start), emu.GuestAddr(end), e.guardCode(func(b emu.Backend, addr uint64, size uint32) {
		fmt.Printf("[trace] 0x%x  %s\n", addr, e.NearestSym(addr))
	}))
	if err != nil {
		return nil, err
	}
	return func() { _ = h.Remove() }, nil
}
