package emulator

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/emu"
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
// space bookkeeping is rolled back (no phantom region, no consumed VA).
// Call sites that cannot propagate errors (guest-initiated JNI up-calls)
// use MustAlloc instead.
func (e *Emulator) Alloc(size uint64, prot int) (uint64, error) {
	return e.doAlloc(size, prot)
}

// MustAlloc is Alloc with panic-on-error — reserved for call sites inside
// guest-initiated up-calls (jni_dispatch) where no error channel exists.
func (e *Emulator) MustAlloc(size uint64, prot int) uint64 {
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
			if err := e.be.MemMap(base, uint64(chunk), prot); err != nil {
				// transaction: the bookkeeping region must not outlive a
				// failed backend map; if the rollback itself fails the
				// emulator is poisoned (address space inconsistent).
				if rb := e.mem.RollbackLast(base, uint64(chunk)); rb != nil {
					return 0, fmt.Errorf("map arena chunk %#x: %w (rollback also failed: %v — emulator poisoned)", base, err, rb)
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
	if err := e.be.MemMap(a, (size+0xfff)&^0xfff, prot); err != nil {
		if rb := e.mem.RollbackLast(a, (size+0xfff)&^0xfff); rb != nil {
			return 0, fmt.Errorf("map %#x: %w (rollback also failed: %v — emulator poisoned)", a, err, rb)
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
	if err := e.be.MemWrite(a, data); err != nil {
		panic(fmt.Sprintf("emulator: WriteScratch: %v", err))
	}
	return a
}

// WriteBytes writes raw bytes to guest memory at addr.
func (e *Emulator) WriteBytes(addr uint64, data []byte) error { return e.be.MemWrite(addr, data) }

// ReadBytes reads n bytes from guest memory at addr.
func (e *Emulator) ReadBytes(addr, n uint64) ([]byte, error) { return e.be.MemRead(addr, n) }

// WriteCString writes s followed by a NUL terminator at addr.
func (e *Emulator) WriteCString(addr uint64, s string) error {
	return e.be.MemWrite(addr, append([]byte(s), 0))
}

// WriteCStringAlloc allocates a region, writes s+NUL, and returns its address.
func (e *Emulator) WriteCStringAlloc(s string) uint64 { return e.WriteScratch(append([]byte(s), 0)) }

// ReadU32 / ReadU64 read a little-endian integer from guest memory.
func (e *Emulator) ReadU32(addr uint64) (uint32, error) {
	b, err := e.be.MemRead(addr, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
func (e *Emulator) ReadU64(addr uint64) (uint64, error) {
	b, err := e.be.MemRead(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// WriteU32 / WriteU64 write a little-endian integer to guest memory.
func (e *Emulator) WriteU32(addr uint64, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return e.be.MemWrite(addr, b[:])
}
func (e *Emulator) WriteU64(addr uint64, v uint64) error { return putU64(e.be, addr, v) }

// ReadCStr reads a NUL-terminated string from guest memory.
func (e *Emulator) ReadCStr(addr uint64) (string, error) {
	var out []byte
	for {
		b, err := e.be.MemRead(addr+uint64(len(out)), 64)
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
// reach the emulator for memory access; the callback's return value becomes X0.
type Hook struct{ e *Emulator }

// Emu returns the emulator, for memory access inside a Replace callback.
func (h *Hook) Emu() *Emulator { return h.e }

// Arg returns integer argument / register Xi (0-based, X0..X7).
func (h *Hook) Arg(i int) uint64 {
	if i < 0 || i > 7 {
		return 0
	}
	v, _ := h.e.be.RegRead(emu.RegX0 + emu.Reg(i))
	return v
}

// Reg returns register Xi for any i in 0..30 (also 31=SP, 32=PC, 33=NZCV) via the
// full GP register file. Use this instead of Arg for X8..X30 (Arg only covers X0..X7).
func (h *Hook) Reg(i int) uint64 {
	if i < 0 || i > 33 {
		return 0
	}
	regs, err := h.e.be.ReadGPRegs()
	if err != nil {
		return 0
	}
	return regs[i]
}

// SetArg sets register Xi (0..7) — e.g. to rewrite an argument from an inline hook.
func (h *Hook) SetArg(i int, v uint64) {
	if i >= 0 && i <= 7 {
		_ = h.e.be.RegWrite(emu.RegX0+emu.Reg(i), v)
	}
}

// PC / SP / LR read those registers (handy inside an inline hook).
func (h *Hook) PC() uint64 { v, _ := h.e.be.RegRead(emu.RegPC); return v }
func (h *Hook) SP() uint64 { v, _ := h.e.be.RegRead(emu.RegSP); return v }
func (h *Hook) LR() uint64 { v, _ := h.e.be.RegRead(emu.RegLR); return v }

// SetPC redirects execution (e.g. skip an instruction, jump elsewhere).
func (h *Hook) SetPC(v uint64) { _ = h.e.be.RegWrite(emu.RegPC, v) }

// ReplaceFunc is a Go stand-in for a native function; its return value is the
// function's return (X0).
type ReplaceFunc func(h *Hook) uint64

// Replace makes calls to the function at addr run fn instead (the entry is
// overwritten with an `svc; ret` trampoline). This is golem's analogue of
// unidbg's hook/replace: model or stub a native function in Go. Works on both
// engines (it's a trap, not an inline patch).
// Replace entry-patches `addr` with an SVC trap dispatched to fn. Panics if
// any step fails (privatize/write/flush): a half-applied patch — code
// patched but stale translation cached, or a registered hook the guest
// never reaches — is worse than a loud failure at setup time.
// ReplaceE entry-patches addr with an SVC trap dispatched to fn — the
// transactional form: privatize shared pages, save the original instructions,
// write the patch, flush, and only then register the hook. Any failure rolls
// the patch back (original instructions restored + flushed); if even the
// rollback cannot be verified the emulator is POISONED and every later
// CallFunc/RunThreads rejects with that error. On a recoverable failure the
// emulator remains usable and the original code still runs.
func (e *Emulator) ReplaceE(addr uint64, fn ReplaceFunc) error {
	if e.poisonErr != nil {
		return fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	// 1. privatize (shared -> private with identical content). On a
	// recoverable privatize failure the original code is intact.
	if err := e.privatize(addr, 8); err != nil {
		if e.poisonErr != nil {
			return e.poisonErr
		}
		return fmt.Errorf("privatize %#x: %w", addr, err)
	}
	// 2. save the original instructions we are about to overwrite.
	orig, err := e.be.MemRead(addr, 8)
	if err != nil {
		return fmt.Errorf("read original %#x: %w", addr, err)
	}
	// 3. write the patch. A partial write cannot be verified -> poison.
	if err := e.be.MemWrite(addr, []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6}); err != nil {
		return e.poison(fmt.Sprintf("patch write %#x", addr), err)
	}
	// 4. flush stale translations. If it fails, roll the original
	// instructions back; if even the rollback cannot be verified -> poison.
	if err := e.be.FlushCache(); err != nil {
		if rerr := e.be.MemWrite(addr, orig); rerr != nil {
			return e.poison(fmt.Sprintf("rollback write %#x", addr), rerr)
		}
		if rerr := e.be.FlushCache(); rerr != nil {
			return e.poison(fmt.Sprintf("rollback flush %#x", addr), rerr)
		}
		return fmt.Errorf("Replace %#x: flush failed (%v) — original instructions restored", addr, err)
	}
	// 5. success: register the dispatch hook last.
	e.replaced[addr] = e.guardHostFn(func(em *Emulator, b emu.Backend) {
		ret := fn(&Hook{em})
		_ = b.RegWrite(emu.RegX0, ret)
	})
	return nil
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
// Inline hooks need per-instruction code hooks; an engine without them
// returns an error wrapping emu.ErrUnsupported (use Replace for entry
// interception, which works on any engine — it is a trap, not an inline patch).
func (e *Emulator) HookAddr(addr uint64, fn func(h *Hook)) (func(), error) {
	h, err := e.be.HookCode(addr, addr, e.guardCode(func(b emu.Backend, a uint64, size uint32) {
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
	h, err := e.be.HookCode(start, end, e.guardCode(func(b emu.Backend, a uint64, size uint32) {
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
	h, err := e.be.HookMemRead(start, end, e.guardMemRead(func(b emu.Backend, addr uint64, size int) {
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
	h, err := e.be.HookMemWrite(start, end, e.guardMemWrite(func(b emu.Backend, addr uint64, size int, value int64) {
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
	h, err := e.be.HookCode(start, end, e.guardCode(func(b emu.Backend, addr uint64, size uint32) {
		fmt.Printf("[trace] 0x%x  %s\n", addr, e.NearestSym(addr))
	}))
	if err != nil {
		return nil, err
	}
	return func() { _ = h.Remove() }, nil
}
