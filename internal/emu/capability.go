package emu

// Capability interfaces (DESIGN.md invariant 14): OPTIONAL engine abilities,
// split off the Backend core interface so the core can freeze. A consumer
// probes with a type assertion:
//
//	if h, ok := be.(emu.InstructionHooker); ok {
//		... // engine supports per-instruction code hooks
//	} // else: degrade — the assertion failure carries the same meaning as a
//	// backend method returning an error wrapping emu.ErrUnsupported
//
// An engine implements exactly the capabilities it supports; the unicorn
// backend implements all of the ones below. New engine abilities get a NEW
// small interface here — Backend itself does not grow methods.
//
// ErrUnsupported stays in use inside capabilities: an engine that HAS the
// interface but cannot perform one specific operation returns an error
// wrapping it.

// InstructionHooker is the per-instruction code-hook capability (the basis of
// inline hooks, breakpoints, and the instruction tracer). [start, end) is the
// guest address range to watch; unicorn's begin>end convention selects the
// whole address space.
type InstructionHooker interface {
	HookCode(start, end GuestAddr, fn CodeHookFunc) (HookHandle, error)
}

// InterruptHooker is the raw SVC/exception hook capability.
//
// Transitional: InstallTrap (core Backend) is the intended path — callers
// migrate to it as trap kinds gain runtime discrimination. Until then the
// syscall dispatcher keeps registering a raw interrupt hook through this
// capability.
type InterruptHooker interface {
	HookInterrupt(fn InterruptHookFunc) (HookHandle, error)
}

// InvalidMemHooker is the invalid-access hook capability: the hook fires on
// unmapped/protected guest memory accesses and may recover the access.
type InvalidMemHooker interface {
	HookMemInvalid(fn MemInvalidHookFunc) (HookHandle, error)
}

// MemReadHooker fires on every valid memory READ in [start,end) with (addr,size).
type MemReadHooker interface {
	HookMemRead(start, end GuestAddr, fn MemReadHookFunc) (HookHandle, error)
}

// MemWriteHooker fires on every valid memory WRITE in [start,end) with
// (addr,size,value).
type MemWriteHooker interface {
	HookMemWrite(start, end GuestAddr, fn MemWriteHookFunc) (HookHandle, error)
}

// ContextManager is the full-CPU-state snapshot capability. SaveContext
// snapshots the entire guest CPU register file (all GP + SIMD registers, SP,
// PC, PSTATE, TPIDR) into an opaque handle; RestoreContext reloads it. Used to
// suspend and resume guest threads (fibers). A backend without it simply does
// not implement the interface and the scheduler degrades to a single-slice
// (non-resumable) run.
type ContextManager interface {
	SaveContext() (CPUContext, error)
	RestoreContext(CPUContext) error
}

// CacheInvalidator invalidates the engine's translated/JIT'd code cache.
// Called after writing new code into an executable region (self-modifying
// code) and after installing an interposition entry hook (P2.5d): unicorn
// instruments hook callouts at TB translation time, so a block translated
// before the hook existed would never fire it unless the cache is flushed.
type CacheInvalidator interface {
	FlushCache() error
}

// CodeCacheController is the execution-hook companion contract (P3.5,
// DESIGN.md §3.1): after installing a NEW execution hook over [start, end),
// already-translated blocks may not contain the hook callout (unicorn
// instruments hooks at TB translation time), so the interpose/stub layer
// must invalidate the affected range through this capability instead of
// knowing the concrete backend. Implementations without a ranged invalidate
// may flush their whole cache internally (unicorn does — see its doc).
type CodeCacheController interface {
	FlushCodeCache(start, end GuestAddr) error
}

// RegFileReader is the whole-register-file dump capability (P7.5c): one call
// returns the guest's general-purpose register file, cheap enough for
// per-instruction consumers (the full tracer) — individual RegReads would
// pay the purego boundary per register. The FILE SHAPE is arch business,
// never a core contract: entries come in the engine's native file order and
// only make sense together with the arch package's register model (AArch64:
// [0..30]=x0..x30, [31]=sp, [32]=pc, [33]=nzcv). Engines without a defined
// file shape answer an error wrapping ErrUnsupported — loudly, never by
// stuffing foreign registers into another arch's slots.
type RegFileReader interface {
	Backend
	ReadGPRegs() ([]uint64, error)
}

// RegWrite is one register write in a batch (see RegBatchWriter).
type RegWrite struct {
	Reg   Reg
	Value uint64
}

// RegBatchWriter is the OPTIONAL batch register-write capability (P9.5a):
// one host↔engine crossing for a whole set of writes instead of one per
// register. Purely a performance seam — the fallback (a RegWrite loop)
// is bit-for-bit equivalent, so consumers probe it and degrade freely;
// a backend without it is merely slower, never wrong.
type RegBatchWriter interface {
	Backend
	WriteRegs(writes []RegWrite) error
}
