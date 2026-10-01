package memory

// Layout pins the fixed regions of the guest address space: where modules,
// the brk heap, the anonymous mmap arena, stub trampolines, the stack and
// the TLS block live. It is pure data with no policy attached — who DECIDES
// these numbers (a platform LayoutPolicy composing arch address-space
// capabilities and user overrides) lives in platform/* ; the memory
// package only carries the resulting geometry.
//
// Every region is a half-open range [Addr, Addr+Size). ModuleRegion is the
// bump-allocated window the loader draws module bases from; HeapRegion and
// MmapRegion are sub-arenas whose internals are managed elsewhere (the
// kernel brk cursor, the Space mmap allocator) — the AddressSpace only owns
// their boundaries so bump allocation can never drift into them. Only Addr
// and Size are meaningful in Layout regions; mapping protection is decided
// by the composition root when it backs the ranges on the CPU backend.
type Layout struct {
	ModuleRegion Region // module load window; modules bump upward from .Addr
	HeapRegion   Region // brk heap (program break grows inside this window)
	MmapRegion   Region // anonymous mmap arena (Space's monotonic allocator)
	StubBase     uint64 // trampoline region (unresolved imports, host fns, JNI slots)
	StubSize     uint64
	StackBase    uint64
	StackSize    uint64
	TLSBase      uint64 // thread-local storage block
	TLSSize      uint64
}
