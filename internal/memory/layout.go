package memory

// Layout pins the fixed regions of the guest address space: where modules,
// stub trampolines, the stack and the TLS block live. It is pure data with
// no policy attached — who DECIDES these numbers (a platform LayoutPolicy
// composing arch address-space capabilities and user overrides) arrives in
// P4/P5; P1 only makes the previously hardcoded emulator constants explicit.
type Layout struct {
	ModuleBase uint64 // first module load address; modules bump upward from here
	ModuleSize uint64 // arena bound, enforced by AddressSpace.Alloc (P2.5c)
	StubBase   uint64 // trampoline region (unresolved imports, host fns, JNI slots)
	StubSize   uint64
	StackBase  uint64
	StackSize  uint64
	TLSBase    uint64 // thread-local storage block
	TLSSize    uint64
}
