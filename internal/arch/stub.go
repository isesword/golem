package arch

// StubKind classifies a guest trampoline stub.
type StubKind uint8

const (
	// StubHostCall is a guest→host function-call trampoline: a
	// host-implemented function entry or an interop (JNI/JavaVM) table slot.
	StubHostCall StubKind = iota
	// StubUnresolved is the placeholder for an import no loaded module
	// exports (traps, logs, returns an optimistic 0).
	StubUnresolved
)

// StubEncoder emits the guest machine code of a trampoline stub. It is a
// capability separate from Arch and CallABI on purpose: how a stub is ENCODED
// (a CPU instruction property), how it is CAPTURED (emu.TrapKind / backend
// hook, DESIGN.md §3.1), and how a syscall reaches the kernel (platform) are
// three different concerns and must not be merged.
//
// Trap identity is deliberately NOT carried in the stub bytes (e.g. an svc
// immediate encoding the kind): that would turn an encoding detail into a
// cross-architecture protocol that e.g. AMD64 (int3 trampolines) cannot
// honor. Classification is by trap-source address (inside the stub region)
// plus the emulator's stub metadata table.
type StubEncoder interface {
	EmitStub(kind StubKind) ([]byte, error)
}
