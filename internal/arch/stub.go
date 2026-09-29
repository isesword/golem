package arch

import "github.com/isesword/golem/internal/emu"

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

	// TrapStubAddr maps the engine-reported PC at a trap back to the address
	// of the trapping instruction — for a stub trap, the stub's entry. The
	// offset is the trap instruction's length under the engine's
	// reports-PC-past-the-instruction semantics (unicorn: UC_HOOK_INTR fires
	// with PC just past the trap instruction): svc #0 is 4 bytes on ARM64,
	// int3 is 1 byte on AMD64. Meaningful only for trap PCs; the caller uses
	// the result for stub-table lookup, never as an execution address.
	TrapStubAddr(pc emu.GuestAddr) emu.GuestAddr
}
