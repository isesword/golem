// Package emu defines the CPU backend abstraction — the single component that
// cannot be written in pure Go. It mirrors the surface unidbg's
// com.github.unidbg.arm.backend.Backend exposes and that unidbg uses:
// register access, guest memory map/read/write/protect (including zero-copy
// mapping of caller-provided host memory via MemMapPtr), code hooks, and
// run/stop.
//
// Like unidbg, the engine is selectable. Concrete backends are compiled in via
// build tags and register themselves (see registry.go):
//
//	-tags unicorn   -> Unicorn2 loaded at runtime via purego (unicorn_purego.go);
//	                   no cgo, no C compiler, binds the stock libunicorn
//
// Build with both to choose at run time (arg / $GOLEM_ENGINE). Everything else
// in this module is written against this interface so it compiles and is
// testable without a C toolchain (a pure-Go build registers no backend).
//
// (DESIGN.md invariants 14/15):
//
//   - Backend is the CORE interface — registers, memory, run/stop, trap
//     install, close. It is a freeze candidate: it must NOT grow methods for
//     new requirements. Optional engine capabilities live in capability.go as
//     small interfaces (InstructionHooker, ContextManager, ...); consumers
//     probe with a type assertion and degrade when it fails, instead of
//     branching on an engine name or bloating Backend.
//   - Guest addresses use the dedicated GuestAddr type, so guest VAs cannot
//     be silently mixed with host pointers, file offsets, or symbol values.
//     Sizes stay plain uint64; internal arithmetic converts explicitly.
package emu

import (
	"errors"
	"unsafe"
)

// ErrNoBackend is returned when no CPU backend is compiled in (a pure-Go build
// without the `unicorn` build tag).
var ErrNoBackend = errors.New("emu: no CPU backend compiled in (build with -tags unicorn)")

// ErrUnsupported is the sentinel a backend returns (wrapped) for an operation
// the engine cannot perform — e.g. per-instruction code hooks on an engine
// without them. Since the PRIMARY absence signal for an optional
// capability is a failed type assertion on the capability interface
// (capability.go); ErrUnsupported remains for a capability that exists but
// cannot perform a specific operation, and callers rewrite assertion failures
// into errors wrapping ErrUnsupported so errors.Is keeps a single path.
var ErrUnsupported = errors.New("emu: operation unsupported by this engine")

// Prot bits for mem_map / mem_protect (match Unicorn UC_PROT_*).
const (
	ProtNone  = 0
	ProtRead  = 1
	ProtWrite = 2
	ProtExec  = 4
	ProtAll   = ProtRead | ProtWrite | ProtExec
)

// Reg is an abstract register id. Each backend translates it to its own
// numbering (e.g. unicorn.ARM64_REG_*). Keeping it abstract avoids baking
// engine-specific enum values into the rest of the code.
//
// The concrete ids live in per-architecture packages — internal/arch/arm64
// for AArch64 (arm64.X0, arm64.SP, ...); emu itself defines none. That
// package imports emu (for Reg), never the reverse.
type Reg int

// GuestAddr is a guest virtual address (DESIGN.md invariant 15). It is a
// distinct type so guest VAs cannot be silently interchanged with host
// pointers, file offsets, or symbol values; arithmetic on it is explicit.
type GuestAddr uint64

// CodeHookFunc fires for each hooked instruction/range. addr is the guest PC,
// size the instruction size. Mirrors the host app's CodeHook.hook(...).
type CodeHookFunc func(b Backend, addr GuestAddr, size uint32)

// InterruptHookFunc fires on SVC/exception. swi is the syscall/exception id.
// The syscall handler registers one of these to service guest syscalls.
type InterruptHookFunc func(b Backend, intno uint32)

// MemInvalidHookFunc fires on an invalid (unmapped/protected) guest memory
// access; returning true tells the engine to retry the access (the hook made
// the memory accessible).
type MemInvalidHookFunc func(b Backend, typ int, addr GuestAddr, size int, value int64) bool

// MemReadHookFunc fires on a valid guest memory read with (addr, size).
type MemReadHookFunc func(b Backend, addr GuestAddr, size int)

// MemWriteHookFunc fires on a valid guest memory write with (addr, size, value).
type MemWriteHookFunc func(b Backend, addr GuestAddr, size int, value int64)

// Backend is the CPU + memory engine's CORE interface: registers, guest
// memory, execution control, trap install, close. FREEZE CANDIDATE (DESIGN.md
// invariant 14): it must not grow methods for new requirements — optional
// engine capabilities (code/memory hooks, context save/restore, cache flush)
// are the small interfaces in capability.go, probed by consumers with type
// assertions. The Unicorn2 purego wrapper implements the core plus every
// capability defined today.
type Backend interface {
	// Registers. Per-register access only — the WHOLE-FILE dump is the
	// optional RegFileReader capability (it used to be a core method
	// with an AArch64-baked [34]uint64 shape, which is exactly the kind of
	// arch shape a frozen core must not carry).
	RegRead(reg Reg) (uint64, error)
	RegWrite(reg Reg, val uint64) error

	// Memory
	MemMap(addr GuestAddr, size uint64, prot int) error
	MemUnmap(addr GuestAddr, size uint64) error
	MemProtect(addr GuestAddr, size uint64, prot int) error
	MemWrite(addr GuestAddr, data []byte) error
	MemRead(addr GuestAddr, size uint64) ([]byte, error)
	// MemMapPtr maps the CALLER-PROVIDED host memory [host, host+size) as guest
	// memory at addr (uc_mem_map_ptr). No copy: guest reads/writes land directly
	// in the host buffer, so several engines mapping the same buffer share it.
	// host must be page-aligned; size page-aligned. The caller keeps host alive.
	MemMapPtr(addr GuestAddr, size uint64, prot int, host unsafe.Pointer) error

	// InstallTrap registers h for guest traps classified as kind (host calls,
	// syscalls, ...). The unicorn backend implements this as an adapter over
	// its single interrupt hook: every SVC invokes every registered handler,
	// each receiving the kind it was registered under.
	//
	// Runtime kind discrimination is deliberately NOT done via svc immediates
	// (design decision: immediates are not a cross-arch contract — AMD64
	// has no equivalent encoding). Instead, trampoline identity is decided by
	// address: traps whose PC lies in the stub region resolve through
	// interpose.StubManager metadata; anything else is a guest syscall.
	// Callers keep HookInterrupt for the raw path; InstallTrap is the
	// kind-annotated path.
	InstallTrap(kind TrapKind, h TrapHandler) (HookHandle, error)

	// Execution
	Start(begin, until GuestAddr) error
	// StartCount runs at most `count` instructions (0 = unlimited), then returns
	// — used by the cooperative scheduler to preempt a thread slice. Backends
	// without an instruction limit may treat it as unlimited.
	StartCount(begin, until GuestAddr, count uint64) error
	Stop() error

	Close() error
}

// HookHandle lets a hook be removed.
type HookHandle interface{ Remove() error }

// CPUContext is an opaque, backend-specific snapshot of the full guest CPU
// register file (see ContextManager.SaveContext). Free releases it.
type CPUContext interface{ Free() error }
