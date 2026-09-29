package amd64

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// stubCode is `int3 ; ret` (x86-64):
//
//	0xCC        int3   — traps to the host (unicorn: UC_HOOK_INTR, intno 3,
//	                     RIP already advanced to stub+1 when the hook fires)
//	0xC3        ret    — the return path: the trap handler leaves RIP here,
//	                     and ret pops the guest return address the caller's
//	                     `call` pushed (the emulator's onStubTrap relies on
//	                     this; a component-level handler may instead end the
//	                     call itself via CallABI.ReturnFromCall, making this
//	                     byte dead — either way the frame unwinds exactly once)
//
// Both stub kinds emit the SAME bytes on purpose: the emulator classifies a
// trap by its source address (inside the stub region) plus its stub metadata
// table, never by anything encoded in the stub (DESIGN.md §3.2, invariant 8).
//
// The x86-64 `syscall` instruction is FORBIDDEN inside host stubs: it routes
// through the engine's syscall-instruction channel (unicorn: UC_HOOK_INSN /
// UC_X86_INS_SYSCALL), which is the REAL guest-syscall path to the kernel —
// the two channels are independent by design and must not be mixed.
var stubCode = []byte{0xCC, 0xC3}

// stubEncoder is the AMD64 trampoline StubEncoder — an independent
// capability, deliberately not merged into Arch or CallABI (DESIGN.md §3.2).
type stubEncoder struct{}

// EmitStub implements arch.StubEncoder. The returned slice is a fresh copy —
// callers may write it into guest memory and forget.
func (stubEncoder) EmitStub(kind arch.StubKind) ([]byte, error) {
	switch kind {
	case arch.StubHostCall, arch.StubUnresolved:
		return append([]byte(nil), stubCode...), nil
	}
	return nil, fmt.Errorf("amd64: unknown stub kind %d", kind)
}

// TrapStubAddr implements arch.StubEncoder: int3 is 1 byte and the engine
// reports RIP just past it (stub+1 — pinned by TestUnicornAMD64HostStubTrap),
// so the trapping instruction sits at pc-1.
func (stubEncoder) TrapStubAddr(pc emu.GuestAddr) emu.GuestAddr { return pc - 1 }
