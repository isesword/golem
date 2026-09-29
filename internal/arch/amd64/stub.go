package amd64

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
)

// stubCode is `int3 ; ret` (x86-64):
//
//	0xCC        int3   — traps to the host (unicorn: UC_HOOK_INTR, intno 3,
//	                     RIP already advanced to stub+1 when the hook fires)
//	0xC3        ret    — safety net; dead in practice: the trap handler hands
//	                     control back through CallABI.ReturnFromCall (which
//	                     pops the guest return address itself), so this byte
//	                     never executes
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
