package arm32

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// stubCode is `svc #0 ; bx lr` in ARM state (little-endian) — the armv7
// analogue of the AArch64 stub.
//
// ARM-state stubs are a deliberate choice over Thumb: every guest call path
// reaches a stub through an interworking branch (blx/bx of a loaded
// pointer), which switches ISA state from the target address's bit0 — an
// EVEN stub address works from ARM and Thumb callers alike, with no
// bit0 convention leaking into the stub manager or the resolver chain.
// (Thumb stubs would be 2 bytes shorter but every stub address handed out
// would have to carry bit0=1, and any non-interworking call pattern —
// `mov pc, reg` — would decode the stub as ARM and go off the rails.)
//
// Both stub kinds emit the SAME bytes on purpose: the emulator classifies a
// trap by its source address (inside the stub region) plus its stub
// metadata table, never by the svc immediate (DESIGN.md §3.2, invariant 8).
var stubCode = []byte{
	0x00, 0x00, 0x00, 0xef, // svc #0
	0x1e, 0xff, 0x2f, 0xe1, // bx lr
}

// stubEncoder is the ARM32 trampoline StubEncoder — an independent
// capability, deliberately not merged into Arch or CallABI (DESIGN.md §3.2).
type stubEncoder struct{}

// EmitStub implements arch.StubEncoder. The returned slice is a fresh copy —
// callers may write it into guest memory and forget.
func (stubEncoder) EmitStub(kind arch.StubKind) ([]byte, error) {
	switch kind {
	case arch.StubHostCall, arch.StubUnresolved:
		return append([]byte(nil), stubCode...), nil
	}
	return nil, fmt.Errorf("arm32: unknown stub kind %d", kind)
}

// TrapStubAddr implements arch.StubEncoder. MEASURED on the live unicorn
// ARM32 engine (TestUnicornARM32SvcTrapPC): an ARM-state svc traps with PC
// at svc+4, so the trapping instruction sits at pc-4. (A Thumb svc traps at
// svc+2 — irrelevant here: golem's stubs are ARM state by design, see
// stubCode.)
func (stubEncoder) TrapStubAddr(pc emu.GuestAddr) emu.GuestAddr { return pc - 4 }
