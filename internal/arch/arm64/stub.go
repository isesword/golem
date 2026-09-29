package arm64

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
)

// stubCode is `svc #0 ; ret` (AArch64, little-endian) — the exact bytes the
// emulator hardcoded before P1.
//
// Both stub kinds emit the SAME bytes on purpose: the emulator classifies a
// trap by its source address (inside the stub region) plus its stub metadata
// table, never by the svc immediate. An immediate-based kind encoding would
// become a cross-architecture protocol that e.g. AMD64 (int3 trampolines)
// cannot honor (DESIGN.md §3.2, invariant 8).
var stubCode = []byte{0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6}

// EmitStub implements arch.StubEncoder on the ABI instance. The returned
// slice is a fresh copy — callers may write it into guest memory and forget.
func (abi) EmitStub(kind arch.StubKind) ([]byte, error) {
	switch kind {
	case arch.StubHostCall, arch.StubUnresolved:
		return append([]byte(nil), stubCode...), nil
	}
	return nil, fmt.Errorf("arm64: unknown stub kind %d", kind)
}
