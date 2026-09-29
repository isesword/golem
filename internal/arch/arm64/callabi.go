package arm64

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// aapcs64 is the AAPCS64 user-space function calling convention
// (arch.CallABI) for AArch64: integer arguments in X0..X7, the result in X0,
// the return address in X30 (LR). The zero value is valid and stateless.
type aapcs64 struct{}

// numArgRegs is the number of integer argument registers (X0..X7); further
// arguments spill to the stack (not implemented yet — see ReadArgs).
const numArgRegs = 8

// Arg implements AAPCS64: integer arguments 0..7 arrive in X0..X7.
func (aapcs64) Arg(i int) emu.Reg {
	if i < 0 || i >= numArgRegs {
		panic(fmt.Sprintf("arm64: Arg(%d) out of range — AAPCS64 passes integer args 0..7 in X0..X7", i))
	}
	return X0 + emu.Reg(i)
}

func (aapcs64) Ret() emu.Reg { return X0 }

// LR is X30 — AArch64 keeps the return address in a register.
func (aapcs64) LR() emu.Reg { return LR }

// ReadArgs reads integer arguments 0..n-1 from X0..X(n-1). Arguments beyond
// the eight registers spill to the stack per AAPCS64; that path is not
// implemented yet (no current consumer) and reports an error.
func (c aapcs64) ReadArgs(b emu.Backend, n int) ([]uint64, error) {
	if n < 0 {
		return nil, fmt.Errorf("arm64: ReadArgs(%d): negative count", n)
	}
	if n > numArgRegs {
		// Stack-spill argument support (args 8+ at [SP, #(i-8)*8]) is left
		// for when a caller actually needs it — no current call path passes
		// >8 integer args through this interface.
		return nil, fmt.Errorf("arm64: ReadArgs(%d): stack-spill arguments not implemented (register limit %d)", n, numArgRegs)
	}
	args := make([]uint64, n)
	for i := range args {
		v, err := b.RegRead(c.Arg(i))
		if err != nil {
			return nil, fmt.Errorf("arm64: ReadArgs: arg %d: %w", i, err)
		}
		args[i] = v
	}
	return args, nil
}

// WriteResult writes the call result: X0 ← Value. Value2 has no consumer on
// AAPCS64 today and is ignored.
func (c aapcs64) WriteResult(b emu.Backend, r arch.CallResult) error {
	return b.RegWrite(c.Ret(), r.Value)
}

// ReturnFromCall performs the AAPCS64 return: PC ← X30 (LR). The stack is
// untouched — the callee has already restored it per the convention.
func (c aapcs64) ReturnFromCall(b emu.Backend) error {
	lr, err := b.RegRead(c.LR())
	if err != nil {
		return fmt.Errorf("arm64: ReturnFromCall: read LR: %w", err)
	}
	if err := b.RegWrite(PC, lr); err != nil {
		return fmt.Errorf("arm64: ReturnFromCall: write PC: %w", err)
	}
	return nil
}
