package emulator

// syscall override: the public seam for consumers whose guests need
// syscall semantics the built-in table lacks (or that must be intercepted).
// Portable across architectures — resolve the syscall by NAME, the number
// is the platform's business.

import (
	"fmt"

	"github.com/isesword/golem/internal/kernel"
)

// Syscall types, re-exported as aliases so consumer callbacks can name
// every parameter without importing internal packages. Identical types to
// kernel's — zero-cost, zero-adapter.
type (
	// SyscallContext is the kernel execution context a syscall handler sees.
	SyscallContext = kernel.Context
	// SyscallFrame carries the syscall number and its decoded arguments.
	SyscallFrame = kernel.SyscallFrame
	// SyscallResult is the handler's semantic result (transport encodes it).
	SyscallResult = kernel.Result
)

// SyscallNumber resolves a syscall NAME to the current platform's number —
// the portable way to address a syscall (uname = 160 on ARM64, 122 on
// ARM32). Names exist for bound and deliberately-unbound entries alike, so
// this also resolves the "not implemented yet" numbers an override can
// fill in. ok=false: the current platform's table does not know the name.
func (e *Emulator) SyscallNumber(name string) (uint64, bool) {
	return e.kctx.Table.Number(name)
}

// SetSyscallHandler installs or REPLACES the handler for syscall number nr
// (Portable-facing configuration; the handler itself is Advanced-grade
// kernel semantics). Per-emulator by construction — tables are per-engine
// instances, overrides never leak across engines.
//
// nr is platform-specific by nature: resolve it portably with
// SyscallNumber(name) first. Unnamed syscalls must use raw numbers from
// the target ABI (Advanced knowledge).
func (e *Emulator) SetSyscallHandler(nr uint64, fn func(ctx *SyscallContext, f *SyscallFrame) SyscallResult) error {
	if fn == nil {
		return fmt.Errorf("SetSyscallHandler(%d): nil handler", nr)
	}
	e.kctx.Table.Set(nr, fn)
	return nil
}
