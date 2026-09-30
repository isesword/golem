// Package android provides golem's Android platform personality: the Linux /
// AArch64 syscall transport (x8 number, x0..x5 args, -errno result encoding),
// the Android/AArch64 syscall table, and the asm-generic LP64 guest struct
// codecs. The interfaces it implements (kernel.SyscallTransport,
// kernel.StructCodecs) are consumer-owned by the kernel package, keeping the
// dependency direction platform/android → kernel → emu (DESIGN.md §3.4/§3.5).
package android

import (
	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// LinuxARM64Transport is the Linux/AArch64 syscall transport ABI
// (asm-generic): the syscall number arrives in x8, up to 6 arguments in
// x0..x5, and the result goes back in x0 — Value on success, the two's
// complement of the errno on failure (the kernel-side "-errno" convention).
type LinuxARM64Transport struct{}

var _ kernel.SyscallTransport = LinuxARM64Transport{}

// syscallArgRegs are the argument registers in argument order (x0..x5).
var syscallArgRegs = [6]emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5}

// Decode reads the syscall number (x8) and the six argument registers
// (x0..x5) into a SyscallFrame. NArg is always 6: the AArch64 syscall ABI has
// no variable-arity path (unlike Darwin's generic syscall shim).
func (LinuxARM64Transport) Decode(b emu.Backend) (kernel.SyscallFrame, error) {
	var f kernel.SyscallFrame
	num, err := b.RegRead(arm64.X8)
	if err != nil {
		return f, err
	}
	f.Num = num
	for i, r := range syscallArgRegs {
		v, err := b.RegRead(r)
		if err != nil {
			return f, err
		}
		f.Args[i] = v
	}
	f.NArg = uint8(len(syscallArgRegs))
	return f, nil
}

// EncodeResult writes the result register: Errno != 0 -> x0 = -Errno (two's
// complement), otherwise x0 = Value. Value2 is IGNORED on Linux — the ABI has
// a single result register; it exists for Darwin's dual-return-value wrapper
// (x0/x1 + carry flag), which is exactly what Result.Value2 pins down
// (DESIGN.md §3.5). Do not "fix" this by writing x1.
func (LinuxARM64Transport) EncodeResult(b emu.Backend, r kernel.Result) error {
	v := r.Value
	if r.Errno != 0 {
		v = uint64(-int64(r.Errno))
	}
	return b.RegWrite(arm64.X0, v)
}
