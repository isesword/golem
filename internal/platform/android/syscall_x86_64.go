package android

import (
	"github.com/isesword/golem/internal/arch/amd64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// LinuxAMD64Transport is the Linux/x86-64 syscall transport ABI: the syscall
// number arrives in RAX, up to 6 arguments in RDI/RSI/RDX/R10/R8/R9, and the
// result goes back in RAX — Value on success, the two's complement of the
// errno on failure (the kernel-side "-errno" convention, same as AArch64).
//
// The 4th argument is R10, NOT RCX — the `syscall` instruction itself
// clobbers RCX (return RIP) and R11 (RFLAGS), so the kernel ABI moves the
// 4th argument to R10. This is the deliberate split from the SysV FUNCTION
// calling convention (arch/amd64.sysV64: arg 3 = RCX); the two ABIs are
// separate implementations and the difference is pinned by tests on both
// sides (TestArgRegsVsSyscallABI there, TestLinuxAMD64TransportDecode here).
type LinuxAMD64Transport struct{}

var _ kernel.SyscallTransport = LinuxAMD64Transport{}

// syscallAMD64ArgRegs are the syscall argument registers in argument order
// (RDI/RSI/RDX/R10/R8/R9).
var syscallAMD64ArgRegs = [6]emu.Reg{amd64.RDI, amd64.RSI, amd64.RDX, amd64.R10, amd64.R8, amd64.R9}

// Decode reads the syscall number (RAX) and the six argument registers into
// a SyscallFrame. NArg is always 6: the x86-64 syscall ABI has no
// variable-arity path.
func (LinuxAMD64Transport) Decode(b emu.Backend) (kernel.SyscallFrame, error) {
	var f kernel.SyscallFrame
	num, err := b.RegRead(amd64.RAX)
	if err != nil {
		return f, err
	}
	f.Num = num
	for i, r := range syscallAMD64ArgRegs {
		v, err := b.RegRead(r)
		if err != nil {
			return f, err
		}
		f.Args[i] = v
	}
	f.NArg = uint8(len(syscallAMD64ArgRegs))
	return f, nil
}

// EncodeResult writes the result register: Errno != 0 -> RAX = -Errno
// (two's complement), otherwise RAX = Value. Value2 is IGNORED — the x86-64
// Linux syscall ABI has a single result register (RDX is not a result
// register here, unlike the SysV function convention's RAX:RDX pair).
func (LinuxAMD64Transport) EncodeResult(b emu.Backend, r kernel.Result) error {
	v := r.Value
	if r.Errno != 0 {
		v = uint64(-int64(r.Errno))
	}
	return b.RegWrite(amd64.RAX, v)
}
