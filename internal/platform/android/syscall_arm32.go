package android

import (
	"github.com/isesword/golem/internal/arch/arm32"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// LinuxARM32Transport is the Linux/ARM EABI (32-bit, armv7) syscall
// transport ABI: the syscall number arrives in r7, up to 6 arguments in
// r0..r5, and the result goes back in r0 — Value on success, the two's
// complement of the errno on failure (the kernel-side "-errno" convention,
// same as AArch64). This is the ARM32 counterpart of LinuxARM64Transport.
//
// EABI 64-bit argument pairing (IMPORTANT, by design NOT handled here): the
// ARM EABI requires 64-bit syscall arguments to be passed in an EVEN/ODD
// register pair (r0:r1 or r2:r3), so a 64-bit argument after an odd number
// of 32-bit arguments leaves a HOLE — e.g. readahead(225)
// (fd, offset64, count) arrives as r0=fd, r1=UNUSED, r2:r3=offset, r4=count.
// The transport deliberately stays ignorant of this: Decode copies r0..r5
// verbatim into Args[0..5]. Pair alignment is knowledge of the handler/table
// binding layer (each 64-bit-taking syscall's binding must name its actual
// argument slots); pinning the raw layout is exactly what lets that layer be
// tested against real kernel behavior. TestLinuxARM32TransportReadaheadLayout
// pins the readahead hole.
type LinuxARM32Transport struct{}

var _ kernel.SyscallTransport = LinuxARM32Transport{}

// syscallARM32ArgRegs are the argument registers in argument order (r0..r5).
var syscallARM32ArgRegs = [6]emu.Reg{arm32.R0, arm32.R1, arm32.R2, arm32.R3, arm32.R4, arm32.R5}

// Decode reads the syscall number (r7) and the six argument registers
// (r0..r5) into a SyscallFrame, verbatim (see the pairing note on the type).
// NArg is always 6: the ARM EABI syscall ABI has no variable-arity path.
func (LinuxARM32Transport) Decode(b emu.Backend) (kernel.SyscallFrame, error) {
	var f kernel.SyscallFrame
	num, err := b.RegRead(arm32.R7)
	if err != nil {
		return f, err
	}
	f.Num = num
	for i, r := range syscallARM32ArgRegs {
		v, err := b.RegRead(r)
		if err != nil {
			return f, err
		}
		f.Args[i] = v
	}
	f.NArg = uint8(len(syscallARM32ArgRegs))
	return f, nil
}

// EncodeResult writes the result register: Errno != 0 -> r0 = -Errno (two's
// complement), otherwise r0 = Value. Value2 is IGNORED on Linux — the ARM32
// syscall ABI has a single result register (64-bit results like lseek's come
// back through r0 on EABI kernels' asm wrappers; bionic's syscall stubs
// handle that, golem's handlers return Value only).
func (LinuxARM32Transport) EncodeResult(b emu.Backend, r kernel.Result) error {
	v := r.Value
	if r.Errno != 0 {
		v = uint64(-int64(r.Errno))
	}
	return b.RegWrite(arm32.R0, v)
}
