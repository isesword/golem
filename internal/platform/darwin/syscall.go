package darwin

import (
	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// DarwinARM64Transport is the XNU/ARM64 syscall transport ABI: the syscall
// number arrives in x16 (NOT Linux's x8), up to 6 arguments in x0..x5, and
// the result encoding follows the BSD wrapper convention —
//
//	unix syscall (x16 > 0):  error   -> carry flag SET,   x0 = errno
//	                         success -> carry flag CLEAR, x0 = Value, x1 = Value2
//	Mach trap   (x16 < 0):   x0 = kern_return_t directly, carry untouched
//
// (Darwin's dual x0/x1 return is why kernel.Result has Value2; DESIGN.md
// §3.5.) Negative numbers are Mach traps; stored in the frame's uint64 Num
// they become huge values that simply miss every table entry, which is the
// correct P5b behavior — no Mach trap is implemented.
//
// The transport is STATEFUL (pointer receiver): EncodeResult must know the
// syscall class (unix vs Mach) to pick the encoding, and kernel's
// DispatchFrame deliberately does not hand the frame back to the transport.
// Decode records the class; EncodeResult consumes it. Guest execution is
// single-threaded (cooperative fibers), and every EncodeResult follows a
// Decode on the same instance — both in kernel.Context.Dispatch and in the
// emulator's onSyscallTrap/scheduler path.
type DarwinARM64Transport struct {
	mach bool // the last decoded frame was a Mach trap (x16 negative)
}

var _ kernel.SyscallTransport = (*DarwinARM64Transport)(nil)

// NewARM64Transport returns the Darwin/ARM64 transport for the kernel.Context
// injection.
func NewARM64Transport() *DarwinARM64Transport { return &DarwinARM64Transport{} }

// syscallArgRegs are the argument registers in argument order (x0..x5).
var syscallArgRegs = [6]emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5}

// nzcvCarry is the C flag's bit position in the NZCV register (bit 29).
const nzcvCarry = 0x20000000

// Decode reads the syscall number (x16) and the six argument registers
// (x0..x5) into a SyscallFrame. NArg is always 6: P5b does not decode the
// 7+-argument stack spill path of Darwin's generic syscall shim (none of the
// bound syscalls takes more than 6 arguments).
func (t *DarwinARM64Transport) Decode(b emu.Backend) (kernel.SyscallFrame, error) {
	var f kernel.SyscallFrame
	num, err := b.RegRead(arm64.X16)
	if err != nil {
		return f, err
	}
	f.Num = num
	t.mach = int64(num) < 0
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

// EncodeResult writes the BSD wrapper result. See the type comment for the
// two encodings; the unix/Mach choice comes from the last Decode.
func (t *DarwinARM64Transport) EncodeResult(b emu.Backend, r kernel.Result) error {
	if t.mach {
		// Mach trap: kern_return_t in x0, no carry convention. (P5b binds no
		// Mach trap, so in practice this only ever encodes the ENOSYS miss of
		// a negative number — still the honest encoding for it.)
		v := r.Value
		if r.Errno != 0 {
			v = uint64(r.Errno)
		}
		return b.RegWrite(arm64.X0, v)
	}
	nzcv, err := b.RegRead(arm64.NZCV)
	if err != nil {
		return err
	}
	if r.Errno != 0 {
		if err := b.RegWrite(arm64.X0, darwinErrno(r.Errno)); err != nil {
			return err
		}
		return b.RegWrite(arm64.NZCV, nzcv|nzcvCarry)
	}
	if err := b.RegWrite(arm64.X0, r.Value); err != nil {
		return err
	}
	if err := b.RegWrite(arm64.X1, r.Value2); err != nil {
		return err
	}
	return b.RegWrite(arm64.NZCV, nzcv&^nzcvCarry)
}

// darwinErrno translates the kernel's semantic Errno (Linux asm-generic
// numbering, by definition of the kernel package) to XNU's numbering. Every
// errno the kernel's handler set produces EXCEPT ENOSYS has the same numeric
// value on both kernels (EPERM=1, ENOENT=2, EIO=5, EBADF=9, EINVAL=22,
// ERANGE=34 all coincide), so only ENOSYS (38 -> 78) is remapped. Any FUTURE
// errno added to the kernel set must be re-checked against XNU here — the BSD
// and Linux low-number ranges happen to agree, but that is a coincidence of
// history, not a contract.
func darwinErrno(e kernel.Errno) uint64 {
	if e == kernel.ENOSYS {
		return 78 // Darwin ENOSYS (Linux asm-generic 38)
	}
	return uint64(e)
}
