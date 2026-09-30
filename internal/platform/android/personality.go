package android

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/kernel"
)

// SyscallPersonality bundles one guest architecture's syscall ABI pieces for
// the kernel.Context injection (P5a.5): the register transport, the number→
// handler dispatch table, the guest struct codecs, and the syscall numbers
// the emulator's cooperative scheduler intercepts (futex / nanosleep). The
// arch-keyed selection lives HERE — per-arch knowledge is the platform
// package's job; the emulator only ever assembles the returned personality.
type SyscallPersonality struct {
	Transport kernel.SyscallTransport
	Table     *kernel.Table
	Codecs    kernel.StructCodecs

	// Scheduler interception numbers: the emulator's cooperative scheduler
	// services these itself (fiber wake/park on futex, slice yield on sleep)
	// before the kernel table ever sees them. They differ per architecture
	// (ARM64 is asm-generic; x86-64 predates asm-generic).
	Futex          uint64
	Nanosleep      uint64
	ClockNanosleep uint64
}

// SyscallPersonalityFor resolves the syscall personality for one
// object-format machine identity (arch.ID from the Target). An unknown id is
// an error naming the missing support.
func SyscallPersonalityFor(id arch.ID) (SyscallPersonality, error) {
	switch id {
	case arch.IDARM64:
		return SyscallPersonality{
			Transport:      LinuxARM64Transport{},
			Table:          NewARM64SyscallTable(kernel.DefaultHandlers()),
			Codecs:         AsmGenericLP64Codecs{},
			Futex:          SYS_futex,
			Nanosleep:      SYS_nanosleep,
			ClockNanosleep: SYS_clock_nanosleep,
		}, nil
	case arch.IDAMD64:
		return SyscallPersonality{
			Transport:      LinuxAMD64Transport{},
			Table:          NewAMD64SyscallTable(kernel.DefaultHandlers()),
			Codecs:         LinuxX8664Codecs{},
			Futex:          SYSX_futex,
			Nanosleep:      SYSX_nanosleep,
			ClockNanosleep: SYSX_clock_nanosleep,
		}, nil
	case arch.IDARM:
		return SyscallPersonality{
			Transport:      LinuxARM32Transport{},
			Table:          NewARM32SyscallTable(kernel.DefaultHandlers()),
			Codecs:         LinuxARM32Codecs{},
			Futex:          SYSA_futex,
			Nanosleep:      SYSA_nanosleep,
			ClockNanosleep: SYSA_clock_nanosleep,
		}, nil
	}
	return SyscallPersonality{}, fmt.Errorf("android: no syscall personality for arch id %d", id)
}
