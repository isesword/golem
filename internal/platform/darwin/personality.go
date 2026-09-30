package darwin

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/kernel"
)

// SyscallPersonality bundles one guest architecture's syscall ABI pieces for
// the kernel.Context injection (mirroring the Android shape, P5a.5): the
// register transport, the number→handler dispatch table, the guest struct
// codecs, and the syscall numbers the emulator's cooperative scheduler
// intercepts. The arch-keyed selection lives HERE — per-arch knowledge is the
// platform package's job; the emulator only ever assembles the returned
// personality.
type SyscallPersonality struct {
	Transport kernel.SyscallTransport
	Table     *kernel.Table
	Codecs    kernel.StructCodecs

	// Scheduler interception numbers. P5b does NO fiber scheduling for
	// Darwin guests: XNU has no futex, and its sleep/wait primitives (psynch)
	// are not modelled. All three stay 0 — which collides with BSD's
	// indirect-syscall number 0 in theory, but arm64 compilers never emit it
	// (the number is always materialized into x16 directly), and no P5b guest
	// issues it. If Darwin fiber scheduling ever lands, these become the real
	// __psynch_* numbers.
	Futex          uint64
	Nanosleep      uint64
	ClockNanosleep uint64
}

// SyscallPersonalityFor resolves the syscall personality for one
// object-format machine identity (arch.ID from the Target). Darwin/ARM64 is
// the only supported combination; an unknown id is an error naming the
// missing support.
func SyscallPersonalityFor(id arch.ID) (SyscallPersonality, error) {
	switch id {
	case arch.IDARM64:
		return SyscallPersonality{
			Transport: NewARM64Transport(),
			Table:     NewARM64SyscallTable(kernel.DefaultHandlers()),
			Codecs:    XNUARM64Codecs{},
		}, nil
	}
	return SyscallPersonality{}, fmt.Errorf("darwin: no syscall personality for arch id %d", id)
}
