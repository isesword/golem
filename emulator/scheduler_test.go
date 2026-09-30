package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// schedTestTransport records what the scheduler would write back to the
// guest — a fabricated result here is exactly the "fake success" the
// unbound-intercept guard exists to prevent.
type schedTestTransport struct {
	encoded int
	last    kernel.Result
}

func (t *schedTestTransport) Decode(b emu.Backend) (kernel.SyscallFrame, error) {
	return kernel.SyscallFrame{}, nil
}

func (t *schedTestTransport) EncodeResult(b emu.Backend, r kernel.Result) error {
	t.encoded++
	t.last = r
	return nil
}

// TestSchedulerUnboundInterceptNumbersNeverMatch pins the P7.5b guard: a
// Darwin-shaped personality leaves all three intercept numbers 0 (no
// futex/nanosleep fibers on that platform). A guest syscall numbered 0 —
// BSD's indirect-syscall register value — must fall through to the kernel
// table (loud ENOSYS), never be eaten by the futex case as a fabricated
// success.
func TestSchedulerUnboundInterceptNumbersNeverMatch(t *testing.T) {
	tr := &schedTestTransport{}
	e := &Emulator{kctx: &kernel.Context{Transport: tr}} // sys* all unbound (0)
	fr := &kernel.SyscallFrame{Num: 0, Args: [8]uint64{0x1000, futexOpWait}}
	if e.handleSchedSyscall(nil, fr) {
		t.Fatal("Num=0 with unbound intercept numbers must NOT be intercepted")
	}
	if tr.encoded != 0 {
		t.Fatalf("transport saw %d encoded results, want 0 (no fabricated success)", tr.encoded)
	}

	// The bound case still intercepts: sysFutex set, matching number, wait
	// answered by the scheduler (curFiber nil → main-thread semantics).
	e.sysFutex = 98
	if !e.handleSchedSyscall(nil, &kernel.SyscallFrame{Num: 98, Args: [8]uint64{0x1000, futexOpWait}}) {
		t.Fatal("Num=98 with sysFutex=98 must be intercepted")
	}
	if tr.last.Errno != 0 {
		t.Fatalf("bound futex wait result = %+v, want success", tr.last)
	}

	// An unbound nanosleep must not swallow its own would-be number either.
	e.sysFutex = 0
	e.sysNanosleep = 0
	e.sysClockNanosleep = 0
	if e.handleSchedSyscall(nil, &kernel.SyscallFrame{Num: 35}) {
		t.Fatal("nanosleep with unbound numbers must NOT be intercepted")
	}
}
