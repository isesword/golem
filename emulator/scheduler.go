package emulator

import (
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/platform/android"
)

// This file is golem's cooperative thread scheduler — the green-thread runtime
// that lets the guest's pthread_create'd threads actually run. We can't run
// guest threads concurrently (one CPU engine, no nested Start), so instead each
// thread is a fiber with its own stack and a saved CPU context; the scheduler
// runs them in interleaved slices, switching at yield points (futex wait,
// nanosleep) or when a slice's instruction budget is spent, and resumes them
// later from their saved context. This is what lets a daemon thread (a detection
// watchdog, the token fetcher) make real progress instead of being cut off.
//
// The "main" thread (a top-level CallFunc from Go) is not a fiber; the scheduler
// runs between main calls (via RunThreads) and snapshots/restores the main CPU
// state around the fiber slices so the main thread's stack/registers survive.

const (
	fiberStackSize = 0x100000 // 1 MiB guest stack per fiber
	fiberSliceCap  = 20000    // serviced syscalls per slice before preemption
	fiberMaxSlices = 80       // cap total slices per fiber (bounds daemon loops)
	schedMaxRounds = 100000   // safety bound on scheduler rounds
)

// fiberState tracks where a fiber is in its lifecycle.
type fiberState int

const (
	fsRunnable fiberState = iota // fresh, or resumable now
	fsWaiting                    // parked on a futex uaddr (only a wake resumes it)
	fsSleeping                   // yielded (nanosleep/preempt); runnable next round
	fsParked                     // slice budget spent; only a futex wake resumes it
	fsDone                       // returned
)

// yield reasons set by the interrupt handler when a fiber slice stops.
const (
	yieldNone = iota
	yieldPreempt
	yieldFutexWait
	yieldSleep
)

// The syscall numbers the scheduler intercepts to drive switching come from
// the Android/AArch64 platform table (android.SYS_futex / SYS_nanosleep /
// SYS_clock_nanosleep); only the futex op bits stay local (they are scheduler
// policy, not table data).
const (
	futexOpWait = 0
	futexOpWake = 1
)

// fiber is one guest thread spawned via pthread_create.
type fiber struct {
	id       int
	routine  uint64         // start_routine
	arg      uint64         // its argument
	sp       uint64         // dedicated stack top
	started  bool           // false until first run
	ctx      emu.CPUContext // saved full CPU context while suspended
	state    fiberState
	waitAddr uint64 // futex uaddr it parked on
	slices   int    // slices consumed (budget)
}

// newFiber registers a pthread_create'd start routine as a runnable fiber with
// its own stack. It runs on the next RunThreads.
func (e *Emulator) newFiber(routine, arg uint64) *fiber {
	e.nextFiberID++
	base := e.MustAlloc(fiberStackSize, emu.ProtRead|emu.ProtWrite) // pthread_create up-call: no error channel
	f := &fiber{
		id:      e.nextFiberID,
		routine: routine,
		arg:     arg,
		sp:      base + fiberStackSize - 0x200, // 16-aligned, headroom
		state:   fsRunnable,
	}
	e.fibers = append(e.fibers, f)
	return f
}

// PendingThreads reports how many fibers are not yet finished.
func (e *Emulator) PendingThreads() int {
	n := 0
	for _, f := range e.fibers {
		if f.state != fsDone {
			n++
		}
	}
	return n
}

// RunThreads runs all spawned fibers cooperatively until none can make progress
// (every fiber is done, or parked/waiting on a futex with no pending wake),
// interleaving slices and saving/restoring each fiber's full CPU context across
// yields. The main thread's CPU state is snapshotted and restored around the
// run, so a top-level call's stack/registers are unaffected. Returns the number
// of slices executed.
func (e *Emulator) RunThreads() (int, error) {
	if e.poisonErr != nil {
		return 0, fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	if !e.anyRunnable() {
		return 0, nil
	}
	// Preserve the main thread's full register state across the fiber slices.
	cm, ok := e.be.(emu.ContextManager)
	if !ok { // capability probe: engine cannot snapshot at all
		return 0, fmt.Errorf("scheduler: save main context: %w (engine %q)", emu.ErrUnsupported, e.engine)
	}
	mainCtx, err := cm.SaveContext()
	if err != nil {
		return 0, fmt.Errorf("scheduler: save main context: %w", err)
	}
	defer func() {
		_ = cm.RestoreContext(mainCtx)
		_ = mainCtx.Free()
	}()

	ran := 0
	for round := 0; round < schedMaxRounds; round++ {
		progressed := false
		for _, f := range e.fibers {
			if f.state != fsRunnable && f.state != fsSleeping {
				continue
			}
			if f.slices >= fiberMaxSlices {
				e.parkFiber(f)
				continue
			}
			if err := e.runFiberSlice(f); err != nil {
				return ran, err
			}
			ran++
			progressed = true
		}
		if !progressed {
			break
		}
	}
	return ran, nil
}

func (e *Emulator) anyRunnable() bool {
	for _, f := range e.fibers {
		if f.state == fsRunnable || f.state == fsSleeping {
			return true
		}
	}
	return false
}

func (e *Emulator) parkFiber(f *fiber) {
	f.state = fsParked
	if f.ctx != nil {
		_ = f.ctx.Free()
		f.ctx = nil
	}
}

// runFiberSlice runs one fiber for up to one slice (until it yields, returns, or
// the slice budget is spent), then snapshots it for later resumption.
func (e *Emulator) runFiberSlice(f *fiber) error {
	e.curFiber = f
	e.yieldReason = yieldNone
	e.threadCap, e.threadOps = fiberSliceCap, 0
	e.scCount = 0 // per-slice runaway budget
	defer func() { e.curFiber = nil; e.threadCap = 0 }()

	startPC := f.routine
	if !f.started {
		// First slice: set up a plain function call (routine(arg)) per the
		// CallABI — own stack, arg in register 0, LR = sentinel.
		if err := e.be.RegWrite(e.spReg, f.sp); err != nil {
			return err
		}
		_ = e.be.RegWrite(e.argRegs[0], f.arg)
		_ = e.be.RegWrite(e.lrReg, sentinel)
		f.started = true
	} else {
		// Capability probe: an engine without ContextManager cannot resume —
		// same degradation as a failed RestoreContext (drop the fiber).
		cm, ok := e.be.(emu.ContextManager)
		if !ok {
			_ = f.ctx.Free()
			f.ctx = nil
			f.state = fsParked
			return nil
		}
		if err := cm.RestoreContext(f.ctx); err != nil { // can't resume -> drop it
			_ = f.ctx.Free()
			f.ctx = nil
			f.state = fsParked
			return nil
		}
		_ = f.ctx.Free()
		f.ctx = nil
		startPC, _ = e.be.RegRead(e.pcReg)
	}

	if err := e.be.Start(emu.GuestAddr(startPC), emu.GuestAddr(sentinel)); err != nil {
		if e.cfg.Verbose {
			fmt.Printf("[sched] fiber %d fault: %v\n", f.id, err)
		}
		f.state = fsDone // a fault in a worker thread shouldn't kill the process
		return nil
	}
	// A guest up-call panicked inside the slice (recovered at the trampoline
	// boundary, guard.go): guest state is untrusted — poison and abort the run.
	if err := e.checkGuestPanic(); err != nil {
		f.state = fsDone
		return err
	}
	if exited, code := e.GuestExited(); exited {
		return fmt.Errorf("guest exit_group(%d) in fiber %d", code, f.id)
	}

	if pc, _ := e.be.RegRead(e.pcReg); pc == sentinel {
		f.state = fsDone
		return nil
	}
	// Yielded mid-execution — snapshot so we can resume from exactly here.
	cm, ok := e.be.(emu.ContextManager)
	if !ok { // capability probe: backend can't snapshot -> single-slice only
		f.state = fsParked
		return nil
	}
	ctx, err := cm.SaveContext()
	if err != nil {
		f.state = fsParked // backend can't snapshot -> single-slice only
		return nil
	}
	f.ctx = ctx
	f.slices++
	if e.yieldReason == yieldFutexWait {
		f.state, f.waitAddr = fsWaiting, e.yieldAddr
	} else {
		f.state = fsSleeping // preempt / nanosleep -> eligible again next round
	}
	return nil
}

// wakeFutex makes every fiber parked on uaddr runnable again; returns the count.
func (e *Emulator) wakeFutex(uaddr uint64) int {
	n := 0
	for _, f := range e.fibers {
		if (f.state == fsWaiting || f.state == fsParked) && f.waitAddr == uaddr {
			f.state = fsRunnable
			n++
		}
	}
	return n
}

// handleSchedSyscall services the syscalls the scheduler cares about: futex
// (wake fibers / park the caller) and nanosleep (yield). Returns true if it
// handled the syscall (so the kernel layer is skipped). futex WAKE is honored on
// any thread; WAIT/sleep only suspend a fiber (the main thread never blocks).
//
// P2: the frame arrives pre-decoded by the platform syscall transport
// (onInterrupt decodes once per trap), and results are written back through
// the same transport — no syscall-register identities (X8/X0/X1) appear here
// anymore. The interception SEMANTICS are unchanged: the scheduler answers
// these syscalls itself and the kernel table never sees them.
func (e *Emulator) handleSchedSyscall(b emu.Backend, f *kernel.SyscallFrame) bool {
	encode := func(res kernel.Result) {
		_ = e.kctx.Transport.EncodeResult(b, res)
	}
	switch f.Num {
	case android.SYS_futex:
		uaddr, op := f.Args[0], f.Args[1]
		switch op & 0x7f {
		case futexOpWake:
			encode(kernel.Result{Value: uint64(e.wakeFutex(uaddr))})
		case futexOpWait:
			encode(kernel.Result{}) // resume as if woken
			if e.curFiber != nil {
				e.yieldReason, e.yieldAddr = yieldFutexWait, uaddr
				_ = b.Stop()
			}
		default:
			encode(kernel.Result{})
		}
		return true
	case android.SYS_nanosleep, android.SYS_clock_nanosleep:
		encode(kernel.Result{})
		if e.curFiber != nil {
			e.yieldReason = yieldSleep
			_ = b.Stop()
		}
		return true
	}
	return false
}
