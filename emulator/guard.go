package emulator

import (
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// This file is the panic boundary between Go callbacks and the CPU engine.
//
// Guest up-calls — trap dispatch (onStubTrap / onSyscallTrap) and everything
// behind it (JNI handlers, Replace callbacks, Go-implemented libc functions),
// plus code and memory hooks — run INSIDE the engine's C→Go trampoline
// (purego). A panic
// that escapes one of those callbacks unwinds across the C boundary, where
// nobody can recover it: the whole process dies, and the Go caller that
// started the run never sees an error. MustAlloc/WriteScratch panic by design
// on exactly these paths, so the boundary must exist.
//
// Every Go function handed to the backend is therefore wrapped by one of the
// guard* helpers below: a panic is recorded in e.pendingPanic and the engine
// is told to Stop, so uc_emu_start returns at the next safe point and the
// panic surfaces as an ordinary error from the run entry point
// (checkGuestPanic in CallFunc and the scheduler). Because guest state after
// a mid-upcall panic is untrusted, surfacing it also poisons the emulator.

// recoverGuestPanic is the deferred head of every guarded backend callback:
// it records the FIRST pending panic (a cascade of secondary panics during
// unwind would only obscure the cause) and asks the engine to unwind the run.
func (e *Emulator) recoverGuestPanic() {
	if p := recover(); p != nil {
		if e.pendingPanic == nil {
			e.pendingPanic = p
		}
		_ = e.be.Stop() // make uc_emu_start return at the next safe point
	}
}

// checkGuestPanic runs after every backend Start returns. A pending panic
// means a guarded callback blew up mid-run: the guest's register/stack state
// was abandoned mid-instruction-stream and cannot be trusted, so the emulator
// is poisoned (every later public entry point refuses to run) and the panic
// is reported as an error.
func (e *Emulator) checkGuestPanic() error {
	if p := e.pendingPanic; p != nil {
		e.pendingPanic = nil
		return e.poison("guest callback panic", fmt.Errorf("panic during guest callback: %v", p))
	}
	return nil
}

// guardTrap / guardCode / guardMemInvalid / guardMemRead / guardMemWrite
// wrap the callback signatures the emu capability interfaces accept;
// guardHostFn wraps the internal hostFn entries (Replace callbacks, Go libc
// implementations) that fire from onStubTrap — already covered by the trap
// guard, but the boundary belongs on every entry the backend can
// reach. The emulator's own callbacks keep plain uint64 addresses; the
// GuestAddr→uint64 conversion happens here, at the backend boundary.
func (e *Emulator) guardTrap(fn emu.TrapHandler) emu.TrapHandler {
	return func(b emu.Backend, kind emu.TrapKind) {
		defer e.recoverGuestPanic()
		fn(b, kind)
	}
}

func (e *Emulator) guardCode(fn func(emu.Backend, uint64, uint32)) emu.CodeHookFunc {
	return func(b emu.Backend, addr emu.GuestAddr, size uint32) {
		defer e.recoverGuestPanic()
		fn(b, uint64(addr), size)
	}
}

func (e *Emulator) guardMemInvalid(fn func(emu.Backend, int, uint64, int, int64) bool) emu.MemInvalidHookFunc {
	return func(b emu.Backend, typ int, addr emu.GuestAddr, size int, val int64) bool {
		defer e.recoverGuestPanic()
		return fn(b, typ, uint64(addr), size, val)
	}
}

func (e *Emulator) guardMemRead(fn func(emu.Backend, uint64, int)) emu.MemReadHookFunc {
	return func(b emu.Backend, addr emu.GuestAddr, size int) {
		defer e.recoverGuestPanic()
		fn(b, uint64(addr), size)
	}
}

func (e *Emulator) guardMemWrite(fn func(emu.Backend, uint64, int, int64)) emu.MemWriteHookFunc {
	return func(b emu.Backend, addr emu.GuestAddr, size int, val int64) {
		defer e.recoverGuestPanic()
		fn(b, uint64(addr), size, val)
	}
}

func (e *Emulator) guardHostFn(fn hostFn) hostFn {
	return func(em *Emulator, b emu.Backend) {
		defer e.recoverGuestPanic()
		fn(em, b)
	}
}
