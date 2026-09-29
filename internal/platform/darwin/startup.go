package darwin

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/platform"
)

// StackTopReserve is the headroom between the initial SP and the top of the
// stack mapping: the boot sets SP = StackBase+StackSize-StackTopReserve, and
// BuildInitialState lays the exec-style frame out with argc AT that SP. The
// frame built below is 60 bytes; 0x100 leaves slack for future apple
// parameters without a geometry change.
const StackTopReserve = 0x100

// argv0 is the single string the initial frame carries: argv[0] and the
// apple[0] executable_path parameter both point at it (as after a real
// execve where argv[0] equals the path).
const argv0 = "golem-guest"

// StartupABI is the Darwin personality's platform.StartupABI (P5b).
//
// Landing form — EXEC-STYLE INITIAL STACK FRAME, not an auxv data block.
// This is the deliberate counter-example to the Android StartupABI: XNU hands
// a new process argc/argv/envp/apple on the stack and has NO auxiliary vector
// at all (dyld learns everything from the mach-o header and sysctl, not from
// AT_* pairs). So BuildInitialState materializes
//
//	[sp+0]  argc = 1
//	[sp+8]  argv[0] -> "golem-guest"
//	[sp+16] NULL            (argv terminator)
//	[sp+24] NULL            (envp terminator: empty environment)
//	[sp+32] apple[0] -> "golem-guest"
//	[sp+40] NULL            (apple terminator)
//	[sp+48] "golem-guest\0" (12 bytes; frame ends at sp+60)
//
// with sp = Stack.Addr+Stack.Size-StackTopReserve (16-aligned, since both the
// stack top and the reserve are). There is intentionally no AT_RANDOM data
// block and no host-side vector: Darwin guests query nothing of the sort.
//
// Decoupling proof (P5b acceptance): BuildInitialState NEVER reads
// ctx.Features — the HWCAP/auxv coupling is an Android property, and this
// implementation builds the full initial state without it.
type StartupABI struct {
	stackTop emu.GuestAddr // where argc sits; the initial SP
	built    bool
}

var _ platform.StartupABI = (*StartupABI)(nil)

// BuildInitialState writes the exec-style frame into the top of the stack
// region. It must be called at most once per StartupABI. ctx.Image may be
// nil — the frame's content does not depend on image metadata.
func (s *StartupABI) BuildInitialState(ctx *platform.StartupContext) error {
	if s.built {
		return errors.New("darwin startup: BuildInitialState called twice (the initial frame is built once per emulator)")
	}
	if ctx == nil {
		return errors.New("darwin startup: nil StartupContext")
	}
	if ctx.Mem == nil {
		return errors.New("darwin startup: nil Mem writer")
	}
	if ctx.Stack.Size < StackTopReserve {
		return fmt.Errorf("darwin startup: stack region %#x+%#x too small for the initial frame", ctx.Stack.Addr, ctx.Stack.Size)
	}

	sp := ctx.Stack.Addr + ctx.Stack.Size - StackTopReserve
	const frameSize = 48 + len(argv0) + 1 // pointers/terminators + string
	strAddr := sp + 48

	frame := make([]byte, frameSize)
	binary.LittleEndian.PutUint64(frame[0:], 1) // argc
	binary.LittleEndian.PutUint64(frame[8:], strAddr)
	// argv/envp/apple terminators stay zero.
	binary.LittleEndian.PutUint64(frame[32:], strAddr)
	copy(frame[48:], argv0)
	if err := ctx.Mem.MemWrite(emu.GuestAddr(sp), frame); err != nil {
		return fmt.Errorf("darwin startup: write initial stack frame at %#x: %w", sp, err)
	}

	s.stackTop = emu.GuestAddr(sp)
	s.built = true
	return nil
}

// StackTop returns the address of argc in the built frame — the SP a Darwin
// guest starts with — 0 before BuildInitialState. It must equal
// StackBase+StackSize-StackTopReserve of the layout the boot used; the boot
// sets SP from the constant and this ABI parks the frame at exactly that
// address, so the two can never drift apart silently (a mismatch reads argc
// from untouched stack, i.e. 0, and fails loudly).
func (s *StartupABI) StackTop() emu.GuestAddr { return s.stackTop }
