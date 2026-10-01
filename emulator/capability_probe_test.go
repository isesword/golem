package emulator

import (
	"errors"
	"testing"

	"github.com/isesword/golem/internal/emu"
)

// .5a caller-side capability probes: with a backend that implements ONLY
// the emu.Backend core interface, every capability-gated emulator entry point
// must degrade to an error wrapping emu.ErrUnsupported — the same errors.Is
// path as an engine that has the capability but refuses it.

// probeBE is the minimal fake: the nil embedded emu.Backend satisfies the core
// interface (methods panic if called), and NO capability interface is
// implemented, so every type-assertion probe fails.
type probeBE struct{ emu.Backend }

func TestCapabilityProbeDegrades(t *testing.T) {
	e := newTestEmulator(t, &probeBE{})
	for name, call := range map[string]func() error{
		"HookAddr": func() error {
			_, err := e.HookAddr(0x1000, func(*Hook) {})
			return err
		},
		"HookRange": func() error {
			_, err := e.HookRange(0x1000, 0x2000, func(*Hook, uint64) {})
			return err
		},
		"HookMemRead": func() error {
			_, err := e.HookMemRead(0x1000, 0x2000, func(*Hook, uint64, int) {})
			return err
		},
		"HookMemWrite": func() error {
			_, err := e.HookMemWrite(0x1000, 0x2000, func(*Hook, uint64, int, int64) {})
			return err
		},
		"Trace": func() error {
			_, err := e.Trace(0x1000, 0x2000)
			return err
		},
		// ReplaceE is interposition now — capability-gated on
		// InstructionHooker like the other entry hooks.
		"ReplaceE": func() error {
			return e.ReplaceE(0x1000, func(*Hook) uint64 { return 0 })
		},
		"NewDebugger": func() error {
			_, err := e.NewDebugger()
			return err
		},
		"Snapshot": func() error {
			_, err := e.Snapshot()
			return err
		},
	} {
		if err := call(); !errors.Is(err, emu.ErrUnsupported) {
			t.Errorf("%s on a core-only backend: err = %v, want errors.Is(emu.ErrUnsupported)", name, err)
		}
	}
}
