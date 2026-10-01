package emulator

// Public Semantic API — hook context. The facade layer over the frozen
// core: callers ask for WHAT they want to know (arguments, return address,
// register roles); how the CPU actually delivers it stays in the arch
// packages. See the Portable-vs-Advanced split in doc.go.

import (
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/arch"
)

// HookKind classifies WHERE a hook fired, which decides which semantic
// questions are answerable. Entry-scoped answers (Arg, ReturnAddress) are
// only promised at function-entry hooks; asking elsewhere returns
// ErrContextUnavailable instead of a guess.
type HookKind uint8

const (
	// HookInstruction fires at an arbitrary PC (HookAddr / HookSymbol /
	// HookRange / memory hooks). Promised: Kind, PC, SP, ReadRole, and the
	// Advanced raw API. NOT promised: Arg / ReturnAddress / ReturnValue.
	HookInstruction HookKind = iota
	// HookFunctionEntry fires where a guest function ENTERS (import
	// overrides and ReplaceE interposition entries): arguments and the
	// return address are well-defined per the CallABI.
	HookFunctionEntry
	// HookFunctionExit is RESERVED for a future exit-hook API: a context
	// where ReturnValue is well-defined. No public API installs one yet.
	HookFunctionExit
	// HookSyscall is RESERVED (syscall handlers receive a kernel Context,
	// not a Hook).
	HookSyscall
)

func (k HookKind) String() string {
	switch k {
	case HookInstruction:
		return "instruction"
	case HookFunctionEntry:
		return "function-entry"
	case HookFunctionExit:
		return "function-exit"
	case HookSyscall:
		return "syscall"
	default:
		return "hook"
	}
}

// ErrContextUnavailable reports that the asked question has no defined
// answer in THIS hook context (e.g. ReturnAddress at an arbitrary-instruction
// hook, where the frame may already be torn open). Distinct from
// ErrUnsupportedRole: the architecture could answer; the context cannot.
var ErrContextUnavailable = errors.New("emulator: not answerable in this hook context")

// HookContext is the Portable semantic view of a hook firing . Hook
// implements it; consumers should type callbacks against this interface so
// the same code ports across ARM64 / ARM32 / AMD64.
type HookContext interface {
	// Kind reports where the hook fired — the gate for every entry-scoped
	// question below.
	Kind() HookKind
	// PC is the faulting/executing instruction address.
	PC() uint64
	// SP is the stack pointer.
	SP() uint64
	// Arg returns integer argument i as a machine-word Value. Only
	// answerable at function-entry hooks; elsewhere ErrContextUnavailable.
	Arg(i int) (Value, error)
	// ReturnValue returns the call's result. Only answerable at function-
	// exit hooks (none installable yet); elsewhere ErrContextUnavailable.
	ReturnValue() (Value, error)
	// ReturnAddress returns the call's return address. Only answerable at
	// function-entry hooks; elsewhere ErrContextUnavailable.
	ReturnAddress() (uint64, error)
	// ReadRole reads a register by ABI role. CPU-state observation: valid
	// at any kind; an architecture without the role answers
	// ErrUnsupportedRole.
	ReadRole(role RegisterRole) (uint64, error)
}

// Hook satisfies the Portable facade.
var _ HookContext = (*Hook)(nil)

// Kind implements HookContext.
func (h *Hook) Kind() HookKind { return h.kind }

// ReadRole implements HookContext: read a register by ABI role through the
// arch's RoleReader . Loudly unsupported roles never return a silent
// zero.
func (h *Hook) ReadRole(role RegisterRole) (uint64, error) {
	rr, ok := h.e.target.Arch.(arch.RoleReader)
	if !ok {
		return 0, fmt.Errorf("ReadRole(%s): arch %s: %w", role, h.e.target.Arch.EngineArch(), arch.ErrUnsupportedRole)
	}
	v, err := rr.ReadRole(h.e.be, role)
	if err != nil {
		return 0, fmt.Errorf("ReadRole(%s): %w", role, err)
	}
	return v, nil
}
