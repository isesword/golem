//go:build unicorn

// AMD64 (x86-64) support for the unicorn backend (P5a): engine creation
// constants, the UC_X86_REG_* translation table, and the syscall-instruction
// trap channel (UC_HOOK_INSN / UC_X86_INS_SYSCALL).
//
// The UC constant values below are pinned against unicorn2's
// include/unicorn/unicorn.h and include/unicorn/unicorn/x86.h (the enum order
// is alphabetical in unicorn2; do NOT "fix" them from unicorn1 memory).
// UC_X86_INS_SYSCALL=699 and the UC_X86_REG_* values were machine-derived
// from the installed headers and verified by live-engine tests
// (TestUnicornAMD64*): a wrong reg id fails uc_reg_read/write loudly, and the
// FS-base/TLS test would read garbage.
package emu

import (
	"fmt"
	"runtime"
	"unsafe"
)

const (
	ucArchX86 = 4     // UC_ARCH_X86
	ucMode64  = 1 << 3 // UC_MODE_64

	hkInsn = 1 << 1 // UC_HOOK_INSN

	ucX86InsSyscall = 699 // UC_X86_INS_SYSCALL (x86.h enum order)

	// UC_X86_REG_* values used by the AMD64 mapping.
	ucX86RegEFLAGS = 25
	ucX86RegRAX    = 35
	ucX86RegRBP    = 36
	ucX86RegRBX    = 37
	ucX86RegRCX    = 38
	ucX86RegRDI    = 39
	ucX86RegRDX    = 40
	ucX86RegRIP    = 41
	ucX86RegRSI    = 43 // note the gap: RIP+1 is the UC_X86_REG_ES alias slot
	ucX86RegRSP    = 44
	ucX86RegR8     = 106
	ucX86RegR9     = 107
	ucX86RegR10    = 108
	ucX86RegR11    = 109
	ucX86RegR12    = 110
	ucX86RegR13    = 111
	ucX86RegR14    = 112
	ucX86RegR15    = 113
	ucX86RegFSBase = 250
	ucX86RegGSBase = 251
)

// regMapAMD64 translates an abstract emu.Reg to its UC_X86_REG_* id. It keys
// on the id NUMBERS internal/arch/amd64 assigns (RAX=64 .. GS_BASE=83 — emu
// cannot import that package: amd64 imports emu for emu.Reg, the reverse
// would be an import cycle). arch/amd64's TestFrozenRegIDs pins those
// numbers, so any drift fails tests loudly instead of corrupting registers.
func regMapAMD64(r Reg) int32 {
	switch r {
	case 64: // amd64.RAX
		return ucX86RegRAX
	case 65: // amd64.RBX
		return ucX86RegRBX
	case 66: // amd64.RCX
		return ucX86RegRCX
	case 67: // amd64.RDX
		return ucX86RegRDX
	case 68: // amd64.RSI
		return ucX86RegRSI
	case 69: // amd64.RDI
		return ucX86RegRDI
	case 70: // amd64.RBP
		return ucX86RegRBP
	case 71: // amd64.RSP
		return ucX86RegRSP
	case 72: // amd64.R8
		return ucX86RegR8
	case 73: // amd64.R9
		return ucX86RegR9
	case 74: // amd64.R10
		return ucX86RegR10
	case 75: // amd64.R11
		return ucX86RegR11
	case 76: // amd64.R12
		return ucX86RegR12
	case 77: // amd64.R13
		return ucX86RegR13
	case 78: // amd64.R14
		return ucX86RegR14
	case 79: // amd64.R15
		return ucX86RegR15
	case 80: // amd64.RIP
		return ucX86RegRIP
	case 81: // amd64.EFLAGS
		return ucX86RegEFLAGS
	case 82: // amd64.FS_BASE
		return ucX86RegFSBase
	case 83: // amd64.GS_BASE
		return ucX86RegGSBase
	default: // includes amd64.NoLR (-1) and every arm64 id — loud failure
		return ucRegInvalid
	}
}

// ---- UC_HOOK_INSN: the AMD64 guest-syscall channel -----------------------------
//
// On x86-64 the guest `syscall` instruction is NOT an interrupt: unicorn
// raises UC_ERR_EXCEPTION for it unless a UC_HOOK_INSN hook for
// UC_X86_INS_SYSCALL is installed (verified by live-engine probe, P5a). Host
// stubs (`int3`) keep using the interrupt channel (UC_HOOK_INTR, intno 3) —
// the two channels are independent by design.
//
// FFI subtlety: uc_hook_add's instruction id is the first VARIADIC C argument.
// On SysV hosts (linux/*, darwin/amd64) and Windows it passes like any other
// integer argument, so the plain 8-argument declaration is exact. On
// darwin/arm64 the Apple ABI passes variadic arguments on the STACK only, so
// the padded 9-argument declaration fills x7 with a dummy and lands the insn
// id in the first stack slot, exactly where uc_hook_add's va_arg reads it
// (verified by probe: the plain form makes uc_hook_add read garbage and
// return UC_ERR_HOOK on darwin/arm64).

var (
	// pHookAddInsn is uc_hook_add with the variadic instruction id fixed —
	// exact on SysV/Windows hosts for integer-only argument lists.
	pHookAddInsn func(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64, insn int64) int32
	// pHookAddInsnPad is the darwin/arm64-host form: one extra integer pad so
	// the insn id lands on the stack (Apple variadic convention).
	pHookAddInsnPad func(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64, pad, insn int64) int32
)

// hookAddInsn installs a UC_HOOK_INSN hook for insnID, choosing the host-ABI
// correct declaration (see the FFI note above).
func hookAddInsn(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64, insnID int64) int32 {
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		return pHookAddInsnPad(uc, hh, htype, cb, user, begin, end, 0, insnID)
	}
	return pHookAddInsn(uc, hh, htype, cb, user, begin, end, insnID)
}

// goInsnHook is the C→Go trampoline for UC_HOOK_INSN hooks. The x86 syscall
// hook typedef (uc_cb_insn_syscall_t) takes just (uc, user_data).
func goInsnHook(uc uintptr, user uintptr) uintptr {
	if e := lookupCB(uint64(user)); e != nil && e.insn != nil {
		e.insn(e.be)
	}
	return 0
}

// installInsnTrap serves InstallTrap(TrapSyscall) on AMD64 engines: a lazily
// installed UC_HOOK_INSN(UC_X86_INS_SYSCALL) dispatches to every registered
// syscall trap handler, each receiving the kind it was registered under —
// the same contract the UC_HOOK_INTR adapter gives ARM64.
func (b *unicornBackend) installInsnTrap(kind TrapKind, h TrapHandler) (HookHandle, error) {
	if b.insnHook == nil {
		id := registerCB(&hookReg{be: b, insn: func(bk Backend) {
			for _, tr := range b.insnTraps {
				tr.h(bk, tr.kind)
			}
		}})
		var hh uint64
		if e := hookAddInsn(b.uc, &hh, hkInsn, insnTramp, uintptr(id), 1, 0, ucX86InsSyscall); e != ucOK {
			unregisterCB(id)
			return nil, ucErr("hook_add UC_HOOK_INSN syscall", e)
		}
		b.cbs = append(b.cbs, id)
		b.insnHook = &ucHook{b: b, hh: hh, id: id}
	}
	tr := &trapReg{kind: kind, h: h}
	b.insnTraps = append(b.insnTraps, tr)
	return &insnTrapHandle{b: b, tr: tr}, nil
}

// insnTrapHandle removes one insn-channel InstallTrap registration. The
// underlying UC_HOOK_INSN hook stays (inert once insnTraps is empty) — Close
// releases it via b.cbs.
type insnTrapHandle struct {
	b  *unicornBackend
	tr *trapReg
}

func (h *insnTrapHandle) Remove() error {
	for i, tr := range h.b.insnTraps {
		if tr == h.tr {
			h.b.insnTraps = append(h.b.insnTraps[:i], h.b.insnTraps[i+1:]...)
			break
		}
	}
	return nil
}

// errNoGPRegs is the ReadGPRegs answer on non-ARM64 engines: the [34]uint64
// register-file shape ([0..30]=x0..x30, [31]=sp, [32]=pc, [33]=nzcv) is an
// AArch64 layout baked into the Backend contract; the full instruction tracer
// that consumes it is ARM64-only for now. AMD64 engines report the capability
// as unsupported rather than stuffing foreign registers into ARM-shaped slots.
func errNoGPRegs(a Arch) error {
	return fmt.Errorf("emu: ReadGPRegs: the [34] register-file shape is AArch64-specific; arch %s: %w", a, ErrUnsupported)
}
