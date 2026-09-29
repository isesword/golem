//go:build unicorn

// THROWAWAY probe (P5a bring-up): answers unicorn-x86 behavioral questions
// before the real backend lands. Will be replaced by proper tests.
package emu

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	probeArchX86  = 4 // UC_ARCH_X86
	probeMode64   = 1 << 3
	probeHookInsn = 1 << 1
	probeHookIntr = 1 << 0
	x86InsnSys    = 699 // UC_X86_INS_SYSCALL (parsed from x86.h)
	ucX86RIP      = 41
	ucX86RAX      = 35
	ucX86RDI      = 39
	ucX86RSP      = 44
	ucX86FSBASE   = 250
)

func TestProbeAMD64(t *testing.T) {
	if err := ensureLoaded(); err != nil {
		t.Skipf("no unicorn: %v", err)
	}
	var uc unsafe.Pointer
	if e := pOpen(probeArchX86, probeMode64, unsafe.Pointer(&uc)); e != 0 {
		t.Fatalf("uc_open x86: %s", pStrerror(e))
	}
	defer pClose(uc)

	const base = 0x100000
	if e := pMemMap(uc, base, 0x2000, uint32(ProtAll)); e != 0 {
		t.Fatalf("mem_map: %s", pStrerror(e))
	}
	// code: mov rax, 60 ; mov rdi, 42 ; syscall ; mov rax, fs:[0]... keep simple:
	//   48 c7 c0 3c 00 00 00   mov rax, 60
	//   48 c7 c7 2a 00 00 00   mov rdi, 42
	//   0f 05                  syscall
	//   cc                     int3
	//   c3                     ret
	code := []byte{
		0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
		0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00,
		0x0f, 0x05,
		0xcc,
		0xc3,
	}
	if e := pMemWrite(uc, base, unsafe.Pointer(&code[0]), uint64(len(code))); e != 0 {
		t.Fatalf("mem_write: %s", pStrerror(e))
	}

	rd := func(reg int32) uint64 {
		var v uint64
		if e := pRegRead(uc, reg, unsafe.Pointer(&v)); e != 0 {
			t.Fatalf("reg_read %d: %s", reg, pStrerror(e))
		}
		return v
	}

	// 1) plain run without syscall hook: expect UC_ERR_EXCEPTION or silent pass?
	err1 := pStart(uc, base, base+uint64(len(code)), 0, 0)
	t.Logf("run WITHOUT syscall hook: err=%d (%s) rip=%#x rax=%d", err1, pStrerror(err1), rd(ucX86RIP), rd(ucX86RAX))

	// reset
	if e := pRegWrite(uc, ucX86RAX, unsafe.Pointer(&[]uint64{0}[0])); e != 0 {
		t.Fatal(e)
	}

	// 2) UC_HOOK_INSN syscall — 8-arg fixed declaration (insn id would land in
	// a register on darwin/arm64, but uc_hook_add reads variadic from stack).
	var hh8 uint64
	type hookAdd8T func(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64, insn int64) int32
	var hookAdd8 hookAdd8T
	if sym, err := findSymbolMust(t, "uc_hook_add"); err == nil {
		purego.RegisterFunc(&hookAdd8, sym)
	}
	called8 := 0
	cb8 := purego.NewCallback(func(ucp uintptr, user uintptr) uintptr {
		called8++
		return 0
	})
	e8 := hookAdd8(uc, &hh8, probeHookInsn, cb8, 0, 1, 0, x86InsnSys)
	t.Logf("hook_add 8-arg: err=%d (%s)", e8, pStrerror(e8))
	err2 := pStart(uc, base, base+uint64(len(code)), 0, 0)
	t.Logf("run WITH 8-arg insn hook: err=%d rip=%#x rax=%d rdi=%d hookFired=%d", err2, rd(ucX86RIP), rd(ucX86RAX), rd(ucX86RDI), called8)
	if hh8 != 0 {
		pHookDel(uc, hh8)
		hh8 = 0
	}

	// 3) 9-arg padded declaration (pad fills x7; insn id lands on the stack
	// where darwin/arm64 variadic reads it).
	var hh9 uint64
	type hookAdd9T func(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64, pad, insn int64) int32
	var hookAdd9 hookAdd9T
	if sym, err := findSymbolMust(t, "uc_hook_add"); err == nil {
		purego.RegisterFunc(&hookAdd9, sym)
	}
	called9 := 0
	cb9 := purego.NewCallback(func(ucp uintptr, user uintptr) uintptr {
		called9++
		return 0
	})
	e9 := hookAdd9(uc, &hh9, probeHookInsn, cb9, 0, 1, 0, 0, x86InsnSys)
	t.Logf("hook_add 9-arg padded: err=%d (%s)", e9, pStrerror(e9))
	err3 := pStart(uc, base, base+uint64(len(code)), 0, 0)
	t.Logf("run WITH 9-arg insn hook: err=%d rip=%#x rax=%d rdi=%d hookFired=%d", err3, rd(ucX86RIP), rd(ucX86RAX), rd(ucX86RDI), called9)
	if hh9 != 0 {
		pHookDel(uc, hh9)
	}

	// 4) INT3 → UC_HOOK_INTR?
	var hhI uint64
	intrNo := -1
	intrRIP := uint64(0)
	cbI := purego.NewCallback(func(ucp uintptr, intno uint64, user uintptr) uintptr {
		intrNo = int(intno)
		var v uint64
		pRegRead(uc, ucX86RIP, unsafe.Pointer(&v))
		intrRIP = v
		return 0
	})
	ei := pHookAdd(uc, &hhI, probeHookIntr, cbI, 0, 1, 0)
	t.Logf("hook_add intr: err=%d", ei)
	err4 := pStart(uc, base+16, base+uint64(len(code)), 0, 0) // start at int3
	t.Logf("run int3: err=%d (%s) intno=%d ripAtHook=%#x", err4, pStrerror(err4), intrNo, intrRIP)
	pHookDel(uc, hhI)

	// 5) FS base write + read back; and guest fs:[0] access
	fsval := uint64(0xdead0000)
	if e := pRegWrite(uc, ucX86FSBASE, unsafe.Pointer(&fsval)); e != 0 {
		t.Fatalf("write FS_BASE: %s", pStrerror(e))
	}
	t.Logf("FS_BASE readback=%#x", rd(ucX86FSBASE))
	if e := pMemMap(uc, 0xdead0000, 0x1000, uint32(ProtAll)); e != 0 {
		t.Fatalf("map fs page: %s", pStrerror(e))
	}
	val := uint64(0x1122334455667788)
	pMemWrite(uc, 0xdead0000, unsafe.Pointer(&val), 8)
	// mov rax, fs:[0]  =>  64 48 8b 04 25 00 00 00 00 ; then ret... stop via until
	fscode := []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}
	pMemWrite(uc, base+0x1000, unsafe.Pointer(&fscode[0]), uint64(len(fscode)))
	err5 := pStart(uc, base+0x1000, base+0x1000+uint64(len(fscode)), 0, 0)
	t.Logf("fs:[0] read: err=%d rax=%#x", err5, rd(ucX86RAX))

	fmt.Println("probe done")
}

func findSymbolMust(t *testing.T, name string) (uintptr, error) {
	t.Helper()
	h, err := dlopenUnicorn()
	if err != nil {
		return 0, err
	}
	return findSymbol(h, name)
}
