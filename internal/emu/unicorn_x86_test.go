//go:build unicorn && (darwin || linux)

package emu

import (
	"encoding/binary"
	"errors"
	"testing"
)

// AMD64 behavioral tests on the real engine (P5a). Test-only aliases for the
// arch/amd64 register ids — this package cannot import internal/arch/amd64
// (import cycle); arch/amd64's TestFrozenRegIDs pins the numbers.
const (
	regRAX = Reg(64) // amd64.RAX
	regRDI = Reg(69) // amd64.RDI
	regRSP = Reg(71) // amd64.RSP
	regRIP = Reg(80) // amd64.RIP
	regFSB = Reg(82) // amd64.FS_BASE
)

func newAMD64Backend(t *testing.T) Backend {
	t.Helper()
	be, err := NewNamed("unicorn", ArchAMD64)
	if err != nil {
		t.Skipf("unicorn backend unavailable: %v", err)
	}
	t.Cleanup(func() { be.Close() })
	return be
}

// mapAndWrite maps one RWX page and fills it with guest code.
func mapAndWrite(t *testing.T, be Backend, addr uint64, code []byte) {
	t.Helper()
	if err := be.MemMap(GuestAddr(addr), 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	if err := be.MemWrite(GuestAddr(addr), code); err != nil {
		t.Fatal(err)
	}
}

// TestUnicornAMD64Executes runs a minimal x86-64 program — `mov rax, 42 ;
// mov rdi, rax ; ret` — proving the engine, the register map and execution
// control all work for ArchAMD64.
func TestUnicornAMD64Executes(t *testing.T) {
	be := newAMD64Backend(t)
	const code = 0x100000
	// mov rax, 42 ; mov rdi, rax ; ret
	mapAndWrite(t, be, code, []byte{
		0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00,
		0x48, 0x89, 0xc7,
		0xc3,
	})
	// Stack for the trailing ret: point RSP at a mapped page whose [RSP] is
	// `until`, so ret lands exactly on the stop address.
	const stack = 0x200000
	mapAndWrite(t, be, stack, make([]byte, 0))
	if err := be.RegWrite(regRSP, stack+0x800); err != nil {
		t.Fatal(err)
	}
	// [RSP] = until (code+10) — the ret pops it and unicorn stops there.
	var until [8]byte
	binary.LittleEndian.PutUint64(until[:], code+10)
	if err := be.MemWrite(GuestAddr(stack+0x800), until[:]); err != nil {
		t.Fatal(err)
	}
	if err := be.Start(GuestAddr(code), GuestAddr(code+10)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if v, _ := be.RegRead(regRAX); v != 42 {
		t.Fatalf("RAX = %d, want 42", v)
	}
	if v, _ := be.RegRead(regRDI); v != 42 {
		t.Fatalf("RDI = %d, want 42", v)
	}
	if v, _ := be.RegRead(regRIP); v != code+10 {
		t.Fatalf("RIP = %#x, want %#x (ret popped the until sentinel)", v, code+10)
	}
}

// TestUnicornAMD64TLSFSBase proves SetTLSBase's mechanism end to end: writing
// amd64.FS_BASE makes a guest `mov rax, fs:[off]` read through that base —
// the real x86-64 TLS mechanism, not a register stash.
func TestUnicornAMD64TLSFSBase(t *testing.T) {
	be := newAMD64Backend(t)
	const tls = 0x300000
	mapAndWrite(t, be, tls, nil)
	want := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if err := be.MemWrite(GuestAddr(tls+0x10), want); err != nil {
		t.Fatal(err)
	}
	if err := be.RegWrite(regFSB, tls); err != nil {
		t.Fatalf("write FS_BASE: %v", err)
	}
	const code = 0x100000
	// mov rax, fs:[0x10] ; ud2 (stop via until before ud2)
	mapAndWrite(t, be, code, []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00})
	if err := be.Start(GuestAddr(code), GuestAddr(code+9)); err != nil {
		t.Fatalf("run: %v", err)
	}
	if v, _ := be.RegRead(regRAX); v != 0x8877665544332211 {
		t.Fatalf("fs:[0x10] read = %#x, want 0x8877665544332211", v)
	}
}

// TestUnicornAMD64HostStubTrap proves the host-stub channel: an `int3` inside
// a StubManager-allocated region fires UC_HOOK_INTR (intno 3) with RIP already
// advanced past the int3 byte — the trap source address is PC-1.
func TestUnicornAMD64HostStubTrap(t *testing.T) {
	be := newAMD64Backend(t)
	const stub = 0x60000000
	mapAndWrite(t, be, stub, []byte{0xCC, 0xC3}) // int3 ; ret
	var gotIntno = -1
	var gotRIP uint64
	h, err := be.(InterruptHooker).HookInterrupt(func(b Backend, intno uint32) {
		gotIntno = int(intno)
		gotRIP, _ = b.RegRead(regRIP)
		_ = b.Stop()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()
	_ = be.Start(GuestAddr(stub), GuestAddr(stub+2))
	if gotIntno != 3 {
		t.Fatalf("intno = %d, want 3 (int3)", gotIntno)
	}
	if gotRIP != stub+1 {
		t.Fatalf("RIP at int3 hook = %#x, want %#x (stub+1 — past the 0xCC byte)", gotRIP, stub+1)
	}
}

// TestUnicornAMD64SyscallInsnTrap proves the guest-syscall channel:
// InstallTrap(TrapSyscall) on an AMD64 engine installs
// UC_HOOK_INSN(UC_X86_INS_SYSCALL), and a real guest `syscall` instruction
// fires it (without it the instruction raises UC_ERR_EXCEPTION).
func TestUnicornAMD64SyscallInsnTrap(t *testing.T) {
	be := newAMD64Backend(t)
	const code = 0x100000
	// mov rax, 39 (getpid) ; syscall ; mov rdi, 0x5a
	mapAndWrite(t, be, code, []byte{
		0x48, 0xc7, 0xc0, 0x27, 0x00, 0x00, 0x00,
		0x0f, 0x05,
		0x48, 0xc7, 0xc7, 0x5a, 0x00, 0x00, 0x00,
	})
	fired := 0
	var ripAtHook uint64
	h, err := be.InstallTrap(TrapSyscall, func(b Backend, kind TrapKind) {
		fired++
		if kind != TrapSyscall {
			t.Errorf("handler kind = %v, want TrapSyscall", kind)
		}
		ripAtHook, _ = b.RegRead(regRIP)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()
	if err := be.Start(GuestAddr(code), GuestAddr(code+16)); err != nil {
		t.Fatalf("run with syscall-insn hook: %v", err)
	}
	if fired != 1 {
		t.Fatalf("syscall hook fired %d times, want 1", fired)
	}
	if ripAtHook != code+7 {
		t.Fatalf("RIP at syscall hook = %#x, want %#x (the syscall instruction)", ripAtHook, code+7)
	}
	// Execution continued past the syscall instruction.
	if v, _ := be.RegRead(regRDI); v != 0x5a {
		t.Fatalf("RDI = %#x, want 0x5a — execution must continue after the hooked syscall", v)
	}
}

// TestUnicornAMD64ReadGPRegsUnsupported pins that an AMD64 engine refuses the
// ARM64 register-file shape with ErrUnsupported instead of returning garbage
// in ARM slots (P7.5c: the dump is the RegFileReader capability; the shape is
// arch business, never a core contract).
func TestUnicornAMD64ReadGPRegsUnsupported(t *testing.T) {
	be := newAMD64Backend(t)
	rr, ok := be.(RegFileReader)
	if !ok {
		t.Fatal("the AMD64 backend must implement RegFileReader (answering ErrUnsupported is its job)")
	}
	if _, err := rr.ReadGPRegs(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ReadGPRegs on AMD64: err = %v, want errors.Is(ErrUnsupported)", err)
	}
}
