package android

import (
	"testing"

	"github.com/isesword/golem/internal/arch/amd64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// --- Decode: RAX number + RDI/RSI/RDX/R10/R8/R9 args, NArg=6 ---

// TestLinuxAMD64TransportDecode pins the x86-64 syscall ABI — in particular
// that the 4th argument comes from R10, NOT RCX (the SysV function ABI's 4th
// argument register; `syscall` clobbers RCX itself). This is the "two ABIs"
// red-line test on the transport side; arch/amd64's TestArgRegsVsSyscallABI
// pins the function-call side.
func TestLinuxAMD64TransportDecode(t *testing.T) {
	be := newRegBE()
	be.regs[amd64.RAX] = SYSX_mmap
	argRegs := []emu.Reg{amd64.RDI, amd64.RSI, amd64.RDX, amd64.R10, amd64.R8, amd64.R9}
	for i, r := range argRegs {
		be.regs[r] = uint64(0x100 * (i + 1))
	}
	be.regs[amd64.RCX] = 0xbaad // decoy: must NOT be decoded as arg 3
	f, err := LinuxAMD64Transport{}.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	if f.Num != SYSX_mmap {
		t.Errorf("Num = %d, want %d (RAX)", f.Num, SYSX_mmap)
	}
	if f.NArg != 6 {
		t.Errorf("NArg = %d, want 6", f.NArg)
	}
	for i := 0; i < 6; i++ {
		if want := uint64(0x100 * (i + 1)); f.Args[i] != want {
			t.Errorf("Args[%d] = %#x, want %#x", i, f.Args[i], want)
		}
	}
	if f.Args[3] == 0xbaad {
		t.Error("arg 3 decoded from RCX — the syscall ABI's 4th argument register is R10")
	}
}

func TestLinuxAMD64TransportEncodeSuccess(t *testing.T) {
	be := newRegBE()
	be.regs[amd64.RAX] = 0xdeadbeef // must be overwritten
	if err := (LinuxAMD64Transport{}).EncodeResult(be, kernel.Result{Value: 42}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[amd64.RAX]; got != 42 {
		t.Fatalf("RAX = %#x, want 42", got)
	}
}

func TestLinuxAMD64TransportEncodeErrno(t *testing.T) {
	be := newRegBE()
	if err := (LinuxAMD64Transport{}).EncodeResult(be, kernel.Result{Errno: kernel.ENOSYS}); err != nil {
		t.Fatal(err)
	}
	want := negErrno(kernel.ENOSYS)
	if got := be.regs[amd64.RAX]; got != want {
		t.Fatalf("RAX = %#x, want %#x (-ENOSYS two's complement)", got, want)
	}
}

// Value2: the Linux syscall ABI has ONE result register — RAX. Value2 must
// not leak into RDX (that is the SysV FUNCTION convention's dual return).
func TestLinuxAMD64TransportIgnoresValue2(t *testing.T) {
	be := newRegBE()
	if err := (LinuxAMD64Transport{}).EncodeResult(be, kernel.Result{Value: 7, Value2: 9}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[amd64.RAX]; got != 7 {
		t.Fatalf("RAX = %d, want 7", got)
	}
	if len(be.writes) != 1 {
		t.Fatalf("Linux transport must write exactly RAX, wrote %d registers: %v", len(be.writes), be.writes)
	}
	if _, ok := be.writes[amd64.RDX]; ok {
		t.Fatal("Value2 must NOT leak into RDX on the syscall ABI (RDX dual-return is the SysV function convention)")
	}
}

// TestDispatchEndToEndAMD64: unimplemented syscall -> -ENOSYS in RAX;
// implemented syscall (getpid=39) -> its value, decoded/encoded through the
// AMD64 transport and the x86-64 number table.
func TestDispatchEndToEndAMD64(t *testing.T) {
	be := newRegBE()
	ctx := &kernel.Context{
		B: be, Pid: 4242,
		Transport: LinuxAMD64Transport{},
		Table:     NewAMD64SyscallTable(kernel.DefaultHandlers()),
		Codecs:    LinuxX8664Codecs{},
	}

	be.regs[amd64.RAX] = 9999 // not in the table
	ctx.Dispatch()
	if want := negErrno(kernel.ENOSYS); be.regs[amd64.RAX] != want {
		t.Fatalf("unimplemented syscall RAX = %#x, want %#x (-ENOSYS)", be.regs[amd64.RAX], want)
	}

	be.regs[amd64.RAX] = SYSX_getpid
	ctx.Dispatch()
	if be.regs[amd64.RAX] != 4242 {
		t.Fatalf("getpid RAX = %d, want 4242", be.regs[amd64.RAX])
	}
}

// TestAMD64TableCoversHandlerSet pins that every handler bound in the ARM64
// table is also bound in the AMD64 table (the syscall SEMANTICS are the same
// Linux; only the numbering differs).
func TestAMD64TableCoversHandlerSet(t *testing.T) {
	h := kernel.DefaultHandlers()
	a64 := NewARM64SyscallTable(h)
	x64 := NewAMD64SyscallTable(h)
	if len(a64.Handlers) != len(x64.Handlers) {
		t.Fatalf("handler count: arm64=%d amd64=%d — the tables must bind the same handler set", len(a64.Handlers), len(x64.Handlers))
	}
	// The tables must NOT share numbers for the same name (x86-64 is not
	// asm-generic): spot-check the classic divergences.
	pairs := map[string][2]uint64{
		"write":   {SYS_write, SYSX_write},     // 64 vs 1
		"mmap":    {SYS_mmap, SYSX_mmap},       // 222 vs 9
		"openat":  {SYS_openat, SYSX_openat},   // 56 vs 257
		"getpid":  {SYS_getpid, SYSX_getpid},   // 172 vs 39
		"statx":   {SYS_statx, SYSX_statx},     // 291 vs 332
		"uname":   {SYS_uname, SYSX_uname},     // 160 vs 63
		"getcwd":  {SYS_getcwd, SYSX_getcwd},   // 17 vs 79
		"faccess": {SYS_faccessat, SYSX_faccessat}, // 48 vs 269
	}
	for name, p := range pairs {
		if p[0] == p[1] {
			t.Errorf("%s: arm64 and amd64 numbers coincide (%d) — suspicious for non-asm-generic x86-64", name, p[0])
		}
		// Each number must be bound in its own table.
		if _, ok := a64.Handlers[p[0]]; !ok {
			t.Errorf("%s: arm64 number %d not bound in the ARM64 table", name, p[0])
		}
		if _, ok := x64.Handlers[p[1]]; !ok {
			t.Errorf("%s: amd64 number %d not bound in the AMD64 table", name, p[1])
		}
	}
}
