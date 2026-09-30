package android

import (
	"testing"

	"github.com/isesword/golem/internal/arch/arm32"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
)

// --- Decode: r7 number + r0..r5 args, NArg=6 ---

// TestLinuxARM32TransportDecode pins the ARM EABI syscall transport: r7 is
// the syscall number, arguments come verbatim from r0..r5.
func TestLinuxARM32TransportDecode(t *testing.T) {
	be := newRegBE()
	be.regs[arm32.R7] = SYSA_mmap2
	argRegs := []emu.Reg{arm32.R0, arm32.R1, arm32.R2, arm32.R3, arm32.R4, arm32.R5}
	for i, r := range argRegs {
		be.regs[r] = uint64(0x100 * (i + 1))
	}
	be.regs[arm32.R6] = 0xbaad // decoy: not an argument register
	f, err := LinuxARM32Transport{}.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	if f.Num != SYSA_mmap2 {
		t.Errorf("Num = %d, want %d (r7)", f.Num, SYSA_mmap2)
	}
	if f.NArg != 6 {
		t.Errorf("NArg = %d, want 6", f.NArg)
	}
	for i := 0; i < 6; i++ {
		if want := uint64(0x100 * (i + 1)); f.Args[i] != want {
			t.Errorf("Args[%d] = %#x, want %#x (r%d)", i, f.Args[i], want, i)
		}
	}
}

// TestLinuxARM32TransportReadaheadLayout pins the transport's raw-read
// contract against the ARM EABI 64-bit-pair rule: readahead(225)
// (int fd, loff_t offset, size_t count) puts fd in r0, leaves r1 UNUSED
// (the pair hole), the 64-bit offset in r2:r3, and count in r4. The
// transport must surface exactly that layout in Args[0..5] — re-aligning is
// the handler/binding layer's job, never the transport's.
func TestLinuxARM32TransportReadaheadLayout(t *testing.T) {
	be := newRegBE()
	be.regs[arm32.R7] = SYSA_readahead
	be.regs[arm32.R0] = 7          // fd
	be.regs[arm32.R1] = 0          // hole (EABI pair alignment)
	be.regs[arm32.R2] = 0x89abcdef // offset low
	be.regs[arm32.R3] = 0x01234567 // offset high
	be.regs[arm32.R4] = 0x1000     // count
	be.regs[arm32.R5] = 0
	f, err := LinuxARM32Transport{}.Decode(be)
	if err != nil {
		t.Fatal(err)
	}
	want := [6]uint64{7, 0, 0x89abcdef, 0x01234567, 0x1000, 0}
	for i, w := range want {
		if f.Args[i] != w {
			t.Fatalf("Args[%d] = %#x, want %#x — the transport must NOT re-align EABI pairs", i, f.Args[i], w)
		}
	}
	// Sanity: the pair really is the 64-bit offset.
	if off := f.Args[2] | f.Args[3]<<32; off != 0x0123456789abcdef {
		t.Fatalf("reconstructed offset = %#x, want 0x0123456789abcdef", off)
	}
}

func TestLinuxARM32TransportEncodeSuccess(t *testing.T) {
	be := newRegBE()
	be.regs[arm32.R0] = 0xdeadbeef // must be overwritten
	if err := (LinuxARM32Transport{}).EncodeResult(be, kernel.Result{Value: 42}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm32.R0]; got != 42 {
		t.Fatalf("r0 = %#x, want 42", got)
	}
}

func TestLinuxARM32TransportEncodeErrno(t *testing.T) {
	be := newRegBE()
	if err := (LinuxARM32Transport{}).EncodeResult(be, kernel.Result{Errno: kernel.ENOSYS}); err != nil {
		t.Fatal(err)
	}
	want := negErrno(kernel.ENOSYS)
	if got := be.regs[arm32.R0]; got != want {
		t.Fatalf("r0 = %#x, want %#x (-ENOSYS two's complement)", got, want)
	}
}

// Value2: the Linux ARM32 syscall ABI has ONE result register — r0.
func TestLinuxARM32TransportIgnoresValue2(t *testing.T) {
	be := newRegBE()
	if err := (LinuxARM32Transport{}).EncodeResult(be, kernel.Result{Value: 7, Value2: 9}); err != nil {
		t.Fatal(err)
	}
	if got := be.regs[arm32.R0]; got != 7 {
		t.Fatalf("r0 = %d, want 7", got)
	}
	if len(be.writes) != 1 {
		t.Fatalf("Linux transport must write exactly r0, wrote %d registers: %v", len(be.writes), be.writes)
	}
	if _, ok := be.writes[arm32.R1]; ok {
		t.Fatal("Value2 must NOT leak into r1 on the syscall ABI")
	}
}

// TestDispatchEndToEndARM32: unimplemented syscall -> -ENOSYS in r0;
// implemented syscall (getpid=20) -> its value, decoded/encoded through the
// ARM32 transport and the ARM32 number table.
func TestDispatchEndToEndARM32(t *testing.T) {
	be := newRegBE()
	ctx := &kernel.Context{
		B: be, Pid: 4242,
		Transport: LinuxARM32Transport{},
		Table:     NewARM32SyscallTable(kernel.DefaultHandlers()),
		Codecs:    LinuxARM32Codecs{},
	}

	be.regs[arm32.R7] = 9999 // not in the table
	ctx.Dispatch()
	if want := negErrno(kernel.ENOSYS); be.regs[arm32.R0] != want {
		t.Fatalf("unimplemented syscall r0 = %#x, want %#x (-ENOSYS)", be.regs[arm32.R0], want)
	}

	be.regs[arm32.R7] = SYSA_getpid
	ctx.Dispatch()
	if be.regs[arm32.R0] != 4242 {
		t.Fatalf("getpid r0 = %d, want 4242", be.regs[arm32.R0])
	}
}

// TestARM32TableCoversHandlerSet pins that the ARM32 table binds the same
// handler set as the ARM64 one (the syscall SEMANTICS are the same Linux;
// only the numbering differs) — with the deliberate exception of
// SYS_open/SYS_readlink/SYS_stat64-class legacy entry points, which are NOT
// bound because their argument shapes differ from the *at handlers
// (SYS_openat & co. are bound instead).
func TestARM32TableCoversHandlerSet(t *testing.T) {
	h := kernel.DefaultHandlers()
	a64 := NewARM64SyscallTable(h)
	a32 := NewARM32SyscallTable(h)
	if len(a64.Handlers) != len(a32.Handlers) {
		t.Fatalf("handler count: arm64=%d arm32=%d — the tables must bind the same handler set", len(a64.Handlers), len(a32.Handlers))
	}
	// The ARM32 numbers are the arch/arm legacy table, NOT asm-generic:
	// spot-check the classic divergences.
	pairs := map[string][2]uint64{
		"write":     {SYS_write, SYSA_write},         // 64 vs 4
		"mmap":      {SYS_mmap, SYSA_mmap2},          // 222 vs 192
		"openat":    {SYS_openat, SYSA_openat},       // 56 vs 322
		"getpid":    {SYS_getpid, SYSA_getpid},       // 172 vs 20
		"statx":     {SYS_statx, SYSA_statx},         // 291 vs 397
		"uname":     {SYS_uname, SYSA_uname},         // 160 vs 122
		"getcwd":    {SYS_getcwd, SYSA_getcwd},       // 17 vs 183
		"faccessat": {SYS_faccessat, SYSA_faccessat}, // 48 vs 334
		"futex":     {SYS_futex, SYSA_futex},         // 98 vs 240
	}
	for name, p := range pairs {
		if p[0] == p[1] {
			t.Errorf("%s: arm64 and arm32 numbers coincide (%d) — suspicious for the legacy ARM table", name, p[0])
		}
		if _, ok := a64.Handlers[p[0]]; !ok {
			t.Errorf("%s: arm64 number %d not bound in the ARM64 table", name, p[0])
		}
		if _, ok := a32.Handlers[p[1]]; !ok {
			t.Errorf("%s: arm32 number %d not bound in the ARM32 table", name, p[1])
		}
	}
}

// TestARM32TableLegacyShapesNotBound pins the deliberate gap: legacy
// pre-*at entry points whose argument shapes the semantic handlers do NOT
// implement (open/readlink/stat64/access use different argument slots than
// openat/readlinkat/newfstatat/faccessat) must stay UNBOUND — the guest gets
// a loud ENOSYS (visible in the trace) rather than a silently mis-decoded
// call. Bionic's arm32 libc uses the *at forms internally.
func TestARM32TableLegacyShapesNotBound(t *testing.T) {
	tbl := NewARM32SyscallTable(kernel.DefaultHandlers())
	for num, name := range map[uint64]string{
		SYSA_open:     "open",
		SYSA_readlink: "readlink",
		SYSA_stat64:   "stat64",
		SYSA_lstat64:  "lstat64",
		SYSA_access:   "access",
	} {
		if _, ok := tbl.Handlers[num]; ok {
			t.Errorf("%s (%d) must NOT be bound (its argument shape differs from the *at handler)", name, num)
		}
		if tbl.Name(num) != name {
			t.Errorf("Name(%d) = %q, want %q (unbound syscalls still get trace names)", num, tbl.Name(num), name)
		}
	}
}
