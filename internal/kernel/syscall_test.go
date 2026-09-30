package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/vfs"
)

// fakeBE is an emu.Backend test double for the syscall layer: a register file
// plus a sparse page store, so MemRead/MemWrite round-trip like a real engine.
// It implements ONLY the Backend core interface (P2.5a): the kernel never calls
// hooks or context ops, so the fake carries no capability interfaces — any
// stray capability use is caught by a failed type assertion, not a stub return.
// Core operations the kernel never calls return emu.ErrUnsupported.
type fakeBE struct {
	regs  map[emu.Reg]uint64
	pages map[uint64][]byte

	regReads  int // P2 purity checks: handlers must not touch registers
	regWrites int

	mapErr   error // MemMap fails while set
	stopped  bool
	unmapped []struct{ addr, size uint64 }
}

func newFakeBE() *fakeBE {
	return &fakeBE{regs: map[emu.Reg]uint64{}, pages: map[uint64][]byte{}}
}

func (f *fakeBE) page(a uint64) []byte {
	pg := a &^ 0xfff
	p := f.pages[pg]
	if p == nil {
		p = make([]byte, 0x1000)
		f.pages[pg] = p
	}
	return p
}

func (f *fakeBE) RegRead(reg emu.Reg) (uint64, error)  { f.regReads++; return f.regs[reg], nil }
func (f *fakeBE) RegWrite(reg emu.Reg, v uint64) error { f.regWrites++; f.regs[reg] = v; return nil }

func (f *fakeBE) MemMap(addr emu.GuestAddr, size uint64, _ int) error {
	if f.mapErr != nil {
		return f.mapErr
	}
	a0 := uint64(addr) // GuestAddr→raw：fake 的页表算术用 uint64
	for a := a0 &^ 0xfff; a < a0+size; a += 0x1000 {
		f.page(a)
	}
	return nil
}
func (f *fakeBE) MemUnmap(addr emu.GuestAddr, size uint64) error {
	a0 := uint64(addr) // GuestAddr→raw
	f.unmapped = append(f.unmapped, struct{ addr, size uint64 }{a0, size})
	for pg := a0 &^ 0xfff; pg < a0+size; pg += 0x1000 {
		delete(f.pages, pg)
	}
	return nil
}
func (f *fakeBE) MemProtect(_ emu.GuestAddr, _ uint64, _ int) error { return nil }
func (f *fakeBE) MemWrite(addr emu.GuestAddr, data []byte) error {
	a0 := uint64(addr) // GuestAddr→raw
	for i, b := range data {
		a := a0 + uint64(i)
		f.page(a)[a&0xfff] = b
	}
	return nil
}
func (f *fakeBE) MemRead(addr emu.GuestAddr, size uint64) ([]byte, error) {
	a0 := uint64(addr) // GuestAddr→raw
	out := make([]byte, size)
	for i := range out {
		a := a0 + uint64(i)
		out[i] = f.page(a)[a&0xfff]
	}
	return out, nil
}
func (f *fakeBE) Stop() error { f.stopped = true; return nil }

func (f *fakeBE) MemMapPtr(_ emu.GuestAddr, _ uint64, _ int, _ unsafe.Pointer) error {
	return emu.ErrUnsupported
}
func (f *fakeBE) InstallTrap(_ emu.TrapKind, _ emu.TrapHandler) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) Start(_, _ emu.GuestAddr) error { return emu.ErrUnsupported }
func (f *fakeBE) StartCount(_, _ emu.GuestAddr, _ uint64) error {
	return emu.ErrUnsupported
}
func (f *fakeBE) Close() error { return nil }

// testTransport is a test double for kernel.SyscallTransport mirroring the
// Linux/AArch64 encoding (x8 number, x0..x5 args, x0 = value / -errno) so the
// kernel's internal tests can exercise Dispatch end-to-end. Kernel's internal
// tests may NOT import the real implementation (platform/android imports
// kernel; Go forbids a package's internal tests from creating that cycle) —
// the REAL transport's encoding is pinned by the platform/android test suite.
type testTransport struct{}

func (testTransport) Decode(b emu.Backend) (SyscallFrame, error) {
	var f SyscallFrame
	num, err := b.RegRead(arm64.X8)
	if err != nil {
		return f, err
	}
	f.Num = num
	for i, r := range []emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5} {
		f.Args[i], _ = b.RegRead(r)
	}
	f.NArg = 6
	return f, nil
}

func (testTransport) EncodeResult(b emu.Backend, r Result) error {
	v := r.Value
	if r.Errno != 0 {
		v = uint64(-int64(r.Errno))
	}
	return b.RegWrite(arm64.X0, v)
}

// captureCodec is a StructCodecs test double: it records the SEMANTIC struct
// values handlers hand to the codec instead of asserting guest byte offsets —
// layout is the platform's contract (pinned by platform/android tests), what
// kernel tests must pin is the semantic content (DESIGN.md invariant 7).
// Sizes return the real asm-generic LP64 sizes so handler buffer allocation
// and the writev stride behave exactly as in production; DecodeIovec decodes
// for real because SysWritev consumes the decoded fields.
type captureCodec struct {
	stat     Stat
	statx    Statx
	timespec Timespec
	timeval  Timeval
	sysinfo  Sysinfo
	rlimit   Rlimit
}

func (c *captureCodec) StatSize() int     { return 128 }
func (c *captureCodec) StatxSize() int    { return 256 }
func (c *captureCodec) TimespecSize() int { return 16 }
func (c *captureCodec) TimevalSize() int  { return 16 }
func (c *captureCodec) SysinfoSize() int  { return 128 }
func (c *captureCodec) RlimitSize() int   { return 16 }
func (c *captureCodec) IovecSize() int    { return 16 }

func (c *captureCodec) EncodeStat(_ []byte, s Stat) error         { c.stat = s; return nil }
func (c *captureCodec) EncodeStatx(_ []byte, s Statx) error       { c.statx = s; return nil }
func (c *captureCodec) EncodeTimespec(_ []byte, t Timespec) error { c.timespec = t; return nil }
func (c *captureCodec) EncodeTimeval(_ []byte, t Timeval) error   { c.timeval = t; return nil }
func (c *captureCodec) EncodeSysinfo(_ []byte, s Sysinfo) error   { c.sysinfo = s; return nil }
func (c *captureCodec) EncodeRlimit(_ []byte, r Rlimit) error     { c.rlimit = r; return nil }

func (c *captureCodec) DecodeIovec(src []byte) (Iovec, error) {
	return Iovec{
		Base: binary.LittleEndian.Uint64(src[0:]),
		Len:  binary.LittleEndian.Uint64(src[8:]),
	}, nil
}

// Synthetic dispatch numbers for the kernel's internal tests: arbitrary small
// integers, deliberately NOT the Android/AArch64 assignments. The dispatch
// mechanism and handler semantics are number-agnostic; the real number ->
// handler binding is pinned by platform/android's table tests (P4b).
const (
	nrGetpid uint64 = iota + 1
	nrGetppid
	nrGettid
	nrGetuid
	nrGeteuid
	nrSetTidAddress
	nrSchedYield
	nrSetRobustList
	nrRtSigaction
	nrRtSigprocmask
	nrPrctl
	nrMadvise
	nrSchedGetaffinity
	nrMmap
	nrMunmap
	nrMprotect
	nrBrk
	nrExit
	nrExitGroup
	nrOpenat
	nrClose
	nrRead
	nrWrite
	nrWritev
	nrReadlinkat
	nrNewfstatat
	nrFstat
	nrFaccessat
	nrMkdirat
	nrLseek
	nrGetcwd
	nrGetdents64
	nrClockGettime
	nrGettimeofday
	nrUname
	nrSysinfo
	nrGetrandom
	nrPrlimit64
	nrFutex
	nrIoctl
	nrStatx
)

// syntheticTable binds the synthetic numbers above to the real semantic
// handlers, taken field-by-field from DefaultHandlers() — the same handlers
// the Android table binds, only the numbers differ.
func syntheticTable() *Table {
	h := DefaultHandlers()
	return &Table{
		Handlers: map[uint64]Handler{
			nrGetpid: h.Getpid, nrGetppid: h.Getppid, nrGettid: h.Gettid,
			nrGetuid: h.Getuid, nrGeteuid: h.Geteuid,
			nrSetTidAddress: h.SetTidAddress, nrSchedYield: h.SchedYield,
			nrSetRobustList: h.SetRobustList, nrRtSigaction: h.RtSigaction,
			nrRtSigprocmask: h.RtSigprocmask, nrPrctl: h.Prctl,
			nrMadvise: h.Madvise, nrSchedGetaffinity: h.SchedGetaffinity,
			nrMmap: h.Mmap, nrMunmap: h.Munmap, nrMprotect: h.Mprotect,
			nrBrk: h.Brk, nrExit: h.Exit, nrExitGroup: h.ExitGroup,
			nrOpenat: h.Openat, nrClose: h.Close, nrRead: h.Read,
			nrWrite: h.Write, nrWritev: h.Writev, nrReadlinkat: h.Readlinkat,
			nrNewfstatat: h.Newfstatat, nrFstat: h.Fstat,
			nrFaccessat: h.Faccessat, nrMkdirat: h.Mkdirat, nrLseek: h.Lseek,
			nrGetcwd: h.Getcwd, nrGetdents64: h.Getdents64,
			nrClockGettime: h.ClockGettime, nrGettimeofday: h.Gettimeofday,
			nrUname: h.Uname, nrSysinfo: h.Sysinfo, nrGetrandom: h.Getrandom,
			nrPrlimit64: h.Prlimit64, nrFutex: h.Futex, nrIoctl: h.Ioctl,
			nrStatx: h.Statx,
		},
		Names: map[uint64]string{
			nrGetpid: "getpid", nrGetppid: "getppid", nrGettid: "gettid",
			nrGetuid: "getuid", nrGeteuid: "geteuid",
			nrSetTidAddress: "set_tid_address", nrSchedYield: "sched_yield",
			nrSetRobustList: "set_robust_list", nrRtSigaction: "rt_sigaction",
			nrRtSigprocmask: "rt_sigprocmask", nrPrctl: "prctl",
			nrMadvise: "madvise", nrSchedGetaffinity: "sched_getaffinity",
			nrMmap: "mmap", nrMunmap: "munmap", nrMprotect: "mprotect",
			nrBrk: "brk", nrExit: "exit", nrExitGroup: "exit_group",
			nrOpenat: "openat", nrClose: "close", nrRead: "read",
			nrWrite: "write", nrWritev: "writev", nrReadlinkat: "readlinkat",
			nrNewfstatat: "newfstatat", nrFstat: "fstat",
			nrFaccessat: "faccessat", nrMkdirat: "mkdirat", nrLseek: "lseek",
			nrGetcwd: "getcwd", nrGetdents64: "getdents64",
			nrClockGettime: "clock_gettime", nrGettimeofday: "gettimeofday",
			nrUname: "uname", nrSysinfo: "sysinfo", nrGetrandom: "getrandom",
			nrPrlimit64: "prlimit64", nrFutex: "futex", nrIoctl: "ioctl",
			nrStatx: "statx",
		},
	}
}

// kernelCtxt bundles a Context with its fake backend for concise dispatching.
type kernelCtxt struct {
	be  *fakeBE
	ctx *Context
	cc  *captureCodec
}

const (
	testPid     = 4242
	testFile    = "/data/local/test.bin"
	testContent = "hello world"
	// scratch is a guest address used for syscall in/out buffers; the fake
	// backend auto-materializes pages, so no explicit mapping is needed.
	scratch = 0x70000000
)

func newKernelCtxt(t testing.TB) *kernelCtxt {
	t.Helper()
	be := newFakeBE()
	v := vfs.New(t.TempDir(), testPid, "testproc")
	v.SetFallback(func(guest string) ([]byte, bool, error) {
		if guest == testFile {
			return []byte(testContent), true, nil
		}
		return nil, false, nil
	})
	cc := &captureCodec{}
	return &kernelCtxt{
		be: be,
		cc: cc,
		ctx: &Context{
			B: be, Mem: memory.NewSpace(), VFS: v, Pid: testPid,
			// P2: Dispatch requires the injected platform personality — a
			// SYNTHETIC table (P4b: kernel tests no longer use the real
			// Android number binding) plus test-double transport/codecs; the
			// real LinuxARM64Transport / AsmGenericLP64Codecs /
			// NewARM64SyscallTable binding are pinned by the platform/android
			// test suite.
			Transport: testTransport{},
			Table:     syntheticTable(),
			Codecs:    cc,
			// P7.5b: the utsname identity is platform-supplied data; the
			// test persona stands in for what the android factory binds.
			Uname: &UnameInfo{
				Sysname: "Linux", Nodename: "localhost",
				Release: "4.14.117-golem", Version: "#1 SMP PREEMPT",
				Machine: "aarch64", Domainname: "localdomain",
			},
		},
	}
}

// call dispatches syscall num with the given x0..x5 args and returns x0 as int64.
func (k *kernelCtxt) call(num uint64, args ...uint64) int64 {
	k.be.regs[arm64.X8] = num
	regs := []emu.Reg{arm64.X0, arm64.X1, arm64.X2, arm64.X3, arm64.X4, arm64.X5}
	for i, r := range regs {
		var v uint64
		if i < len(args) {
			v = args[i]
		}
		k.be.regs[r] = v
	}
	k.ctx.Dispatch()
	return int64(k.be.regs[arm64.X0])
}

// putStr writes a NUL-terminated string into guest memory, returning its address.
func (k *kernelCtxt) putStr(addr uint64, s string) uint64 {
	if err := k.be.MemWrite(emu.GuestAddr(addr), append([]byte(s), 0)); err != nil {
		panic(err)
	}
	return addr
}

func (k *kernelCtxt) memAt(addr, n uint64) []byte {
	b, err := k.be.MemRead(emu.GuestAddr(addr), n)
	if err != nil {
		panic(err)
	}
	return b
}

// openTestFile opens the VFS-backed test file read-only and returns its fd.
func (k *kernelCtxt) openTestFile() int64 {
	return k.call(nrOpenat, 0, k.putStr(scratch+0x800, testFile), 0)
}

// --- Dispatch semantics ---

func TestDispatchArgsAndResult(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(nrGetpid); got != testPid {
		t.Fatalf("getpid = %d, want %d", got, testPid)
	}
	// getcwd proves x0/x1 args are read: it writes into the buffer arg and
	// returns its length including the NUL.
	ret := k.call(nrGetcwd, scratch, 64)
	if ret != 2 {
		t.Fatalf("getcwd = %d, want 2", ret)
	}
	if got := k.memAt(scratch, 2); string(got) != "/\x00" {
		t.Fatalf("getcwd buf = %q, want %q", got, "/\x00")
	}
	// buffer too small -> -int64(ERANGE)
	if got := k.call(nrGetcwd, scratch, 1); got != -int64(ERANGE) {
		t.Fatalf("getcwd(tiny buf) = %d, want %d", got, -int64(ERANGE))
	}
}

func TestDispatchUnimplementedSyscall(t *testing.T) {
	k := newKernelCtxt(t)
	k.be.regs[arm64.X0] = 0xdeadbeef // must be overwritten by the result
	ret := k.call(9999)
	if ret != -int64(ENOSYS) {
		t.Fatalf("unimplemented syscall = %d, want %d", ret, -int64(ENOSYS))
	}
	want := int64(-int64(ENOSYS))
	if got := k.be.regs[arm64.X0]; got != uint64(want) {
		t.Fatalf("x0 = %#x, want two's-complement of %d", got, -int64(ENOSYS))
	}
}

// TestSyntheticTableDispatch proves the dispatch mechanism is number-agnostic:
// a test-only handler bound at an arbitrary number is routed purely by table
// lookup, and an unknown number falls through to ENOSYS. The real Android
// number -> handler binding (and its Names consistency) is pinned by the
// platform/android table tests.
func TestSyntheticTableDispatch(t *testing.T) {
	k := newKernelCtxt(t)
	calls := 0
	k.ctx.Table.Handlers[424242] = func(_ *Context, f *SyscallFrame) Result {
		calls++
		return Result{Value: f.Args[0] + 1}
	}
	if got := k.call(424242, 41); got != 42 {
		t.Fatalf("synthetic handler = %d, want 42", got)
	}
	if calls != 1 {
		t.Fatalf("synthetic handler called %d times, want 1", calls)
	}
	if got := k.call(424243); got != -int64(ENOSYS) {
		t.Fatalf("unknown synthetic number = %d, want %d", got, -int64(ENOSYS))
	}
}

func TestTrivialSyscalls(t *testing.T) {
	k := newKernelCtxt(t)
	cases := []struct {
		name string
		num  uint64
		args [6]uint64
		want int64
	}{
		{"getppid", nrGetppid, [6]uint64{}, 1},
		{"getuid", nrGetuid, [6]uint64{}, 10000},
		{"geteuid", nrGeteuid, [6]uint64{}, 10000},
		{"gettid", nrGettid, [6]uint64{}, testPid},
		{"sched_yield", nrSchedYield, [6]uint64{}, 0},
		{"set_tid_address", nrSetTidAddress, [6]uint64{}, testPid},
		{"set_robust_list", nrSetRobustList, [6]uint64{}, 0},
		{"rt_sigaction", nrRtSigaction, [6]uint64{}, 0},
		{"rt_sigprocmask", nrRtSigprocmask, [6]uint64{}, 0},
		{"prctl", nrPrctl, [6]uint64{}, 0},
		{"madvise", nrMadvise, [6]uint64{}, 0},
		{"futex", nrFutex, [6]uint64{0x1000, 1, 1}, 0},
		{"ioctl", nrIoctl, [6]uint64{1, 0x5401, scratch}, 0},
		{"getdents64", nrGetdents64, [6]uint64{100, scratch, 0x1000}, 0},
	}
	for _, tc := range cases {
		if got := k.call(tc.num, tc.args[:]...); got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// --- File IO ---

func TestOpenatReadClose(t *testing.T) {
	k := newKernelCtxt(t)

	if got := k.call(nrOpenat, 0, k.putStr(scratch+0x900, "/no/such/file"), 0); got != -int64(ENOENT) {
		t.Fatalf("openat(missing) = %d, want %d", got, -int64(ENOENT))
	}

	fd := k.openTestFile()
	if fd != 100 {
		t.Fatalf("first fd = %d, want 100", fd)
	}

	// partial read
	if got := k.call(nrRead, uint64(fd), scratch, 5); got != 5 {
		t.Fatalf("read = %d, want 5", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "hello" {
		t.Fatalf("read buf = %q, want %q", got, "hello")
	}
	// oversized read truncates to the remaining bytes
	if got := k.call(nrRead, uint64(fd), scratch, 100); got != int64(len(testContent))-5 {
		t.Fatalf("oversized read = %d, want %d", got, len(testContent)-5)
	}
	if got := k.memAt(scratch, 6); string(got) != " world" {
		t.Fatalf("read buf = %q, want %q", got, " world")
	}
	// EOF
	if got := k.call(nrRead, uint64(fd), scratch, 10); got != 0 {
		t.Fatalf("read at EOF = %d, want 0", got)
	}

	if got := k.call(nrClose, uint64(fd)); got != 0 {
		t.Fatalf("close = %d, want 0", got)
	}
	if got := k.call(nrRead, uint64(fd), scratch, 1); got != -int64(EBADF) {
		t.Fatalf("read on closed fd = %d, want %d", got, -int64(EBADF))
	}

	// fds allocate monotonically from 100
	if fd2 := k.openTestFile(); fd2 != 101 {
		t.Fatalf("second fd = %d, want 101", fd2)
	}
}

func TestLseek(t *testing.T) {
	k := newKernelCtxt(t)
	fd := k.openTestFile()

	cases := []struct {
		name   string
		off    int64
		whence uint64
		want   int64
	}{
		{"SEEK_SET", 6, 0, 6},
		{"SEEK_CUR", -3, 1, 3},
		{"SEEK_END", -5, 2, int64(len(testContent)) - 5},
	}
	for _, tc := range cases {
		if got := k.call(nrLseek, uint64(fd), uint64(tc.off), tc.whence); got != tc.want {
			t.Errorf("%s: lseek = %d, want %d", tc.name, got, tc.want)
		}
	}
	// A negative resulting position returns -int64(EINVAL) and leaves the fd's
	// position unchanged (real kernels reject the seek, not return a negative
	// offset that reads as an errno).
	seekBack := int64(-100)
	if got := k.call(nrLseek, uint64(fd), uint64(seekBack), 2); got != -int64(EINVAL) {
		t.Errorf("SEEK_END past start = %d, want -EINVAL", got)
	}
	if f := k.ctx.files[int32(fd)]; f == nil || f.pos != 0 {
		t.Fatal("rejected lseek must leave the fd at position 0")
	}
	// unknown whence -> -int64(EINVAL)
	if got := k.call(nrLseek, uint64(fd), 0, 9); got != -int64(EINVAL) {
		t.Errorf("unknown whence = %d, want -EINVAL", got)
	}

	// seek back and read to prove the position took effect
	if got := k.call(nrLseek, uint64(fd), 6, 0); got != 6 {
		t.Fatalf("lseek = %d, want 6", got)
	}
	if got := k.call(nrRead, uint64(fd), scratch, 5); got != 5 {
		t.Fatalf("read after seek = %d, want 5", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "world" {
		t.Fatalf("read after seek = %q, want %q", got, "world")
	}

	if got := k.call(nrLseek, 999, 0, 0); got != -int64(EBADF) {
		t.Fatalf("lseek on unknown fd = %d, want %d", got, -int64(EBADF))
	}
}

func TestWritableOverlay(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/out.bin"

	fd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd != 100 {
		t.Fatalf("writable openat fd = %d, want 100", fd)
	}
	k.be.MemWrite(emu.GuestAddr(scratch), []byte("AB"))
	k.be.MemWrite(emu.GuestAddr(scratch+0x100), []byte("CD"))
	if got := k.call(nrWrite, uint64(fd), scratch, 2); got != 2 {
		t.Fatalf("write = %d, want 2", got)
	}
	if got := k.call(nrWrite, uint64(fd), scratch+0x100, 2); got != 2 {
		t.Fatalf("write = %d, want 2", got)
	}
	k.call(nrClose, uint64(fd))

	// read the overlay back through a fresh read-only fd
	fd2 := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), 0)
	if fd2 < 0 {
		t.Fatalf("reopen overlay = %d, want >= 0", fd2)
	}
	if got := k.call(nrRead, uint64(fd2), scratch+0x200, 16); got != 4 {
		t.Fatalf("read back = %d, want 4", got)
	}
	if got := k.memAt(scratch+0x200, 4); string(got) != "ABCD" {
		t.Fatalf("overlay content = %q, want %q", got, "ABCD")
	}

	// O_TRUNC resets the overlay
	fd3 := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT|oTRUNC)
	if fd3 < 0 {
		t.Fatalf("O_TRUNC openat = %d", fd3)
	}
	if got := k.call(nrNewfstatat, 0, k.putStr(scratch+0x800, wpath), scratch+0x400, 0); got != 0 {
		t.Fatalf("newfstatat truncated = %d, want 0", got)
	}
	if k.cc.stat.Size != 0 {
		t.Fatalf("truncated size = %d, want 0", k.cc.stat.Size)
	}
}

func TestWritev(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/iov.bin"
	fd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}

	// two iovecs: {"foo",3},{"bar",3}
	k.be.MemWrite(emu.GuestAddr(scratch+0x1000), []byte("foo"))
	k.be.MemWrite(emu.GuestAddr(scratch+0x1100), []byte("bar"))
	var iov [32]byte
	binary.LittleEndian.PutUint64(iov[0:], scratch+0x1000)
	binary.LittleEndian.PutUint64(iov[8:], 3)
	binary.LittleEndian.PutUint64(iov[16:], scratch+0x1100)
	binary.LittleEndian.PutUint64(iov[24:], 3)
	k.be.MemWrite(emu.GuestAddr(scratch+0x1200), iov[:])

	if got := k.call(nrWritev, uint64(fd), scratch+0x1200, 2); got != 6 {
		t.Fatalf("writev = %d, want 6", got)
	}
	k.call(nrClose, uint64(fd))

	fd2 := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), 0)
	if got := k.call(nrRead, uint64(fd2), scratch+0x200, 16); got != 6 {
		t.Fatalf("read back = %d, want 6", got)
	}
	if got := k.memAt(scratch+0x200, 6); string(got) != "foobar" {
		t.Fatalf("writev content = %q, want %q", got, "foobar")
	}
}

// --- brk / mmap ---

func TestBrk(t *testing.T) {
	k := newKernelCtxt(t)

	// query before any growth initializes the break at BrkBase
	if got := k.call(nrBrk, 0); got != BrkBase {
		t.Fatalf("brk(0) = %#x, want %#x", got, BrkBase)
	}
	// grow: new break returned, pages mapped on the backend
	want := uint64(BrkBase + 0x2345) // deliberately unaligned
	if got := k.call(nrBrk, want); got != int64(want) {
		t.Fatalf("brk(grow) = %#x, want %#x", uint64(got), want)
	}
	if k.ctx.BrkTop() != pageUp(want) {
		t.Fatalf("BrkTop = %#x, want %#x", k.ctx.BrkTop(), pageUp(want))
	}
	k.be.MemWrite(emu.GuestAddr(BrkBase), []byte("heap!"))
	if got := k.memAt(BrkBase, 5); string(got) != "heap!" {
		t.Fatalf("brk heap not writable on backend, got %q", got)
	}
	// shrink
	if got := k.call(nrBrk, BrkBase+0x1000); got != BrkBase+0x1000 {
		t.Fatalf("brk(shrink) = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
	// query returns the current break
	if got := k.call(nrBrk, 0); got != BrkBase+0x1000 {
		t.Fatalf("brk(0) after shrink = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
	// below BrkBase is a query too
	if got := k.call(nrBrk, 0x1000); got != BrkBase+0x1000 {
		t.Fatalf("brk(below base) = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
}

func TestMmap(t *testing.T) {
	k := newKernelCtxt(t)
	const protRW = emu.ProtRead | emu.ProtWrite

	a := k.call(nrMmap, 0, 0x1000, protRW, 0x22, 0, 0) // MAP_PRIVATE|MAP_ANONYMOUS
	if a != memory.MmapBase {
		t.Fatalf("first mmap = %#x, want %#x", uint64(a), uint64(memory.MmapBase))
	}
	b := k.call(nrMmap, 0, 0x2000, protRW, 0x22, 0, 0)
	if b != a+0x1000 {
		t.Fatalf("second mmap = %#x, want monotonic %#x", uint64(b), uint64(a+0x1000))
	}

	// mapped memory round-trips through the backend
	k.be.MemWrite(emu.GuestAddr(uint64(a)), []byte("mmap-data"))
	if got := k.memAt(uint64(a), 9); string(got) != "mmap-data" {
		t.Fatalf("mmap memory = %q, want %q", got, "mmap-data")
	}
	if _, ok := k.ctx.Mem.Find(uint64(b)); !ok {
		t.Fatalf("mmap region %#x not tracked in memory.Space", uint64(b))
	}

	// MAP_FIXED maps exactly at the (page-rounded) hint
	const fixed = 0x50001000
	c := k.call(nrMmap, fixed+0x123, 0x1000, protRW, 0x22|mapFixed, 0, 0)
	if c != fixed {
		t.Fatalf("MAP_FIXED mmap = %#x, want %#x", uint64(c), uint64(fixed))
	}

	// munmap drops the region from the space bookkeeping
	if got := k.call(nrMunmap, uint64(b), 0x2000); got != 0 {
		t.Fatalf("munmap = %d, want 0", got)
	}
	if _, ok := k.ctx.Mem.Find(uint64(b)); ok {
		t.Fatalf("region %#x still tracked after munmap", uint64(b))
	}

	// backend map failure surfaces as -int64(ENOSYS)
	k.be.mapErr = errors.New("map refused")
	if got := k.call(nrMmap, 0, 0x1000, protRW, 0x22, 0, 0); got != -int64(ENOSYS) {
		t.Fatalf("mmap with failing backend = %d, want %d", got, -int64(ENOSYS))
	}
}

func TestMprotect(t *testing.T) {
	k := newKernelCtxt(t)
	a := k.call(nrMmap, 0, 0x1000, emu.ProtRead|emu.ProtWrite, 0x22, 0, 0)
	if a < 0 {
		t.Fatalf("mmap = %d", a)
	}
	if got := k.call(nrMprotect, uint64(a), 0x1000, emu.ProtRead); got != 0 {
		t.Fatalf("mprotect = %d, want 0", got)
	}
}

// --- stat family ---

func TestStatFamily(t *testing.T) {
	k := newKernelCtxt(t)
	buf := uint64(scratch + 0x400)

	// regular file via newfstatat — the codec capture pins the SEMANTIC struct
	// content; byte offsets are the platform codec's contract (android tests).
	if got := k.call(nrNewfstatat, 0, k.putStr(scratch+0x800, testFile), buf, 0); got != 0 {
		t.Fatalf("newfstatat = %d, want 0", got)
	}
	if k.cc.stat.Mode != 0x81a4 {
		t.Errorf("st_mode = %#o, want %#o (S_IFREG|0644)", k.cc.stat.Mode, 0x81a4)
	}
	if k.cc.stat.Size != uint64(len(testContent)) {
		t.Errorf("st_size = %d, want %d", k.cc.stat.Size, len(testContent))
	}

	// missing path
	if got := k.call(nrNewfstatat, 0, k.putStr(scratch+0x800, "/nope"), buf, 0); got != -int64(ENOENT) {
		t.Fatalf("newfstatat(missing) = %d, want %d", got, -int64(ENOENT))
	}

	// directory created via mkdirat stats as a dir
	if got := k.call(nrMkdirat, 0, k.putStr(scratch+0x800, "/data/local/dir"), 0755); got != 0 {
		t.Fatalf("mkdirat = %d, want 0", got)
	}
	if got := k.call(nrNewfstatat, 0, k.putStr(scratch+0x800, "/data/local/dir"), buf, 0); got != 0 {
		t.Fatalf("newfstatat(dir) = %d, want 0", got)
	}
	if k.cc.stat.Mode != 0x41ed {
		t.Errorf("dir st_mode = %#o, want %#o (S_IFDIR|0755)", k.cc.stat.Mode, 0x41ed)
	}

	// fstat on an open fd
	fd := k.openTestFile()
	if got := k.call(nrFstat, uint64(fd), buf); got != 0 {
		t.Fatalf("fstat = %d, want 0", got)
	}
	if k.cc.stat.Size != uint64(len(testContent)) {
		t.Errorf("fstat st_size = %d, want %d", k.cc.stat.Size, len(testContent))
	}
	if got := k.call(nrFstat, 999, buf); got != -int64(EBADF) {
		t.Fatalf("fstat(bad fd) = %d, want %d", got, -int64(EBADF))
	}

	// statx ABI
	if got := k.call(nrStatx, 0, k.putStr(scratch+0x800, testFile), 0, 0, buf); got != 0 {
		t.Fatalf("statx = %d, want 0", got)
	}
	if k.cc.statx.Mode != 0x81a4 {
		t.Errorf("stx_mode = %#o, want %#o", k.cc.statx.Mode, 0x81a4)
	}
	if k.cc.statx.Size != uint64(len(testContent)) {
		t.Errorf("stx_size = %d, want %d", k.cc.statx.Size, len(testContent))
	}
	if got := k.call(nrStatx, 0, k.putStr(scratch+0x800, "/nope"), 0, 0, buf); got != -int64(ENOENT) {
		t.Fatalf("statx(missing) = %d, want %d", got, -int64(ENOENT))
	}
}

func TestFaccessat(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(nrFaccessat, 0, k.putStr(scratch+0x800, testFile), 0); got != 0 {
		t.Errorf("faccessat(existing) = %d, want 0", got)
	}
	if got := k.call(nrFaccessat, 0, k.putStr(scratch+0x900, "/nope"), 0); got != -int64(ENOENT) {
		t.Errorf("faccessat(missing) = %d, want %d", got, -int64(ENOENT))
	}
	// synthetic VFS file
	if got := k.call(nrFaccessat, 0, k.putStr(scratch+0xa00, "/proc/self/cmdline"), 0); got != 0 {
		t.Errorf("faccessat(synthetic) = %d, want 0", got)
	}
	// mkdirat'd directory
	k.call(nrMkdirat, 0, k.putStr(scratch+0xb00, "/data/local/dir"), 0755)
	if got := k.call(nrFaccessat, 0, k.putStr(scratch+0xb00, "/data/local/dir"), 0); got != 0 {
		t.Errorf("faccessat(dir) = %d, want 0", got)
	}
	// writable-overlay file
	fd := k.call(nrOpenat, 0, k.putStr(scratch+0xc00, "/data/local/w.bin"), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}
	if got := k.call(nrFaccessat, 0, k.putStr(scratch+0xc00, "/data/local/w.bin"), 0); got != 0 {
		t.Errorf("faccessat(overlay) = %d, want 0", got)
	}
}

// --- time determinism ---

func TestEpochPinnedTime(t *testing.T) {
	k := newKernelCtxt(t)
	k.ctx.Epoch = 1234567890

	if got := k.call(nrClockGettime, clockRealtime, scratch); got != 0 {
		t.Fatalf("clock_gettime = %d, want 0", got)
	}
	if k.cc.timespec.Sec != 1234567890 {
		t.Errorf("clock_gettime sec = %d, want 1234567890", k.cc.timespec.Sec)
	}
	if k.cc.timespec.Nsec != 0 {
		t.Errorf("clock_gettime nsec = %d, want 0 (pinned)", k.cc.timespec.Nsec)
	}

	// Semantic fix: in Epoch mode the monotonic clocks are zero-based (boot
	// time == epoch) instead of aliasing the wall clock — MONOTONIC measuring
	// "seconds since 1970" was never right and made uptime checks inconsistent.
	if got := k.call(nrClockGettime, clockMonotonic, scratch); got != 0 {
		t.Fatalf("clock_gettime(MONOTONIC) = %d, want 0", got)
	}
	if k.cc.timespec.Sec != 0 {
		t.Errorf("MONOTONIC sec = %d, want 0 (pinned: boot == epoch)", k.cc.timespec.Sec)
	}

	if got := k.call(nrGettimeofday, scratch+0x100, 0); got != 0 {
		t.Fatalf("gettimeofday = %d, want 0", got)
	}
	if k.cc.timeval.Sec != 1234567890 {
		t.Errorf("gettimeofday sec = %d, want 1234567890", k.cc.timeval.Sec)
	}
	if k.cc.timeval.Usec != 0 {
		t.Errorf("gettimeofday usec = %d, want 0 (pinned)", k.cc.timeval.Usec)
	}
}

// testClock is a fixed Clock: wall clock 3h42m after boot.
type testClock struct{}

var testClockBoot = time.Unix(1700000000, 0)

func (testClock) Now() time.Time      { return testClockBoot.Add(3*time.Hour + 42*time.Minute) }
func (testClock) BootTime() time.Time { return testClockBoot }

func TestClockIDDistribution(t *testing.T) {
	k := newKernelCtxt(t)
	k.ctx.Clock = testClock{}

	wantUptime := int64(3*3600 + 42*60)
	wallSec := testClock{}.Now().Unix()

	// realtime family -> wall clock
	for _, id := range []uint64{clockRealtime, clockRealtimeCoarse} {
		if got := k.call(nrClockGettime, id, scratch); got != 0 {
			t.Fatalf("clock_gettime(%d) = %d, want 0", id, got)
		}
		if k.cc.timespec.Sec != wallSec {
			t.Errorf("clockid %d sec = %d, want wall %d", id, k.cc.timespec.Sec, wallSec)
		}
	}
	// monotonic family -> time since boot
	for _, id := range []uint64{clockMonotonic, clockMonotonicRaw, clockMonotonicCoarse, clockBoottime} {
		if got := k.call(nrClockGettime, id, scratch); got != 0 {
			t.Fatalf("clock_gettime(%d) = %d, want 0", id, got)
		}
		if k.cc.timespec.Sec != wantUptime {
			t.Errorf("clockid %d sec = %d, want uptime %d", id, k.cc.timespec.Sec, wantUptime)
		}
	}
	// sysinfo uptime agrees with CLOCK_BOOTTIME (cross-check consistency)
	if got := k.call(nrSysinfo, scratch); got != 0 {
		t.Fatalf("sysinfo = %d, want 0", got)
	}
	if k.cc.sysinfo.UptimeSec != uint64(wantUptime) {
		t.Errorf("sysinfo uptime = %d, want %d", k.cc.sysinfo.UptimeSec, wantUptime)
	}
	// gettimeofday follows the wall clock
	if got := k.call(nrGettimeofday, scratch, 0); got != 0 {
		t.Fatalf("gettimeofday = %d, want 0", got)
	}
	if k.cc.timeval.Sec != wallSec || k.cc.timeval.Usec != 0 {
		t.Errorf("gettimeofday = %d.%d, want wall clock", k.cc.timeval.Sec, k.cc.timeval.Usec)
	}
}

func TestEpochZeroUsesHostClock(t *testing.T) {
	k := newKernelCtxt(t) // Epoch == 0
	if got := k.call(nrClockGettime, 0, scratch); got != 0 {
		t.Fatalf("clock_gettime = %d, want 0", got)
	}
	if k.cc.timespec.Sec == 0 {
		t.Error("clock_gettime with Epoch=0 must return a non-zero host time")
	}
}

// --- exit ---

func TestExit(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(nrExitGroup, 7); got != 0 {
		t.Fatalf("exit_group = %d, want 0", got)
	}
	if !k.ctx.Exited {
		t.Error("Exited must be set after exit_group")
	}
	if k.ctx.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", k.ctx.ExitCode)
	}
	if !k.be.stopped {
		t.Error("backend Stop must be called on exit_group")
	}

	k2 := newKernelCtxt(t)
	k2.call(nrExit, 0)
	if !k2.ctx.Exited || k2.ctx.ExitCode != 0 {
		t.Errorf("exit(0): Exited=%v ExitCode=%d", k2.ctx.Exited, k2.ctx.ExitCode)
	}
}

// --- Snapshot / Restore ---

func TestSnapshotRestore(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/snap.bin"

	// accumulate state: grow brk, open an fd, write an overlay file
	if got := k.call(nrBrk, BrkBase+0x2000); got != BrkBase+0x2000 {
		t.Fatalf("brk = %#x", uint64(got))
	}
	fd := k.openTestFile()
	wfd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	k.be.MemWrite(emu.GuestAddr(scratch), []byte("DATA"))
	k.call(nrWrite, uint64(wfd), scratch, 4)

	snap := k.ctx.Snapshot()

	// mutate everything mutable
	k.call(nrBrk, BrkBase+0x5000)
	k.openTestFile() // consumes another fd
	k.call(nrRead, uint64(fd), scratch+0x200, 5)
	k.be.MemWrite(emu.GuestAddr(scratch), []byte("MORE"))
	k.call(nrWrite, uint64(wfd), scratch, 4)
	k.ctx.Exited, k.ctx.ExitCode = true, 3
	k.call(nrMkdirat, 0, k.putStr(scratch+0x900, "/data/local/extra"), 0755)

	k.ctx.Restore(snap)

	if k.ctx.brkCur != BrkBase+0x2000 {
		t.Errorf("brkCur after restore = %#x, want %#x", k.ctx.brkCur, uint64(BrkBase+0x2000))
	}
	if k.ctx.BrkTop() != BrkBase+0x2000 {
		t.Errorf("BrkTop after restore = %#x, want %#x", k.ctx.BrkTop(), uint64(BrkBase+0x2000))
	}
	if len(k.be.unmapped) == 0 {
		t.Error("restore must unmap brk pages grown since the snapshot")
	}
	if k.ctx.Exited || k.ctx.ExitCode != 0 {
		t.Errorf("exit latch not rewound: Exited=%v ExitCode=%d", k.ctx.Exited, k.ctx.ExitCode)
	}
	if len(k.ctx.files) != 2 {
		t.Errorf("fd table after restore = %d entries, want 2", len(k.ctx.files))
	}
	if f := k.ctx.files[int32(fd)]; f == nil || f.pos != 0 {
		t.Errorf("fd %d pos after restore = %+v, want pos 0", fd, f)
	}
	if got := string(k.ctx.wfiles[wpath]); got != "DATA" {
		t.Errorf("overlay after restore = %q, want %q", got, "DATA")
	}
	if k.ctx.dirs["/data/local/extra"] {
		t.Error("mkdirat'd dir survived restore")
	}
	// the next fd allocation must reuse the rewound counter
	if fd3 := k.openTestFile(); fd3 != fd+2 {
		t.Errorf("fd after restore = %d, want %d", fd3, fd+2)
	}
	// snapshot state must be decoupled from later Context mutation
	k.ctx.wfiles[wpath][0] = 'X'
	if got := string(snap.wfiles[wpath]); got != "DATA" {
		t.Errorf("snapshot aliased by context mutation: %q", got)
	}
}

// --- getrandom ---

func TestGetrandom(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(nrGetrandom, scratch, 32, 0); got != 32 {
		t.Fatalf("getrandom = %d, want 32", got)
	}
	first := k.memAt(scratch, 32)
	if bytes.Count(first, []byte{0}) == 32 {
		t.Fatal("getrandom wrote all-zero buffer")
	}
	// NOTE: the stream is seeded from byte(addr ^ n) — only the low byte of the
	// address participates, so calls at addresses sharing a low byte (e.g.
	// page-strided buffers) produce identical streams. Flagged as a suspected
	// weakness; this test uses addresses that differ in the low byte.
	if got := k.call(nrGetrandom, scratch+1, 32, 0); got != 32 {
		t.Fatalf("getrandom #2 = %d, want 32", got)
	}
	if second := k.memAt(scratch+1, 32); bytes.Equal(first, second) {
		t.Error("two getrandom calls returned identical buffers")
	}
}

// --- misc info syscalls ---

func TestInfoSyscalls(t *testing.T) {
	k := newKernelCtxt(t)

	// uname: the platform-supplied identity, encoded verbatim ("Linux" at
	// off 0, machine at off 4*65).
	if got := k.call(nrUname, scratch); got != 0 {
		t.Fatalf("uname = %d, want 0", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "Linux" {
		t.Errorf("uname sysname = %q, want %q", got, "Linux")
	}
	if got := k.memAt(scratch+4*65, 7); string(got) != "aarch64" {
		t.Errorf("uname machine = %q, want %q", got, "aarch64")
	}
	// P7.5b: a platform that binds uname without an identity is a wiring
	// bug — fail loudly instead of fabricating values. (k.call returns the
	// transport wire encoding: Linux carries -errno.)
	saved := k.ctx.Uname
	k.ctx.Uname = nil
	if got := k.call(nrUname, scratch); got != -int64(EINVAL) {
		t.Errorf("uname without identity = %d, want -EINVAL(%d)", got, EINVAL)
	}
	k.ctx.Uname = saved

	// sysinfo: totalram
	if got := k.call(nrSysinfo, scratch); got != 0 {
		t.Fatalf("sysinfo = %d, want 0", got)
	}
	if k.cc.sysinfo.TotalRAM != 4*1024*1024*1024 {
		t.Errorf("sysinfo totalram = %d, want 4 GiB", k.cc.sysinfo.TotalRAM)
	}

	// readlinkat: known /proc symlink, truncation, unknown path
	n := k.call(nrReadlinkat, 0, k.putStr(scratch+0x800, "/proc/self/exe"), scratch+0x400, 256)
	if want := "/system/bin/app_process64"; n != int64(len(want)) || string(k.memAt(scratch+0x400, uint64(n))) != want {
		t.Errorf("readlinkat(exe) = %d %q, want %d %q", n, k.memAt(scratch+0x400, uint64(n)), len(want), want)
	}
	if got := k.call(nrReadlinkat, 0, k.putStr(scratch+0x800, "/proc/self/exe"), scratch+0x400, 4); got != 4 {
		t.Errorf("readlinkat(truncated) = %d, want 4", got)
	}
	if got := k.call(nrReadlinkat, 0, k.putStr(scratch+0x800, "/proc/self/unknown"), scratch+0x400, 256); got != -int64(ENOENT) {
		t.Errorf("readlinkat(unknown) = %d, want %d", got, -int64(ENOENT))
	}

	// sched_getaffinity
	if got := k.call(nrSchedGetaffinity, 0, 0, scratch); got != -int64(EINVAL) {
		t.Errorf("sched_getaffinity(size 0) = %d, want %d", got, -int64(EINVAL))
	}
	if got := k.call(nrSchedGetaffinity, 0, 8, scratch); got != 8 {
		t.Errorf("sched_getaffinity(8) = %d, want 8", got)
	}
	if m := k.memAt(scratch, 8); m[0] != 0xFF {
		t.Errorf("affinity mask[0] = %#x, want 0xFF", m[0])
	}
	// cpusetsize larger than 8 is clamped to 8
	if got := k.call(nrSchedGetaffinity, 0, 64, scratch); got != 8 {
		t.Errorf("sched_getaffinity(64) = %d, want 8 (clamped)", got)
	}

	// prlimit64: RLIMIT_STACK -> 8 MiB / 8 MiB written to old rlim
	if got := k.call(nrPrlimit64, 0, 3, 0, scratch); got != 0 {
		t.Fatalf("prlimit64 = %d, want 0", got)
	}
	if k.cc.rlimit.Cur != 8*1024*1024 {
		t.Errorf("rlimit cur = %d, want 8 MiB", k.cc.rlimit.Cur)
	}
	if k.cc.rlimit.Max != 8*1024*1024 {
		t.Errorf("rlimit max = %d, want 8 MiB", k.cc.rlimit.Max)
	}
	// unknown resource -> infinity
	k.call(nrPrlimit64, 0, 99, 0, scratch)
	if k.cc.rlimit.Cur != ^uint64(0) {
		t.Errorf("unknown rlimit cur = %#x, want RLIM_INFINITY", k.cc.rlimit.Cur)
	}
}

// --- semantics conformance (kernel-comparison round) ---

// close on an unopened fd must return -int64(EBADF) — real kernels reject it, and
// returning 0 is a fingerprint anti-emulation probes check for.
func TestCloseUnknownFdEBADF(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(nrClose, 0xdead); got != -int64(EBADF) {
		t.Errorf("close(0xdead) = %d, want %d", got, -int64(EBADF))
	}
	// a real close still works afterwards
	fd := k.openTestFile()
	if got := k.call(nrClose, uint64(fd)); got != 0 {
		t.Errorf("close(open fd) = %d, want 0", got)
	}
	// and the second close of the now-closed fd is EBADF again
	if got := k.call(nrClose, uint64(fd)); got != -int64(EBADF) {
		t.Errorf("double close = %d, want %d", got, -int64(EBADF))
	}
}

// writev must honor the fd's position (lseek then writev overwrites, not
// appends) — previously it appended unconditionally, corrupting data for
// guests that seek before vector writes.
func TestWritevHonorsPosition(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/posiov.bin"
	fd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}
	// write "0123456789" (10 bytes) at pos 0
	k.be.MemWrite(emu.GuestAddr(scratch+0x1000), []byte("0123456789"))
	if got := k.call(nrWrite, uint64(fd), scratch+0x1000, 10); got != 10 {
		t.Fatalf("write = %d, want 10", got)
	}
	// seek to 3, then writev {"AB",2},{"CD",2} — must overwrite bytes 3..7
	k.call(nrLseek, uint64(fd), 3, 0)
	k.be.MemWrite(emu.GuestAddr(scratch+0x1000), []byte("AB"))
	k.be.MemWrite(emu.GuestAddr(scratch+0x1100), []byte("CD"))
	var iov [32]byte
	binary.LittleEndian.PutUint64(iov[0:], scratch+0x1000)
	binary.LittleEndian.PutUint64(iov[8:], 2)
	binary.LittleEndian.PutUint64(iov[16:], scratch+0x1100)
	binary.LittleEndian.PutUint64(iov[24:], 2)
	k.be.MemWrite(emu.GuestAddr(scratch+0x1200), iov[:])
	if got := k.call(nrWritev, uint64(fd), scratch+0x1200, 2); got != 4 {
		t.Fatalf("writev = %d, want 4", got)
	}
	// read the whole file back: "012ABC789"
	fd2 := k.call(nrOpenat, 0, k.putStr(scratch+0x1400, wpath), 0)
	if got := k.call(nrRead, uint64(fd2), scratch+0x200, 16); got != 10 {
		t.Fatalf("read back = %d, want 10", got)
	}
	if got := string(k.memAt(scratch+0x200, 10)); got != "012ABCD789" {
		t.Fatalf("content after seek+writev = %q, want %q", got, "012ABCD789")
	}
}

// getrandom: deterministic mode must mix all parameters and a per-call
// counter (repeated identical calls must NOT return the same bytes).
func TestGetrandomDeterministicVaries(t *testing.T) {
	k := newKernelCtxt(t)
	const buf = scratch + 0x800
	if got := k.call(nrGetrandom, buf, 32, 0); got != 32 {
		t.Fatalf("getrandom = %d, want 32", got)
	}
	first := k.memAt(buf, 32)
	if got := k.call(nrGetrandom, buf, 32, 0); got != 32 {
		t.Fatalf("getrandom = %d, want 32", got)
	}
	second := k.memAt(buf, 32)
	same := 0
	for i := 0; i < 32; i++ {
		if first[i] == second[i] {
			same++
		}
	}
	if same == 32 {
		t.Fatal("two identical getrandom calls returned identical bytes — predictable-stream fingerprint")
	}
}

// --- P2 boundary: handlers produce pure Results ----------------------------

// Handlers consume a SyscallFrame and return a Result — they must never read
// the syscall number / argument registers, never write the result register,
// and never apply the Linux -errno encoding themselves (DESIGN.md invariant
// 6). The fakeBE counts register traffic; read/write are the spot-check.
func TestHandlersReturnPureResults(t *testing.T) {
	k := newKernelCtxt(t)

	frame := func(args ...uint64) *SyscallFrame {
		f := &SyscallFrame{NArg: uint8(len(args))}
		copy(f.Args[:], args)
		return f
	}

	// error path: pure Errno, no register traffic
	k.be.regReads, k.be.regWrites = 0, 0
	res := SysRead(k.ctx, frame(0xdead, scratch, 1)) // unknown fd
	if res != (Result{Errno: EBADF}) {
		t.Errorf("SysRead(bad fd) = %+v, want {Errno: EBADF}", res)
	}
	if k.be.regReads != 0 || k.be.regWrites != 0 {
		t.Errorf("SysRead touched registers: reads=%d writes=%d, want 0/0", k.be.regReads, k.be.regWrites)
	}

	// success path: pure Value
	fd := k.openTestFile()
	k.be.regReads, k.be.regWrites = 0, 0
	res = SysRead(k.ctx, frame(uint64(fd), scratch, 5))
	if res != (Result{Value: 5}) {
		t.Errorf("SysRead = %+v, want {Value: 5}", res)
	}
	if got := string(k.memAt(scratch, 5)); got != "hello" {
		t.Errorf("read buf = %q, want %q", got, "hello")
	}
	if k.be.regReads != 0 || k.be.regWrites != 0 {
		t.Errorf("SysRead touched registers: reads=%d writes=%d, want 0/0", k.be.regReads, k.be.regWrites)
	}

	// SysWrite on a writable overlay fd: pure Value, no registers
	wfd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, "/data/local/pure.bin"), oWRONLY|oCREAT)
	k.be.MemWrite(emu.GuestAddr(scratch), []byte("XY"))
	k.be.regReads, k.be.regWrites = 0, 0
	res = SysWrite(k.ctx, frame(uint64(wfd), scratch, 2))
	if res != (Result{Value: 2}) {
		t.Errorf("SysWrite = %+v, want {Value: 2}", res)
	}
	if k.be.regReads != 0 || k.be.regWrites != 0 {
		t.Errorf("SysWrite touched registers: reads=%d writes=%d, want 0/0", k.be.regReads, k.be.regWrites)
	}
}
