package kernel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/vfs"
)

// fakeBE is an emu.Backend test double for the syscall layer: a register file
// plus a sparse page store, so MemRead/MemWrite round-trip like a real engine.
// Operations the kernel never calls return emu.ErrUnsupported.
type fakeBE struct {
	regs  map[emu.Reg]uint64
	pages map[uint64][]byte

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

func (f *fakeBE) RegRead(reg emu.Reg) (uint64, error)  { return f.regs[reg], nil }
func (f *fakeBE) RegWrite(reg emu.Reg, v uint64) error { f.regs[reg] = v; return nil }
func (f *fakeBE) ReadGPRegs() ([34]uint64, error)      { return [34]uint64{}, emu.ErrUnsupported }

func (f *fakeBE) MemMap(addr, size uint64, _ int) error {
	if f.mapErr != nil {
		return f.mapErr
	}
	for a := addr &^ 0xfff; a < addr+size; a += 0x1000 {
		f.page(a)
	}
	return nil
}
func (f *fakeBE) MemUnmap(addr, size uint64) error {
	f.unmapped = append(f.unmapped, struct{ addr, size uint64 }{addr, size})
	for pg := addr &^ 0xfff; pg < addr+size; pg += 0x1000 {
		delete(f.pages, pg)
	}
	return nil
}
func (f *fakeBE) MemProtect(_, _ uint64, _ int) error { return nil }
func (f *fakeBE) MemWrite(addr uint64, data []byte) error {
	for i, b := range data {
		a := addr + uint64(i)
		f.page(a)[a&0xfff] = b
	}
	return nil
}
func (f *fakeBE) MemRead(addr, size uint64) ([]byte, error) {
	out := make([]byte, size)
	for i := range out {
		a := addr + uint64(i)
		out[i] = f.page(a)[a&0xfff]
	}
	return out, nil
}
func (f *fakeBE) Stop() error { f.stopped = true; return nil }

func (f *fakeBE) MemMapPtr(_, _ uint64, _ int, _ unsafe.Pointer) error {
	return emu.ErrUnsupported
}
func (f *fakeBE) HookCode(_, _ uint64, _ emu.CodeHookFunc) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) HookInterrupt(_ emu.InterruptHookFunc) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) HookMemInvalid(_ func(b emu.Backend, typ int, addr uint64, size int, value int64) bool) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) HookMemRead(_, _ uint64, _ func(b emu.Backend, addr uint64, size int)) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) HookMemWrite(_, _ uint64, _ func(b emu.Backend, addr uint64, size int, value int64)) (emu.HookHandle, error) {
	return nil, emu.ErrUnsupported
}
func (f *fakeBE) Start(_, _ uint64) error              { return emu.ErrUnsupported }
func (f *fakeBE) StartCount(_, _, _ uint64) error      { return emu.ErrUnsupported }
func (f *fakeBE) SaveContext() (emu.CPUContext, error) { return nil, emu.ErrUnsupported }
func (f *fakeBE) RestoreContext(emu.CPUContext) error  { return emu.ErrUnsupported }
func (f *fakeBE) FlushCache() error                    { return emu.ErrUnsupported }
func (f *fakeBE) Close() error                         { return nil }

// kernelCtxt bundles a Context with its fake backend for concise dispatching.
type kernelCtxt struct {
	be  *fakeBE
	ctx *Context
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
	return &kernelCtxt{
		be:  be,
		ctx: &Context{B: be, Mem: memory.NewSpace(), VFS: v, Pid: testPid},
	}
}

// call dispatches syscall num with the given x0..x5 args and returns x0 as int64.
func (k *kernelCtxt) call(num uint64, args ...uint64) int64 {
	k.be.regs[emu.RegX8] = num
	regs := []emu.Reg{emu.RegX0, emu.RegX1, emu.RegX2, emu.RegX3, emu.RegX4, emu.RegX5}
	for i, r := range regs {
		var v uint64
		if i < len(args) {
			v = args[i]
		}
		k.be.regs[r] = v
	}
	k.ctx.Dispatch()
	return int64(k.be.regs[emu.RegX0])
}

// putStr writes a NUL-terminated string into guest memory, returning its address.
func (k *kernelCtxt) putStr(addr uint64, s string) uint64 {
	if err := k.be.MemWrite(addr, append([]byte(s), 0)); err != nil {
		panic(err)
	}
	return addr
}

func (k *kernelCtxt) memAt(addr, n uint64) []byte {
	b, err := k.be.MemRead(addr, n)
	if err != nil {
		panic(err)
	}
	return b
}

// openTestFile opens the VFS-backed test file read-only and returns its fd.
func (k *kernelCtxt) openTestFile() int64 {
	return k.call(SYS_openat, 0, k.putStr(scratch+0x800, testFile), 0)
}

// --- Dispatch semantics ---

func TestDispatchArgsAndResult(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(SYS_getpid); got != testPid {
		t.Fatalf("getpid = %d, want %d", got, testPid)
	}
	// getcwd proves x0/x1 args are read: it writes into the buffer arg and
	// returns its length including the NUL.
	ret := k.call(SYS_getcwd, scratch, 64)
	if ret != 2 {
		t.Fatalf("getcwd = %d, want 2", ret)
	}
	if got := k.memAt(scratch, 2); string(got) != "/\x00" {
		t.Fatalf("getcwd buf = %q, want %q", got, "/\x00")
	}
	// buffer too small -> -ERANGE
	if got := k.call(SYS_getcwd, scratch, 1); got != -ERANGE {
		t.Fatalf("getcwd(tiny buf) = %d, want %d", got, -ERANGE)
	}
}

func TestDispatchUnimplementedSyscall(t *testing.T) {
	k := newKernelCtxt(t)
	k.be.regs[emu.RegX0] = 0xdeadbeef // must be overwritten by the result
	ret := k.call(9999)
	if ret != -ENOSYS {
		t.Fatalf("unimplemented syscall = %d, want %d", ret, -ENOSYS)
	}
	want := int64(-ENOSYS)
	if got := k.be.regs[emu.RegX0]; got != uint64(want) {
		t.Fatalf("x0 = %#x, want two's-complement of %d", got, -ENOSYS)
	}
}

func TestTableNamesConsistency(t *testing.T) {
	// Every implemented syscall should have a trace name.
	for num := range table {
		if Names[num] == "" {
			t.Errorf("table syscall #%d has no Names entry", num)
		}
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
		{"getppid", SYS_getppid, [6]uint64{}, 1},
		{"getuid", SYS_getuid, [6]uint64{}, 10000},
		{"geteuid", SYS_geteuid, [6]uint64{}, 10000},
		{"gettid", SYS_gettid, [6]uint64{}, testPid},
		{"sched_yield", SYS_sched_yield, [6]uint64{}, 0},
		{"set_tid_address", SYS_set_tid_address, [6]uint64{}, testPid},
		{"set_robust_list", SYS_set_robust_list, [6]uint64{}, 0},
		{"rt_sigaction", SYS_rt_sigaction, [6]uint64{}, 0},
		{"rt_sigprocmask", SYS_rt_sigprocmask, [6]uint64{}, 0},
		{"prctl", SYS_prctl, [6]uint64{}, 0},
		{"madvise", SYS_madvise, [6]uint64{}, 0},
		{"futex", SYS_futex, [6]uint64{0x1000, 1, 1}, 0},
		{"ioctl", SYS_ioctl, [6]uint64{1, 0x5401, scratch}, 0},
		{"getdents64", SYS_getdents64, [6]uint64{100, scratch, 0x1000}, 0},
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

	if got := k.call(SYS_openat, 0, k.putStr(scratch+0x900, "/no/such/file"), 0); got != -ENOENT {
		t.Fatalf("openat(missing) = %d, want %d", got, -ENOENT)
	}

	fd := k.openTestFile()
	if fd != 100 {
		t.Fatalf("first fd = %d, want 100", fd)
	}

	// partial read
	if got := k.call(SYS_read, uint64(fd), scratch, 5); got != 5 {
		t.Fatalf("read = %d, want 5", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "hello" {
		t.Fatalf("read buf = %q, want %q", got, "hello")
	}
	// oversized read truncates to the remaining bytes
	if got := k.call(SYS_read, uint64(fd), scratch, 100); got != int64(len(testContent))-5 {
		t.Fatalf("oversized read = %d, want %d", got, len(testContent)-5)
	}
	if got := k.memAt(scratch, 6); string(got) != " world" {
		t.Fatalf("read buf = %q, want %q", got, " world")
	}
	// EOF
	if got := k.call(SYS_read, uint64(fd), scratch, 10); got != 0 {
		t.Fatalf("read at EOF = %d, want 0", got)
	}

	if got := k.call(SYS_close, uint64(fd)); got != 0 {
		t.Fatalf("close = %d, want 0", got)
	}
	if got := k.call(SYS_read, uint64(fd), scratch, 1); got != -EBADF {
		t.Fatalf("read on closed fd = %d, want %d", got, -EBADF)
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
		if got := k.call(SYS_lseek, uint64(fd), uint64(tc.off), tc.whence); got != tc.want {
			t.Errorf("%s: lseek = %d, want %d", tc.name, got, tc.want)
		}
	}
	// A negative resulting position returns -EINVAL and leaves the fd's
	// position unchanged (real kernels reject the seek, not return a negative
	// offset that reads as an errno).
	seekBack := int64(-100)
	if got := k.call(SYS_lseek, uint64(fd), uint64(seekBack), 2); got != -EINVAL {
		t.Errorf("SEEK_END past start = %d, want -EINVAL", got)
	}
	if f := k.ctx.files[int32(fd)]; f == nil || f.pos != 0 {
		t.Fatal("rejected lseek must leave the fd at position 0")
	}
	// unknown whence -> -EINVAL
	if got := k.call(SYS_lseek, uint64(fd), 0, 9); got != -EINVAL {
		t.Errorf("unknown whence = %d, want -EINVAL", got)
	}

	// seek back and read to prove the position took effect
	if got := k.call(SYS_lseek, uint64(fd), 6, 0); got != 6 {
		t.Fatalf("lseek = %d, want 6", got)
	}
	if got := k.call(SYS_read, uint64(fd), scratch, 5); got != 5 {
		t.Fatalf("read after seek = %d, want 5", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "world" {
		t.Fatalf("read after seek = %q, want %q", got, "world")
	}

	if got := k.call(SYS_lseek, 999, 0, 0); got != -EBADF {
		t.Fatalf("lseek on unknown fd = %d, want %d", got, -EBADF)
	}
}

func TestWritableOverlay(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/out.bin"

	fd := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd != 100 {
		t.Fatalf("writable openat fd = %d, want 100", fd)
	}
	k.be.MemWrite(scratch, []byte("AB"))
	k.be.MemWrite(scratch+0x100, []byte("CD"))
	if got := k.call(SYS_write, uint64(fd), scratch, 2); got != 2 {
		t.Fatalf("write = %d, want 2", got)
	}
	if got := k.call(SYS_write, uint64(fd), scratch+0x100, 2); got != 2 {
		t.Fatalf("write = %d, want 2", got)
	}
	k.call(SYS_close, uint64(fd))

	// read the overlay back through a fresh read-only fd
	fd2 := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), 0)
	if fd2 < 0 {
		t.Fatalf("reopen overlay = %d, want >= 0", fd2)
	}
	if got := k.call(SYS_read, uint64(fd2), scratch+0x200, 16); got != 4 {
		t.Fatalf("read back = %d, want 4", got)
	}
	if got := k.memAt(scratch+0x200, 4); string(got) != "ABCD" {
		t.Fatalf("overlay content = %q, want %q", got, "ABCD")
	}

	// O_TRUNC resets the overlay
	fd3 := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT|oTRUNC)
	if fd3 < 0 {
		t.Fatalf("O_TRUNC openat = %d", fd3)
	}
	if got := k.call(SYS_newfstatat, 0, k.putStr(scratch+0x800, wpath), scratch+0x400, 0); got != 0 {
		t.Fatalf("newfstatat truncated = %d, want 0", got)
	}
	if size := binary.LittleEndian.Uint64(k.memAt(scratch+0x400+48, 8)); size != 0 {
		t.Fatalf("truncated size = %d, want 0", size)
	}
}

func TestWritev(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/iov.bin"
	fd := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}

	// two iovecs: {"foo",3},{"bar",3}
	k.be.MemWrite(scratch+0x1000, []byte("foo"))
	k.be.MemWrite(scratch+0x1100, []byte("bar"))
	var iov [32]byte
	binary.LittleEndian.PutUint64(iov[0:], scratch+0x1000)
	binary.LittleEndian.PutUint64(iov[8:], 3)
	binary.LittleEndian.PutUint64(iov[16:], scratch+0x1100)
	binary.LittleEndian.PutUint64(iov[24:], 3)
	k.be.MemWrite(scratch+0x1200, iov[:])

	if got := k.call(SYS_writev, uint64(fd), scratch+0x1200, 2); got != 6 {
		t.Fatalf("writev = %d, want 6", got)
	}
	k.call(SYS_close, uint64(fd))

	fd2 := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), 0)
	if got := k.call(SYS_read, uint64(fd2), scratch+0x200, 16); got != 6 {
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
	if got := k.call(SYS_brk, 0); got != BrkBase {
		t.Fatalf("brk(0) = %#x, want %#x", got, BrkBase)
	}
	// grow: new break returned, pages mapped on the backend
	want := uint64(BrkBase + 0x2345) // deliberately unaligned
	if got := k.call(SYS_brk, want); got != int64(want) {
		t.Fatalf("brk(grow) = %#x, want %#x", uint64(got), want)
	}
	if k.ctx.BrkTop() != pageUp(want) {
		t.Fatalf("BrkTop = %#x, want %#x", k.ctx.BrkTop(), pageUp(want))
	}
	k.be.MemWrite(BrkBase, []byte("heap!"))
	if got := k.memAt(BrkBase, 5); string(got) != "heap!" {
		t.Fatalf("brk heap not writable on backend, got %q", got)
	}
	// shrink
	if got := k.call(SYS_brk, BrkBase+0x1000); got != BrkBase+0x1000 {
		t.Fatalf("brk(shrink) = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
	// query returns the current break
	if got := k.call(SYS_brk, 0); got != BrkBase+0x1000 {
		t.Fatalf("brk(0) after shrink = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
	// below BrkBase is a query too
	if got := k.call(SYS_brk, 0x1000); got != BrkBase+0x1000 {
		t.Fatalf("brk(below base) = %#x, want %#x", uint64(got), uint64(BrkBase+0x1000))
	}
}

func TestMmap(t *testing.T) {
	k := newKernelCtxt(t)
	const protRW = emu.ProtRead | emu.ProtWrite

	a := k.call(SYS_mmap, 0, 0x1000, protRW, 0x22, 0, 0) // MAP_PRIVATE|MAP_ANONYMOUS
	if a != memory.MmapBase {
		t.Fatalf("first mmap = %#x, want %#x", uint64(a), uint64(memory.MmapBase))
	}
	b := k.call(SYS_mmap, 0, 0x2000, protRW, 0x22, 0, 0)
	if b != a+0x1000 {
		t.Fatalf("second mmap = %#x, want monotonic %#x", uint64(b), uint64(a+0x1000))
	}

	// mapped memory round-trips through the backend
	k.be.MemWrite(uint64(a), []byte("mmap-data"))
	if got := k.memAt(uint64(a), 9); string(got) != "mmap-data" {
		t.Fatalf("mmap memory = %q, want %q", got, "mmap-data")
	}
	if _, ok := k.ctx.Mem.Find(uint64(b)); !ok {
		t.Fatalf("mmap region %#x not tracked in memory.Space", uint64(b))
	}

	// MAP_FIXED maps exactly at the (page-rounded) hint
	const fixed = 0x50001000
	c := k.call(SYS_mmap, fixed+0x123, 0x1000, protRW, 0x22|mapFixed, 0, 0)
	if c != fixed {
		t.Fatalf("MAP_FIXED mmap = %#x, want %#x", uint64(c), uint64(fixed))
	}

	// munmap drops the region from the space bookkeeping
	if got := k.call(SYS_munmap, uint64(b), 0x2000); got != 0 {
		t.Fatalf("munmap = %d, want 0", got)
	}
	if _, ok := k.ctx.Mem.Find(uint64(b)); ok {
		t.Fatalf("region %#x still tracked after munmap", uint64(b))
	}

	// backend map failure surfaces as -ENOSYS
	k.be.mapErr = errors.New("map refused")
	if got := k.call(SYS_mmap, 0, 0x1000, protRW, 0x22, 0, 0); got != -ENOSYS {
		t.Fatalf("mmap with failing backend = %d, want %d", got, -ENOSYS)
	}
}

func TestMprotect(t *testing.T) {
	k := newKernelCtxt(t)
	a := k.call(SYS_mmap, 0, 0x1000, emu.ProtRead|emu.ProtWrite, 0x22, 0, 0)
	if a < 0 {
		t.Fatalf("mmap = %d", a)
	}
	if got := k.call(SYS_mprotect, uint64(a), 0x1000, emu.ProtRead); got != 0 {
		t.Fatalf("mprotect = %d, want 0", got)
	}
}

// --- stat family ---

func TestStatFamily(t *testing.T) {
	k := newKernelCtxt(t)
	buf := uint64(scratch + 0x400)

	// regular file via newfstatat
	if got := k.call(SYS_newfstatat, 0, k.putStr(scratch+0x800, testFile), buf, 0); got != 0 {
		t.Fatalf("newfstatat = %d, want 0", got)
	}
	st := k.memAt(buf, 128)
	if mode := binary.LittleEndian.Uint32(st[16:]); mode != 0x81a4 {
		t.Errorf("st_mode = %#o, want %#o (S_IFREG|0644)", mode, 0x81a4)
	}
	if size := binary.LittleEndian.Uint64(st[48:]); size != uint64(len(testContent)) {
		t.Errorf("st_size = %d, want %d", size, len(testContent))
	}

	// missing path
	if got := k.call(SYS_newfstatat, 0, k.putStr(scratch+0x800, "/nope"), buf, 0); got != -ENOENT {
		t.Fatalf("newfstatat(missing) = %d, want %d", got, -ENOENT)
	}

	// directory created via mkdirat stats as a dir
	if got := k.call(SYS_mkdirat, 0, k.putStr(scratch+0x800, "/data/local/dir"), 0755); got != 0 {
		t.Fatalf("mkdirat = %d, want 0", got)
	}
	if got := k.call(SYS_newfstatat, 0, k.putStr(scratch+0x800, "/data/local/dir"), buf, 0); got != 0 {
		t.Fatalf("newfstatat(dir) = %d, want 0", got)
	}
	st = k.memAt(buf, 128)
	if mode := binary.LittleEndian.Uint32(st[16:]); mode != 0x41ed {
		t.Errorf("dir st_mode = %#o, want %#o (S_IFDIR|0755)", mode, 0x41ed)
	}

	// fstat on an open fd
	fd := k.openTestFile()
	if got := k.call(SYS_fstat, uint64(fd), buf); got != 0 {
		t.Fatalf("fstat = %d, want 0", got)
	}
	if size := binary.LittleEndian.Uint64(k.memAt(buf+48, 8)); size != uint64(len(testContent)) {
		t.Errorf("fstat st_size = %d, want %d", size, len(testContent))
	}
	if got := k.call(SYS_fstat, 999, buf); got != -EBADF {
		t.Fatalf("fstat(bad fd) = %d, want %d", got, -EBADF)
	}

	// statx ABI
	if got := k.call(SYS_statx, 0, k.putStr(scratch+0x800, testFile), 0, 0, buf); got != 0 {
		t.Fatalf("statx = %d, want 0", got)
	}
	sx := k.memAt(buf, 256)
	if mode := binary.LittleEndian.Uint16(sx[28:]); mode != 0x81a4 {
		t.Errorf("stx_mode = %#o, want %#o", mode, 0x81a4)
	}
	if size := binary.LittleEndian.Uint64(sx[40:]); size != uint64(len(testContent)) {
		t.Errorf("stx_size = %d, want %d", size, len(testContent))
	}
	if got := k.call(SYS_statx, 0, k.putStr(scratch+0x800, "/nope"), 0, 0, buf); got != -ENOENT {
		t.Fatalf("statx(missing) = %d, want %d", got, -ENOENT)
	}
}

func TestFaccessat(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(SYS_faccessat, 0, k.putStr(scratch+0x800, testFile), 0); got != 0 {
		t.Errorf("faccessat(existing) = %d, want 0", got)
	}
	if got := k.call(SYS_faccessat, 0, k.putStr(scratch+0x900, "/nope"), 0); got != -ENOENT {
		t.Errorf("faccessat(missing) = %d, want %d", got, -ENOENT)
	}
	// synthetic VFS file
	if got := k.call(SYS_faccessat, 0, k.putStr(scratch+0xa00, "/proc/self/cmdline"), 0); got != 0 {
		t.Errorf("faccessat(synthetic) = %d, want 0", got)
	}
	// mkdirat'd directory
	k.call(SYS_mkdirat, 0, k.putStr(scratch+0xb00, "/data/local/dir"), 0755)
	if got := k.call(SYS_faccessat, 0, k.putStr(scratch+0xb00, "/data/local/dir"), 0); got != 0 {
		t.Errorf("faccessat(dir) = %d, want 0", got)
	}
	// writable-overlay file
	fd := k.call(SYS_openat, 0, k.putStr(scratch+0xc00, "/data/local/w.bin"), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}
	if got := k.call(SYS_faccessat, 0, k.putStr(scratch+0xc00, "/data/local/w.bin"), 0); got != 0 {
		t.Errorf("faccessat(overlay) = %d, want 0", got)
	}
}

// --- time determinism ---

func TestEpochPinnedTime(t *testing.T) {
	k := newKernelCtxt(t)
	k.ctx.Epoch = 1234567890

	if got := k.call(SYS_clock_gettime, clockRealtime, scratch); got != 0 {
		t.Fatalf("clock_gettime = %d, want 0", got)
	}
	ts := k.memAt(scratch, 16)
	if sec := binary.LittleEndian.Uint64(ts[0:]); sec != 1234567890 {
		t.Errorf("clock_gettime sec = %d, want 1234567890", sec)
	}
	if nsec := binary.LittleEndian.Uint64(ts[8:]); nsec != 0 {
		t.Errorf("clock_gettime nsec = %d, want 0 (pinned)", nsec)
	}

	// Semantic fix: in Epoch mode the monotonic clocks are zero-based (boot
	// time == epoch) instead of aliasing the wall clock — MONOTONIC measuring
	// "seconds since 1970" was never right and made uptime checks inconsistent.
	if got := k.call(SYS_clock_gettime, clockMonotonic, scratch); got != 0 {
		t.Fatalf("clock_gettime(MONOTONIC) = %d, want 0", got)
	}
	ts = k.memAt(scratch, 16)
	if sec := binary.LittleEndian.Uint64(ts[0:]); sec != 0 {
		t.Errorf("MONOTONIC sec = %d, want 0 (pinned: boot == epoch)", sec)
	}

	if got := k.call(SYS_gettimeofday, scratch+0x100, 0); got != 0 {
		t.Fatalf("gettimeofday = %d, want 0", got)
	}
	tv := k.memAt(scratch+0x100, 16)
	if sec := binary.LittleEndian.Uint64(tv[0:]); sec != 1234567890 {
		t.Errorf("gettimeofday sec = %d, want 1234567890", sec)
	}
	if usec := binary.LittleEndian.Uint64(tv[8:]); usec != 0 {
		t.Errorf("gettimeofday usec = %d, want 0 (pinned)", usec)
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

	readTS := func(addr uint64) (sec, nsec uint64) {
		ts := k.memAt(addr, 16)
		return binary.LittleEndian.Uint64(ts[0:]), binary.LittleEndian.Uint64(ts[8:])
	}
	wantUptime := uint64(3*3600 + 42*60)

	// realtime family -> wall clock
	for _, id := range []uint64{clockRealtime, clockRealtimeCoarse} {
		if got := k.call(SYS_clock_gettime, id, scratch); got != 0 {
			t.Fatalf("clock_gettime(%d) = %d, want 0", id, got)
		}
		if sec, _ := readTS(scratch); sec != uint64(testClock{}.Now().Unix()) {
			t.Errorf("clockid %d sec = %d, want wall %d", id, sec, testClock{}.Now().Unix())
		}
	}
	// monotonic family -> time since boot
	for _, id := range []uint64{clockMonotonic, clockMonotonicRaw, clockMonotonicCoarse, clockBoottime} {
		if got := k.call(SYS_clock_gettime, id, scratch); got != 0 {
			t.Fatalf("clock_gettime(%d) = %d, want 0", id, got)
		}
		if sec, _ := readTS(scratch); sec != wantUptime {
			t.Errorf("clockid %d sec = %d, want uptime %d", id, sec, wantUptime)
		}
	}
	// sysinfo uptime agrees with CLOCK_BOOTTIME (cross-check consistency)
	if got := k.call(SYS_sysinfo, scratch); got != 0 {
		t.Fatalf("sysinfo = %d, want 0", got)
	}
	if up := binary.LittleEndian.Uint64(k.memAt(scratch, 8)); up != wantUptime {
		t.Errorf("sysinfo uptime = %d, want %d", up, wantUptime)
	}
	// gettimeofday follows the wall clock
	if got := k.call(SYS_gettimeofday, scratch, 0); got != 0 {
		t.Fatalf("gettimeofday = %d, want 0", got)
	}
	if sec, usec := readTS(scratch); sec != uint64(testClock{}.Now().Unix()) || usec != 0 {
		t.Errorf("gettimeofday = %d.%d, want wall clock", sec, usec)
	}
}

func TestEpochZeroUsesHostClock(t *testing.T) {
	k := newKernelCtxt(t) // Epoch == 0
	if got := k.call(SYS_clock_gettime, 0, scratch); got != 0 {
		t.Fatalf("clock_gettime = %d, want 0", got)
	}
	if sec := binary.LittleEndian.Uint64(k.memAt(scratch, 8)); sec == 0 {
		t.Error("clock_gettime with Epoch=0 must return a non-zero host time")
	}
}

// --- exit ---

func TestExit(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(SYS_exit_group, 7); got != 0 {
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
	k2.call(SYS_exit, 0)
	if !k2.ctx.Exited || k2.ctx.ExitCode != 0 {
		t.Errorf("exit(0): Exited=%v ExitCode=%d", k2.ctx.Exited, k2.ctx.ExitCode)
	}
}

// --- Snapshot / Restore ---

func TestSnapshotRestore(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/snap.bin"

	// accumulate state: grow brk, open an fd, write an overlay file
	if got := k.call(SYS_brk, BrkBase+0x2000); got != BrkBase+0x2000 {
		t.Fatalf("brk = %#x", uint64(got))
	}
	fd := k.openTestFile()
	wfd := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	k.be.MemWrite(scratch, []byte("DATA"))
	k.call(SYS_write, uint64(wfd), scratch, 4)

	snap := k.ctx.Snapshot()

	// mutate everything mutable
	k.call(SYS_brk, BrkBase+0x5000)
	k.openTestFile() // consumes another fd
	k.call(SYS_read, uint64(fd), scratch+0x200, 5)
	k.be.MemWrite(scratch, []byte("MORE"))
	k.call(SYS_write, uint64(wfd), scratch, 4)
	k.ctx.Exited, k.ctx.ExitCode = true, 3
	k.call(SYS_mkdirat, 0, k.putStr(scratch+0x900, "/data/local/extra"), 0755)

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
	if got := k.call(SYS_getrandom, scratch, 32, 0); got != 32 {
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
	if got := k.call(SYS_getrandom, scratch+1, 32, 0); got != 32 {
		t.Fatalf("getrandom #2 = %d, want 32", got)
	}
	if second := k.memAt(scratch+1, 32); bytes.Equal(first, second) {
		t.Error("two getrandom calls returned identical buffers")
	}
}

// --- misc info syscalls ---

func TestInfoSyscalls(t *testing.T) {
	k := newKernelCtxt(t)

	// uname: "Linux" at off 0, "aarch64" machine at off 4*65
	if got := k.call(SYS_uname, scratch); got != 0 {
		t.Fatalf("uname = %d, want 0", got)
	}
	if got := k.memAt(scratch, 5); string(got) != "Linux" {
		t.Errorf("uname sysname = %q, want %q", got, "Linux")
	}
	if got := k.memAt(scratch+4*65, 7); string(got) != "aarch64" {
		t.Errorf("uname machine = %q, want %q", got, "aarch64")
	}

	// sysinfo: totalram at off 32
	if got := k.call(SYS_sysinfo, scratch); got != 0 {
		t.Fatalf("sysinfo = %d, want 0", got)
	}
	if ram := binary.LittleEndian.Uint64(k.memAt(scratch+32, 8)); ram != 4*1024*1024*1024 {
		t.Errorf("sysinfo totalram = %d, want 4 GiB", ram)
	}

	// readlinkat: known /proc symlink, truncation, unknown path
	n := k.call(SYS_readlinkat, 0, k.putStr(scratch+0x800, "/proc/self/exe"), scratch+0x400, 256)
	if want := "/system/bin/app_process64"; n != int64(len(want)) || string(k.memAt(scratch+0x400, uint64(n))) != want {
		t.Errorf("readlinkat(exe) = %d %q, want %d %q", n, k.memAt(scratch+0x400, uint64(n)), len(want), want)
	}
	if got := k.call(SYS_readlinkat, 0, k.putStr(scratch+0x800, "/proc/self/exe"), scratch+0x400, 4); got != 4 {
		t.Errorf("readlinkat(truncated) = %d, want 4", got)
	}
	if got := k.call(SYS_readlinkat, 0, k.putStr(scratch+0x800, "/proc/self/unknown"), scratch+0x400, 256); got != -ENOENT {
		t.Errorf("readlinkat(unknown) = %d, want %d", got, -ENOENT)
	}

	// sched_getaffinity
	if got := k.call(SYS_sched_getaffinity, 0, 0, scratch); got != -EINVAL {
		t.Errorf("sched_getaffinity(size 0) = %d, want %d", got, -EINVAL)
	}
	if got := k.call(SYS_sched_getaffinity, 0, 8, scratch); got != 8 {
		t.Errorf("sched_getaffinity(8) = %d, want 8", got)
	}
	if m := k.memAt(scratch, 8); m[0] != 0xFF {
		t.Errorf("affinity mask[0] = %#x, want 0xFF", m[0])
	}
	// cpusetsize larger than 8 is clamped to 8
	if got := k.call(SYS_sched_getaffinity, 0, 64, scratch); got != 8 {
		t.Errorf("sched_getaffinity(64) = %d, want 8 (clamped)", got)
	}

	// prlimit64: RLIMIT_STACK -> 8 MiB / 8 MiB written to old rlim
	if got := k.call(SYS_prlimit64, 0, 3, 0, scratch); got != 0 {
		t.Fatalf("prlimit64 = %d, want 0", got)
	}
	rl := k.memAt(scratch, 16)
	if cur := binary.LittleEndian.Uint64(rl[0:]); cur != 8*1024*1024 {
		t.Errorf("rlimit cur = %d, want 8 MiB", cur)
	}
	if max := binary.LittleEndian.Uint64(rl[8:]); max != 8*1024*1024 {
		t.Errorf("rlimit max = %d, want 8 MiB", max)
	}
	// unknown resource -> infinity
	k.call(SYS_prlimit64, 0, 99, 0, scratch)
	if cur := binary.LittleEndian.Uint64(k.memAt(scratch, 8)); cur != ^uint64(0) {
		t.Errorf("unknown rlimit cur = %#x, want RLIM_INFINITY", cur)
	}
}

// --- semantics conformance (kernel-comparison round) ---

// close on an unopened fd must return -EBADF — real kernels reject it, and
// returning 0 is a fingerprint anti-emulation probes check for.
func TestCloseUnknownFdEBADF(t *testing.T) {
	k := newKernelCtxt(t)
	if got := k.call(SYS_close, 0xdead); got != -EBADF {
		t.Errorf("close(0xdead) = %d, want %d", got, -EBADF)
	}
	// a real close still works afterwards
	fd := k.openTestFile()
	if got := k.call(SYS_close, uint64(fd)); got != 0 {
		t.Errorf("close(open fd) = %d, want 0", got)
	}
	// and the second close of the now-closed fd is EBADF again
	if got := k.call(SYS_close, uint64(fd)); got != -EBADF {
		t.Errorf("double close = %d, want %d", got, -EBADF)
	}
}

// writev must honor the fd's position (lseek then writev overwrites, not
// appends) — previously it appended unconditionally, corrupting data for
// guests that seek before vector writes.
func TestWritevHonorsPosition(t *testing.T) {
	k := newKernelCtxt(t)
	const wpath = "/data/local/posiov.bin"
	fd := k.call(SYS_openat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	if fd < 0 {
		t.Fatalf("openat = %d", fd)
	}
	// write "0123456789" (10 bytes) at pos 0
	k.be.MemWrite(scratch+0x1000, []byte("0123456789"))
	if got := k.call(SYS_write, uint64(fd), scratch+0x1000, 10); got != 10 {
		t.Fatalf("write = %d, want 10", got)
	}
	// seek to 3, then writev {"AB",2},{"CD",2} — must overwrite bytes 3..7
	k.call(SYS_lseek, uint64(fd), 3, 0)
	k.be.MemWrite(scratch+0x1000, []byte("AB"))
	k.be.MemWrite(scratch+0x1100, []byte("CD"))
	var iov [32]byte
	binary.LittleEndian.PutUint64(iov[0:], scratch+0x1000)
	binary.LittleEndian.PutUint64(iov[8:], 2)
	binary.LittleEndian.PutUint64(iov[16:], scratch+0x1100)
	binary.LittleEndian.PutUint64(iov[24:], 2)
	k.be.MemWrite(scratch+0x1200, iov[:])
	if got := k.call(SYS_writev, uint64(fd), scratch+0x1200, 2); got != 4 {
		t.Fatalf("writev = %d, want 4", got)
	}
	// read the whole file back: "012ABC789"
	fd2 := k.call(SYS_openat, 0, k.putStr(scratch+0x1400, wpath), 0)
	if got := k.call(SYS_read, uint64(fd2), scratch+0x200, 16); got != 10 {
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
	if got := k.call(SYS_getrandom, buf, 32, 0); got != 32 {
		t.Fatalf("getrandom = %d, want 32", got)
	}
	first := k.memAt(buf, 32)
	if got := k.call(SYS_getrandom, buf, 32, 0); got != 32 {
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
