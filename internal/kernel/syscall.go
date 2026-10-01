// Package kernel emulates the semantics of the Linux syscall interface. The
// transport half of the ABI — which register carries the syscall number,
// which carry the arguments, how results and errors are encoded back — lives
// behind the consumer-owned SyscallTransport interface (implemented by
// platform/android for AArch64 Linux: x8 number, x0..x5 args, -errno results);
// kernel code never touches a syscall register or a -errno literal.
//
// the target .so does not issue syscalls directly; the *bionic libc* we
// emulate does, on its behalf. So the set that actually fires is "whatever
// libc.so/libm.so touch during JNI_OnLoad + the target call" — a few dozen, not
// the full table. The Android/AArch64 number table lives in platform/android.
package kernel

import (
	crand "crypto/rand"
	"fmt"
	"time"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/vfs"
)

// BrkBase is the guest program-break heap origin (clear of modules/mmap arena).
const BrkBase = 0x30000000

// MaxGuestIO bounds every guest-supplied byte count that would become a
// HOST allocation or copy (getrandom fill, writable-fd write capture, JNI
// byte arrays). 64 MiB is far above any legitimate bionic/JNI traffic and
// far below OOM territory. Policy a guest length never converts
// directly into a host allocation size — over-cap requests fail loudly
// (errno / JNI NULL / pending exception) instead of allocating.
const MaxGuestIO = 64 << 20

// Errno is a semantic syscall error, carried in Result.Errno (0 = success).
// It is deliberately NOT a wire encoding: how an Errno reaches the guest
// (Linux: x0 = -errno; Darwin: x0 = +errno + carry flag) is the transport's
// business. The numeric values below are the Linux asm-generic assignments;
// a Darwin transport must translate them to Darwin's numbering.
type Errno int

const (
	ENOSYS Errno = 38
	EPERM  Errno = 1
	EIO    Errno = 5
	EBADF  Errno = 9
	ENOENT Errno = 2
	EINVAL Errno = 22
	ERANGE Errno = 34
	EFAULT Errno = 14
)

// Result is what a Handler produces: pure syscall semantics, no encoding
// (DESIGN.md invariant 6). Value2 is reserved for dual-return-value ABIs —
// the Darwin ARM64 syscall wrapper preserves x0/x1 + carry; Linux ignores
// Value2 entirely (see the transport's EncodeResult).
type Result struct {
	Value  uint64
	Value2 uint64
	Errno  Errno // 0 = success
}

// SyscallFrame is the product of SyscallTransport.Decode: the syscall number
// plus its arguments, with no register identities attached. Args has a fixed
// capacity of 8 (not a slice — no allocation on the dispatch hot path); Linux
// uses at most 6 today, Darwin's generic syscall shim has a 7-argument path,
// so no Linux-specific arity is baked into the core abstraction. NArg records
// how many slots the transport actually decoded; handlers don't have to
// consume all of them.
type SyscallFrame struct {
	Num  uint64
	Args [8]uint64
	NArg uint8
}

// SyscallTransport is a consumer-owned interface (DESIGN.md invariant 6): the
// syscall transport ABI conceptually belongs to the OS platform, but the
// interface lives in kernel so the dependency stays platform → kernel → emu
// without a cycle. platform/android implements Linux/AArch64 (x8 number,
// x0..x5 args, -errno result); platform/darwin will implement x16 /
// carry+errno / dual return values.
type SyscallTransport interface {
	Decode(b emu.Backend) (SyscallFrame, error)
	EncodeResult(b emu.Backend, r Result) error
}

// Handler implements one syscall's semantics: it reads frame.Args, operates
// on the Context, and returns a Result. It must never read the syscall number
// register or argument registers itself, and never return a Linux -errno
// encoding — only Result{Errno: ...} (DESIGN.md invariant 6).
type Handler func(c *Context, f *SyscallFrame) Result

// Table is one platform's syscall dispatch table: number -> handler, plus
// trace names. It is an injectable instance (held by Context), not a package
// global; platform/android builds the Android/AArch64 one.
type Table struct {
	Handlers map[uint64]Handler
	Names    map[uint64]string
}

// Lookup resolves a syscall number to its handler.
func (t *Table) Lookup(num uint64) (Handler, bool) {
	h, ok := t.Handlers[num]
	return h, ok
}

// Name returns the trace name for a syscall number ("" if unknown).
func (t *Table) Name(num uint64) string { return t.Names[num] }

// --- guest ABI structure semantics (encoded by StructCodecs) ---------------
//
// The types below are the SEMANTIC content of guest structs that handlers
// read or write; their guest-memory layout (offsets, field widths, struct
// size) is a platform/ABI implementation detail behind StructCodecs — the
// QEMU thunk approach (DESIGN.md invariant 7). The set is exactly the structs
// the current handlers touch; it grows only when a handler genuinely reads or
// writes another guest ABI struct. Plain u32/u64 guest-memory accesses and
// fixed-layout blobs (utsname's 6×65 bytes, cpumask bytes) are NOT ABI-layout
// dependent and stay inline in the handlers.

// Stat is the semantic content of `struct stat` (fstat/newfstatat).
type Stat struct {
	Mode uint32 // S_IF* | permission bits (Linux values, arch-independent)
	Size uint64
}

// Statx is the semantic content of `struct statx`.
type Statx struct {
	Mask    uint32
	Blksize uint32
	Nlink   uint32
	Mode    uint16
	Size    uint64
	Blocks  uint64
}

// Timespec is `struct timespec` (clock_gettime): seconds + nanoseconds.
type Timespec struct {
	Sec  int64
	Nsec int64
}

// Timeval is `struct timeval` (gettimeofday): seconds + microseconds.
type Timeval struct {
	Sec  int64
	Usec int64
}

// Sysinfo is the semantic content of `struct sysinfo` (LP64-layout dependent).
type Sysinfo struct {
	UptimeSec uint64
	TotalRAM  uint64
	FreeRAM   uint64
	Procs     uint16
	MemUnit   uint32
}

// Rlimit is one `struct rlimit` (prlimit64 old-value out): rlim_cur/max,
// whose width follows the guest's unsigned long.
type Rlimit struct {
	Cur uint64
	Max uint64
}

// Iovec is one `struct iovec` (writev): a guest pointer + length, both
// pointer-width dependent.
type Iovec struct {
	Base uint64
	Len  uint64
}

// StructCodecs encodes/decodes guest ABI structures (consumer-owned, like
// SyscallTransport). dst/src buffers are sized by the caller via the
// companion Size methods, so no layout constant ever appears in kernel code.
type StructCodecs interface {
	StatSize() int
	EncodeStat(dst []byte, s Stat) error
	StatxSize() int
	EncodeStatx(dst []byte, s Statx) error
	TimespecSize() int
	EncodeTimespec(dst []byte, t Timespec) error
	TimevalSize() int
	EncodeTimeval(dst []byte, t Timeval) error
	SysinfoSize() int
	EncodeSysinfo(dst []byte, s Sysinfo) error
	RlimitSize() int
	EncodeRlimit(dst []byte, r Rlimit) error
	IovecSize() int
	DecodeIovec(src []byte) (Iovec, error)
}

// Context is the state a syscall handler operates on.
type Context struct {
	B       emu.Backend
	Mem     *memory.Space
	VFS     *vfs.VFS
	Pid     int
	Verbose bool
	// Transport, Table and Codecs are the injected platform personality:
	// transport owns the syscall register ABI, the table owns number->handler,
	// codecs own guest struct layouts. All three are required for Dispatch.
	Transport SyscallTransport
	Table     *Table
	Codecs    StructCodecs
	// Epoch, if non-zero, pins gettimeofday/clock_gettime to this fixed Unix time
	// (seconds) instead of the host clock — for deterministic, reproducible runs
	// (reverse-engineering: the same inputs must yield the same signature).
	// Epoch wins over Clock; in Epoch mode the monotonic clocks are zero-based
	// (boot time == epoch), so uptime reads 0 rather than the wall time.
	Epoch int64
	// TrueRandom makes getrandom fill buffers from crypto/rand. Default off:
	// the deterministic stream keeps runs reproducible, but it is trivially
	// distinguishable from real entropy — set this for security-sensitive
	// guests or whenever anti-emulation sampling is a concern.
	TrueRandom bool
	// Clock, if non-nil, supplies the guest's wall clock and monotonic origin
	// (boot time). nil = host clock with the monotonic origin at process start.
	// The emulator installs a profile-backed clock here when a device liveness
	// profile is configured, so syscall-time and JNI-time agree.
	Clock Clock
	// Uname is the guest-visible utsname identity, supplied by the
	// platform personality as pure data and injected at wiring time. The
	// uname handler only encodes it — deciding WHO the guest is (sysname,
	// machine, release) is platform business. nil = the platform bound no
	// uname number into its table; if a table nevertheless binds uname, the
	// handler fails loudly (EINVAL) instead of reporting a hardcoded lie.
	Uname *UnameInfo

	brkCur         uint64 // current program break (0 = uninitialized)
	getrandomCalls uint64 // deterministic getrandom stream counter
	Exited         bool   // guest called exit/exit_group
	ExitCode       int

	files  map[int32]*openFile
	nextFd int32
	wfiles map[string][]byte // writable in-memory FS overlay (e.g. /mssdk/ml/*)
	dirs   map[string]bool   // directories created via mkdirat
}

type openFile struct {
	path     string
	data     []byte // read-only snapshot (VFS files)
	pos      int64
	writable bool // backed by Context.wfiles[path]
}

func (c *Context) fdTable() map[int32]*openFile {
	if c.files == nil {
		c.files = map[int32]*openFile{}
		c.nextFd = 100
	}
	return c.files
}

// State is the mutable per-run kernel state that accumulates across guest calls:
// the program break, the exit latch, the fd table, the writable-FS overlay, and
// created dirs. Snapshot captures it right after boot/init; Restore rewinds it,
// so a reused emulator starts every call from the same kernel state a freshly
// booted process would have (part of the emulator's Snapshot/Restore).
type State struct {
	brkCur   uint64
	exited   bool
	exitCode int
	nextFd   int32
	files    map[int32]*openFile
	wfiles   map[string][]byte
	dirs     map[string]bool
}

// Snapshot deep-copies the mutable kernel state.
func (c *Context) Snapshot() State {
	st := State{brkCur: c.brkCur, exited: c.Exited, exitCode: c.ExitCode, nextFd: c.nextFd}
	if c.files != nil {
		st.files = make(map[int32]*openFile, len(c.files))
		for k, v := range c.files {
			f := *v // copy pos/path/writable; data is a read-only snapshot (shared)
			st.files[k] = &f
		}
	}
	if c.wfiles != nil {
		st.wfiles = make(map[string][]byte, len(c.wfiles))
		for k, v := range c.wfiles {
			st.wfiles[k] = append([]byte(nil), v...)
		}
	}
	if c.dirs != nil {
		st.dirs = make(map[string]bool, len(c.dirs))
		for k, v := range c.dirs {
			st.dirs[k] = v
		}
	}
	return st
}

// BrkTop returns the page-aligned top of the currently mapped program break
// (BrkBase when brk was never grown). The emulator snapshots [BrkBase, BrkTop)
// as writable memory, since the brk heap is backed on the CPU engine directly
// and isn't tracked in the mmap-arena allocator.
func (c *Context) BrkTop() uint64 { return brkTopOf(c.brkCur) }

func brkTopOf(brkCur uint64) uint64 {
	if brkCur > BrkBase {
		return pageUp(brkCur)
	}
	return BrkBase
}

// Restore rewinds the mutable kernel state to a prior Snapshot (clearing the
// exit latch, program break, fd table, and FS overlay accumulated since).
func (c *Context) Restore(st State) {
	// Release brk pages grown since the snapshot so a later brk() can re-map them
	// cleanly — sysBrk maps pages on growth, and re-mapping a still-mapped page
	// fails, which would silently break the guest allocator on a reused instance.
	if cur, tgt := c.BrkTop(), brkTopOf(st.brkCur); cur > tgt {
		_ = c.B.MemUnmap(emu.GuestAddr(tgt), cur-tgt)
	}
	c.brkCur = st.brkCur
	c.Exited = st.exited
	c.ExitCode = st.exitCode
	c.nextFd = st.nextFd
	c.files = copyFiles(st.files)
	c.wfiles = copyWfiles(st.wfiles)
	c.dirs = copyDirs(st.dirs)
}

func copyFiles(in map[int32]*openFile) map[int32]*openFile {
	if in == nil {
		return nil
	}
	out := make(map[int32]*openFile, len(in))
	for k, v := range in {
		f := *v
		out[k] = &f
	}
	return out
}

func copyWfiles(in map[string][]byte) map[string][]byte {
	if in == nil {
		return nil
	}
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func copyDirs(in map[string]bool) map[string]bool {
	if in == nil {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Dispatch decodes the syscall frame from the backend through the injected
// transport and services it (see DispatchFrame). Register it via
// Backend.HookInterrupt / InstallTrap(TrapSyscall).
//
// Coverage policy (a deliberate design boundary): unimplemented syscalls
// return ENOSYS so gaps between the emulated kernel and a real one surface
// in testing instead of being masked; trivial stub handlers optimistically
// return 0 for calls real kernels commonly answer with trivial success, and
// log under Verbose. Every stub entry is a place the emulation may drift from
// a real device — keep that list short.
func (c *Context) Dispatch() {
	frame, err := c.Transport.Decode(c.B)
	if err != nil {
		if c.Verbose {
			fmt.Printf("[syscall] decode failed: %v\n", err)
		}
		return
	}
	c.DispatchFrame(&frame)
}

// DispatchFrame services an already-decoded syscall frame: table lookup
// (unimplemented -> ENOSYS, logged under Verbose), handler, result encoding
// through the transport. The emulator decodes once per trap and calls this
// directly, so the scheduler's interception path shares the decode.
func (c *Context) DispatchFrame(f *SyscallFrame) {
	var res Result
	h, ok := c.Table.Lookup(f.Num)
	if !ok || h == nil {
		if c.Verbose {
			fmt.Printf("[syscall] UNIMPLEMENTED #%d (%s) args=%v\n", f.Num, c.Table.Name(f.Num), f.Args[:f.NArg])
		}
		res = Result{Errno: ENOSYS}
	} else {
		res = h(c, f)
	}
	if err := c.Transport.EncodeResult(c.B, res); err != nil && c.Verbose {
		fmt.Printf("[syscall] encode result for #%d failed: %v\n", f.Num, err)
	}
}

const mapFixed = 0x10

func SysMmap(c *Context, f *SyscallFrame) Result {
	a := f.Args
	// addr, length, prot, flags, fd, offset
	hint := a[0]
	length := pageUp(a[1])
	prot := int(a[2])
	flags := a[3]
	var addr uint64
	if flags&mapFixed != 0 && hint != 0 {
		addr = hint &^ 0xfff
		c.Mem.Munmap(addr, length) // drop any prior mapping under MAP_FIXED
		_ = c.Mem.Map(addr, length, prot, "mmap-fixed")
		c.B.MemUnmap(emu.GuestAddr(addr), length)
	} else {
		addr = c.Mem.Mmap(length, prot, "mmap")
	}
	if err := c.B.MemMap(emu.GuestAddr(addr), length, prot|emu.ProtRead); err != nil {
		return Result{Errno: ENOSYS}
	}
	return Result{Value: addr}
}

// SysWrite/SysWritev capture the .so's own log output (it logs to fd 1/2 and
// to logd before bailing) — invaluable for seeing why it exits.
func SysWrite(c *Context, f *SyscallFrame) Result {
	a := f.Args
	fd, buf, n := a[0], a[1], a[2]
	// writable file fd -> store into the overlay
	if f := c.fdTable()[int32(fd)]; f != nil && f.writable {
		if n > MaxGuestIO {
			return Result{Errno: EINVAL} // a guest count never sizes a host alloc
		}
		d, err := c.B.MemRead(emu.GuestAddr(buf), n)
		if err != nil {
			return Result{Errno: EBADF}
		}
		return Result{Value: uint64(c.writeOverlay(f, d))}
	}
	// otherwise it's stdout/stderr/log -> surface it only when tracing
	if c.Verbose && n > 0 && n < 0x10000 {
		if d, err := c.B.MemRead(emu.GuestAddr(buf), n); err == nil {
			fmt.Printf("[write fd=%d] %s\n", fd, string(d))
		}
	}
	return Result{Value: n}
}

// writeOverlay writes d into the writable overlay at the fd's position,
// zero-filling gaps and advancing f.pos — the single implementation of the
// pos semantics shared by SysWrite and SysWritev.
func (c *Context) writeOverlay(f *openFile, d []byte) int {
	w := c.wstore()
	cur := w[f.path]
	end := f.pos + int64(len(d))
	if int64(len(cur)) < end {
		nb := make([]byte, end)
		copy(nb, cur)
		cur = nb
	}
	copy(cur[f.pos:end], d)
	w[f.path] = cur
	f.pos = end
	return len(d)
}

func SysWritev(c *Context, f *SyscallFrame) Result {
	a := f.Args
	fd, iov, cnt := a[0], a[1], a[2]
	wf := c.fdTable()[int32(fd)]
	stride := uint64(c.Codecs.IovecSize())
	total := uint64(0)
	for i := uint64(0); i < cnt && i < 64; i++ {
		ent, err := c.B.MemRead(emu.GuestAddr(iov+i*stride), stride)
		if err != nil {
			break
		}
		iv, err := c.Codecs.DecodeIovec(ent)
		if err != nil {
			break
		}
		if iv.Len == 0 || iv.Len >= 0x10000 {
			continue
		}
		d, err := c.B.MemRead(emu.GuestAddr(iv.Base), iv.Len)
		if err != nil {
			continue
		}
		if wf != nil && wf.writable { // honor the fd's position, like SysWrite
			c.writeOverlay(wf, d)
		} else if c.Verbose {
			fmt.Printf("[writev fd=%d] %s\n", fd, string(d))
		}
		total += iv.Len
	}
	return Result{Value: total}
}

// readCStr reads a NUL-terminated guest string (for path args).
func (c *Context) readCStr(addr uint64) string {
	var out []byte
	for i := 0; i < 4096; i++ {
		b, err := c.B.MemRead(emu.GuestAddr(addr+uint64(len(out))), 1)
		if err != nil || b[0] == 0 {
			break
		}
		out = append(out, b[0])
	}
	return string(out)
}

// open flags (asm-generic).
const (
	oWRONLY = 0x1
	oRDWR   = 0x2
	oCREAT  = 0x40
	oTRUNC  = 0x200
	oAPPEND = 0x400
)

func (c *Context) wstore() map[string][]byte {
	if c.wfiles == nil {
		c.wfiles = map[string][]byte{}
	}
	return c.wfiles
}

func SysOpenat(c *Context, f *SyscallFrame) Result {
	a := f.Args
	path := c.readCStr(a[1])
	flags := a[2]
	t := c.fdTable()
	fd := c.nextFd

	if flags&(oWRONLY|oRDWR|oCREAT) != 0 { // writable
		w := c.wstore()
		if _, ok := w[path]; !ok || flags&oTRUNC != 0 {
			w[path] = nil
		}
		of := &openFile{path: path, writable: true}
		if flags&oAPPEND != 0 {
			of.pos = int64(len(w[path]))
		}
		c.nextFd++
		t[fd] = of
		if c.Verbose {
			fmt.Printf("[openat:w] %q -> fd=%d\n", path, fd)
		}
		return Result{Value: uint64(fd)}
	}

	data, err := c.VFS.Read(path)
	if err != nil {
		if w, ok := c.wstore()[path]; ok { // previously written file
			data = w
		} else {
			if c.Verbose {
				fmt.Printf("[openat] %q -> ENOENT\n", path)
			}
			return Result{Errno: ENOENT}
		}
	}
	c.nextFd++
	t[fd] = &openFile{path: path, data: data}
	if c.Verbose {
		fmt.Printf("[openat] %q -> fd=%d (%d bytes)\n", path, fd, len(data))
	}
	return Result{Value: uint64(fd)}
}

func (c *Context) fileData(f *openFile) []byte {
	if f.writable {
		return c.wstore()[f.path]
	}
	return f.data
}

func SysRead(c *Context, f *SyscallFrame) Result {
	a := f.Args
	fp := c.fdTable()[int32(a[0])]
	if fp == nil {
		return Result{Errno: EBADF}
	}
	data := c.fileData(fp)
	n := int64(a[2])
	if rem := int64(len(data)) - fp.pos; n > rem {
		n = rem
	}
	if n <= 0 {
		return Result{}
	}
	c.B.MemWrite(emu.GuestAddr(a[1]), data[fp.pos:fp.pos+n])
	fp.pos += n
	return Result{Value: uint64(n)}
}

func SysClose(c *Context, f *SyscallFrame) Result {
	fd := int32(f.Args[0])
	if _, ok := c.fdTable()[fd]; !ok {
		return Result{Errno: EBADF} // real kernels reject closing an unopened fd
	}
	delete(c.fdTable(), fd)
	return Result{}
}

func SysMkdirat(c *Context, f *SyscallFrame) Result {
	path := c.readCStr(f.Args[1])
	if c.dirs == nil {
		c.dirs = map[string]bool{}
	}
	c.dirs[path] = true
	if c.Verbose {
		fmt.Printf("[mkdirat] %q -> 0\n", path)
	}
	return Result{}
}

func SysLseek(c *Context, f *SyscallFrame) Result {
	a := f.Args
	fp := c.fdTable()[int32(a[0])]
	if fp == nil {
		return Result{Errno: EBADF}
	}
	off, whence := int64(a[1]), a[2]
	switch whence {
	case 0: // SEEK_SET
		fp.pos = off
	case 1: // SEEK_CUR
		fp.pos += off
	case 2: // SEEK_END
		fp.pos = int64(len(c.fileData(fp))) + off
	default: // SEEK_DATA/HOLE etc. unmodeled
		return Result{Errno: EINVAL}
	}
	if fp.pos < 0 {
		fp.pos = 0 // don't leave the fd positioned at a negative offset
		return Result{Errno: EINVAL}
	}
	return Result{Value: uint64(fp.pos)}
}

func SysFaccessat(c *Context, f *SyscallFrame) Result {
	path := c.readCStr(f.Args[1])
	if c.VFS.Exists(path) || c.dirs[path] {
		return Result{}
	}
	if _, ok := c.wstore()[path]; ok {
		return Result{}
	}
	return Result{Errno: ENOENT}
}

// writeStat fills the guest `struct stat` at addr through the injected codec
// (kernel owns the semantic content — mode bits and size; the codec owns the
// asm-generic LP64 layout and derived fields like st_blocks).
func (c *Context) writeStat(addr uint64, size uint64, isDir bool) {
	mode := uint32(0x81a4) // S_IFREG|0644
	if isDir {
		mode = 0x41ed // S_IFDIR|0755
	}
	buf := make([]byte, c.Codecs.StatSize())
	if err := c.Codecs.EncodeStat(buf, Stat{Mode: mode, Size: size}); err != nil {
		return
	}
	c.B.MemWrite(emu.GuestAddr(addr), buf)
}

func SysFstat(c *Context, f *SyscallFrame) Result {
	a := f.Args
	fp := c.fdTable()[int32(a[0])]
	if fp == nil {
		return Result{Errno: EBADF}
	}
	c.writeStat(a[1], uint64(len(c.fileData(fp))), false)
	return Result{}
}

func SysNewfstatat(c *Context, f *SyscallFrame) Result {
	a := f.Args
	path := c.readCStr(a[1])
	if c.dirs[path] {
		c.writeStat(a[2], 4096, true)
		if c.Verbose {
			fmt.Printf("[newfstatat] %q -> dir\n", path)
		}
		return Result{}
	}
	var size int64 = -1
	if data, err := c.VFS.Read(path); err == nil {
		size = int64(len(data))
	} else if w, ok := c.wstore()[path]; ok {
		size = int64(len(w))
	}
	if size < 0 {
		if c.Verbose {
			fmt.Printf("[newfstatat] %q -> ENOENT\n", path)
		}
		return Result{Errno: ENOENT}
	}
	c.writeStat(a[2], uint64(size), false)
	if c.Verbose {
		fmt.Printf("[newfstatat] %q -> size=%d\n", path, size)
	}
	return Result{}
}

func SysFutex(c *Context, f *SyscallFrame) Result {
	a := f.Args
	op := a[1] & 0x7f
	if c.Verbose {
		name := map[uint64]string{0: "WAIT", 1: "WAKE", 9: "WAKE_OP", 6: "WAIT_BITSET", 7: "WAKE_BITSET"}[op]
		fmt.Printf("[futex] uaddr=0x%x op=%d(%s) val=%d\n", a[0], op, name, a[2])
	}
	return Result{}
}

func SysExit(c *Context, f *SyscallFrame) Result {
	c.Exited = true
	c.ExitCode = int(int32(f.Args[0]))
	fmt.Printf("[syscall] exit_group(%d) — guest requested exit; stopping\n", c.ExitCode)
	_ = c.B.Stop()
	return Result{}
}

func SysBrk(c *Context, f *SyscallFrame) Result {
	if c.brkCur == 0 {
		c.brkCur = BrkBase
	}
	want := f.Args[0]
	if want == 0 || want < BrkBase {
		return Result{Value: c.brkCur}
	}
	if hi, lo := pageUp(want), pageUp(c.brkCur); hi > lo {
		if err := c.B.MemMap(emu.GuestAddr(lo), hi-lo, emu.ProtRead|emu.ProtWrite); err != nil {
			return Result{Value: c.brkCur}
		}
	}
	c.brkCur = want
	return Result{Value: want}
}

// Clock is the guest's time source. All time-serving syscalls derive from one
// Clock so the values cross-check (a risk-control probe comparing wall time,
// monotonic time, and sysinfo uptime must find them consistent).
type Clock interface {
	Now() time.Time      // wall clock (CLOCK_REALTIME / gettimeofday)
	BootTime() time.Time // origin of CLOCK_MONOTONIC / CLOCK_BOOTTIME / uptime
}

// clockid values (asm-generic / Linux).
const (
	clockRealtime        = 0
	clockMonotonic       = 1
	clockMonotonicRaw    = 4
	clockRealtimeCoarse  = 5
	clockMonotonicCoarse = 6
	clockBoottime        = 7
)

// pinnedClock implements Clock for Epoch mode: the wall clock frozen at the
// epoch, monotonic clocks zero-based (boot == epoch) so they stay frozen too.
type pinnedClock int64

func (p pinnedClock) Now() time.Time      { return time.Unix(int64(p), 0) }
func (p pinnedClock) BootTime() time.Time { return p.Now() }

// hostClock is the default: real wall time, booted when the process started.
type hostClock struct{ started time.Time }

func (h hostClock) Now() time.Time      { return time.Now() }
func (h hostClock) BootTime() time.Time { return h.started }

var processStart = time.Now()

// clock resolves the effective time source: Epoch pins everything (signing
// determinism beats realism), then an injected Clock, then the host clock.
func (c *Context) clock() Clock {
	if c.Epoch != 0 {
		return pinnedClock(c.Epoch)
	}
	if c.Clock != nil {
		return c.Clock
	}
	return hostClock{processStart}
}

// Now returns the guest wall clock (CLOCK_REALTIME semantics).
func (c *Context) Now() time.Time { return c.clock().Now() }

// SinceBoot returns the guest monotonic clock (time since boot).
func (c *Context) SinceBoot() time.Duration {
	cl := c.clock()
	if d := cl.Now().Sub(cl.BootTime()); d > 0 {
		return d
	}
	return 0
}

func SysClockGettime(c *Context, f *SyscallFrame) Result {
	a := f.Args
	var sec, nsec int64
	switch a[0] {
	case clockMonotonic, clockMonotonicRaw, clockMonotonicCoarse, clockBoottime:
		d := c.SinceBoot()
		sec, nsec = int64(d/time.Second), int64(d%time.Second)
	default:
		// CLOCK_REALTIME (+COARSE) and any clockid we don't model: wall time,
		// matching the pre-clockid behavior for the unhandled ids.
		now := c.Now()
		sec, nsec = now.Unix(), int64(now.Nanosecond())
	}
	buf := make([]byte, c.Codecs.TimespecSize())
	if err := c.Codecs.EncodeTimespec(buf, Timespec{Sec: sec, Nsec: nsec}); err != nil {
		return Result{Errno: EINVAL}
	}
	c.B.MemWrite(emu.GuestAddr(a[1]), buf)
	return Result{}
}

func SysGettimeofday(c *Context, f *SyscallFrame) Result {
	now := c.Now()
	buf := make([]byte, c.Codecs.TimevalSize())
	if err := c.Codecs.EncodeTimeval(buf, Timeval{Sec: now.Unix(), Usec: int64(now.Nanosecond() / 1000)}); err != nil {
		return Result{Errno: EINVAL}
	}
	c.B.MemWrite(emu.GuestAddr(f.Args[0]), buf)
	return Result{}
}

// SysGetrandom fills the buffer. Two modes:
//   - TrueRandom set: crypto/rand — for security-sensitive guests whose
//     key material must not be predictable.
//   - default (deterministic): a mixed-parameter LCG stream. Deterministic
//     so runs stay reproducible, but the seed mixes ALL call parameters plus
//     a per-call counter, so repeated identical calls no longer return the
//     same bytes. NOTE: even the deterministic stream is trivially
//     distinguishable from real entropy — guests that sample it for
//     anti-emulation checks will see through it; set TrueRandom for those.
func SysGetrandom(c *Context, f *SyscallFrame) Result {
	a := f.Args
	n := a[1]
	if n > MaxGuestIO {
		return Result{Errno: EINVAL} // a guest count never sizes a host alloc
	}
	buf := make([]byte, n)
	if c.TrueRandom {
		if _, err := crand.Read(buf); err != nil {
			return Result{Errno: EIO}
		}
		c.B.MemWrite(emu.GuestAddr(a[0]), buf)
		return Result{Value: n}
	}
	seed := uint64(a[0]) ^ uint64(a[1])<<8 ^ uint64(a[2])<<16 ^ a[3]<<24 ^ a[4]<<32 ^ a[5]<<40 ^ c.getrandomCalls<<56
	c.getrandomCalls++
	DeterministicRandom(seed, buf)
	c.B.MemWrite(emu.GuestAddr(a[0]), buf)
	return Result{Value: n}
}

func SysMunmap(c *Context, f *SyscallFrame) Result {
	a := f.Args
	c.Mem.Munmap(a[0], a[1])
	c.B.MemUnmap(emu.GuestAddr(a[0]), pageUp(a[1]))
	return Result{}
}

func SysMprotect(c *Context, f *SyscallFrame) Result {
	a := f.Args
	// Page-granular protect on the backend; mem.Space bookkeeping is best-effort
	// (bionic protects sub-ranges of larger mappings, e.g. thread stack guards).
	_ = c.Mem.Protect(a[0], a[1], int(a[2]))
	if err := c.B.MemProtect(emu.GuestAddr(a[0]&^0xfff), pageUp(a[1]), int(a[2])); err != nil {
		return Result{Errno: EPERM}
	}
	return Result{}
}

func pageUp(x uint64) uint64 { return (x + 0xfff) &^ 0xfff }

// UnameInfo is the platform-supplied utsname identity per-arch
// personality data selected at Bind time (e.g. Android: aarch64 / armv7l /
// x86_64), injected into Context by the composition root. The utsname LAYOUT
// is identical on every Linux architecture (fixed 65-byte fields), so the
// handler stays layout-independent — but the IDENTITY is platform business,
// never a kernel-side constant.
type UnameInfo struct {
	Sysname    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
}

// SysUname fills `struct utsname` (6 × 65-byte NUL-padded fields) from the
// platform-supplied identity (Context.Uname). A platform that binds uname
// without configuring an identity is a wiring bug: fail loudly (EINVAL)
// rather than fabricate values.
func SysUname(c *Context, f *SyscallFrame) Result {
	if c.Uname == nil {
		return Result{Errno: EINVAL} // loud: uname bound without a platform identity
	}
	u := c.Uname
	var buf [6 * 65]byte
	set := func(i int, s string) { copy(buf[i*65:i*65+64], s) }
	set(0, u.Sysname)
	set(1, u.Nodename)
	set(2, u.Release)
	set(3, u.Version)
	set(4, u.Machine)
	set(5, u.Domainname)
	if err := c.B.MemWrite(emu.GuestAddr(f.Args[0]), buf[:]); err != nil {
		return Result{Errno: EFAULT}
	}
	return Result{}
}

// SysSysinfo fills a plausible `struct sysinfo` — enough RAM for libc
// heuristics; uptime comes from the guest clock so it agrees with
// clock_gettime(CLOCK_BOOTTIME) (0 in pinned-Epoch mode).
func SysSysinfo(c *Context, f *SyscallFrame) Result {
	buf := make([]byte, c.Codecs.SysinfoSize())
	err := c.Codecs.EncodeSysinfo(buf, Sysinfo{
		UptimeSec: uint64(c.SinceBoot() / time.Second),
		TotalRAM:  4 * 1024 * 1024 * 1024,
		FreeRAM:   2 * 1024 * 1024 * 1024,
		Procs:     64,
		MemUnit:   1, // bytes
	})
	if err != nil {
		return Result{Errno: EINVAL}
	}
	c.B.MemWrite(emu.GuestAddr(f.Args[0]), buf)
	return Result{}
}

// SysReadlinkat resolves the handful of /proc symlinks libc reads at startup.
func SysReadlinkat(c *Context, f *SyscallFrame) Result {
	a := f.Args
	path := c.readCStr(a[1])
	var target string
	switch path {
	case "/proc/self/exe":
		target = "/system/bin/app_process64"
	case "/proc/self/cwd":
		target = "/"
	default:
		if c.Verbose {
			fmt.Printf("[readlinkat] %q -> ENOENT\n", path)
		}
		return Result{Errno: ENOENT}
	}
	n := uint64(len(target))
	if n > a[3] {
		n = a[3]
	}
	c.B.MemWrite(emu.GuestAddr(a[2]), []byte(target)[:n])
	return Result{Value: n}
}

// SysGetdents64 reports an empty directory (end-of-stream). A real enumeration
// of the VFS could go here; empty is correct and safe for callers that iterate.
func SysGetdents64(c *Context, f *SyscallFrame) Result { return Result{} }

// SysGetcwd writes the current working directory (root) including the NUL.
func SysGetcwd(c *Context, f *SyscallFrame) Result {
	a := f.Args
	cwd := []byte("/\x00")
	if uint64(len(cwd)) > a[1] {
		return Result{Errno: ERANGE}
	}
	c.B.MemWrite(emu.GuestAddr(a[0]), cwd)
	return Result{Value: uint64(len(cwd))}
}

// SysPrlimit64 returns sensible RLIMITs (stack 8 MiB, files 1024, else infinity).
func SysPrlimit64(c *Context, f *SyscallFrame) Result {
	a := f.Args
	if old := a[3]; old != 0 {
		rl := Rlimit{Cur: ^uint64(0), Max: ^uint64(0)} // RLIM_INFINITY
		switch a[1] {
		case 3: // RLIMIT_STACK
			rl.Cur, rl.Max = 8*1024*1024, 8*1024*1024
		case 7: // RLIMIT_NOFILE
			rl.Cur, rl.Max = 1024, 4096
		}
		buf := make([]byte, c.Codecs.RlimitSize())
		if err := c.Codecs.EncodeRlimit(buf, rl); err != nil {
			return Result{Errno: EINVAL}
		}
		c.B.MemWrite(emu.GuestAddr(old), buf)
	}
	return Result{}
}

// SysIoctl is a permissive no-op (success); the sign path issues no meaningful
// ioctls. Logged under -v so a load-bearing one is noticeable.
func SysIoctl(c *Context, f *SyscallFrame) Result {
	if c.Verbose {
		fmt.Printf("[ioctl] fd=%d req=0x%x -> 0\n", f.Args[0], f.Args[1])
	}
	return Result{}
}

// SysSchedGetaffinity reports up to 8 online CPUs and returns the mask byte
// count. The mask is a plain byte blob (no layout dependence), not a codec
// struct.
func SysSchedGetaffinity(c *Context, f *SyscallFrame) Result {
	a := f.Args
	n := a[1] // cpusetsize
	if n == 0 {
		return Result{Errno: EINVAL}
	}
	if n > 8 {
		n = 8
	}
	mask := make([]byte, n)
	mask[0] = 0xFF // CPUs 0..7 online
	c.B.MemWrite(emu.GuestAddr(a[2]), mask)
	return Result{Value: n}
}

// SysStatx fills a minimal `struct statx` (like newfstatat, statx ABI).
func SysStatx(c *Context, f *SyscallFrame) Result {
	a := f.Args
	path := c.readCStr(a[1])
	var size int64 = -1
	isDir := c.dirs[path]
	switch {
	case isDir:
		size = 4096
	default:
		if data, err := c.VFS.Read(path); err == nil {
			size = int64(len(data))
		} else if w, ok := c.wstore()[path]; ok {
			size = int64(len(w))
		}
	}
	if size < 0 {
		if c.Verbose {
			fmt.Printf("[statx] %q -> ENOENT\n", path)
		}
		return Result{Errno: ENOENT}
	}
	mode := uint16(0x81a4) // S_IFREG|0644
	if isDir {
		mode = 0x41ed // S_IFDIR|0755
	}
	buf := make([]byte, c.Codecs.StatxSize())
	err := c.Codecs.EncodeStatx(buf, Statx{
		Mask:    0x7ff, // STATX_BASIC_STATS
		Blksize: 0x1000,
		Nlink:   1,
		Mode:    mode,
		Size:    uint64(size),
		Blocks:  uint64((size + 511) / 512),
	})
	if err != nil {
		return Result{Errno: EINVAL}
	}
	c.B.MemWrite(emu.GuestAddr(a[4]), buf)
	return Result{}
}
