package kernel

// Handlers is the kernel's complete semantic handler set: one field per
// emulated syscall SEMANTIC, with no syscall numbers attached (P4b: the
// number -> handler binding lives in platform/android). Fields are nil only
// when a semantic is genuinely unimplemented.
type Handlers struct {
	// identity / process
	Getpid        Handler
	Getppid       Handler
	Gettid        Handler
	Getuid        Handler
	Geteuid       Handler
	SetTidAddress Handler

	// scheduler / signal stubs
	SchedYield       Handler
	SetRobustList    Handler
	RtSigaction      Handler
	RtSigprocmask    Handler
	Prctl            Handler
	Madvise          Handler
	SchedGetaffinity Handler

	// memory
	Mmap     Handler
	Munmap   Handler
	Mprotect Handler
	Brk      Handler

	// lifecycle
	Exit      Handler
	ExitGroup Handler

	// file IO
	Openat     Handler
	Close      Handler
	Read       Handler
	Write      Handler
	Writev     Handler
	Readlinkat Handler
	Newfstatat Handler
	Fstat      Handler
	Faccessat  Handler
	Mkdirat    Handler
	Lseek      Handler
	Getcwd     Handler
	Getdents64 Handler

	// time
	ClockGettime Handler
	Gettimeofday Handler

	// misc
	Uname     Handler
	Sysinfo   Handler
	Getrandom Handler
	Prlimit64 Handler
	Futex     Handler
	Ioctl     Handler
	Statx     Handler
}

// DefaultHandlers returns the kernel's full semantic handler set. Platforms
// bind these to their syscall numbers (Android/AArch64:
// platform/android.NewARM64SyscallTable).
func DefaultHandlers() Handlers {
	return Handlers{
		Getpid:        sysGetpid,
		Getppid:       sysGetppid,
		Gettid:        sysGettid,
		Getuid:        sysGetuid,
		Geteuid:       sysGeteuid,
		SetTidAddress: sysSetTidAddress,

		SchedYield:       stub0,
		SetRobustList:    stub0,
		RtSigaction:      stub0,
		RtSigprocmask:    stub0,
		Prctl:            stub0,
		Madvise:          stub0,
		SchedGetaffinity: SysSchedGetaffinity,

		Mmap:     SysMmap,
		Munmap:   SysMunmap,
		Mprotect: SysMprotect,
		Brk:      SysBrk,

		Exit:      SysExit,
		ExitGroup: SysExit,

		Openat:     SysOpenat,
		Close:      SysClose,
		Read:       SysRead,
		Write:      SysWrite,
		Writev:     SysWritev,
		Readlinkat: SysReadlinkat,
		Newfstatat: SysNewfstatat,
		Fstat:      SysFstat,
		Faccessat:  SysFaccessat,
		Mkdirat:    SysMkdirat,
		Lseek:      SysLseek,
		Getcwd:     SysGetcwd,
		Getdents64: SysGetdents64,

		ClockGettime: SysClockGettime,
		Gettimeofday: SysGettimeofday,

		Uname:     SysUname,
		Sysinfo:   SysSysinfo,
		Getrandom: SysGetrandom,
		Prlimit64: SysPrlimit64,
		Futex:     SysFutex,
		Ioctl:     SysIoctl,
		Statx:     SysStatx,
	}
}

// Trivial identity handlers: golem emulates a single-process guest, so the
// pid family is the Context's Pid and uids are the Android app uid.
func sysGetpid(c *Context, _ *SyscallFrame) Result  { return Result{Value: uint64(c.Pid)} }
func sysGetppid(_ *Context, _ *SyscallFrame) Result { return Result{Value: 1} }
func sysGettid(c *Context, _ *SyscallFrame) Result  { return Result{Value: uint64(c.Pid)} }
func sysGetuid(_ *Context, _ *SyscallFrame) Result  { return Result{Value: 10000} }
func sysGeteuid(_ *Context, _ *SyscallFrame) Result { return Result{Value: 10000} }

func sysSetTidAddress(c *Context, _ *SyscallFrame) Result { return Result{Value: uint64(c.Pid)} }

// stub0 is an optimistic stub: success for syscalls real kernels commonly
// answer trivially. Kept quiet deliberately — these fire constantly (prctl,
// rt_sigprocmask, ...) and the unimplemented-ENOSYS log already covers the
// discovery path for syscalls that matter.
func stub0(c *Context, _ *SyscallFrame) Result { return Result{} }
