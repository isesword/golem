package kernel

// AArch64 syscall numbers (asm-generic unistd) and the Android/AArch64
// dispatch table constructor.
//
// Why this lives in kernel rather than platform/android: kernel's INTERNAL
// test suite dispatches real syscalls through the real table, and Go forbids
// a package's internal test files from importing a package that imports it
// (kernel_test → platform/android → kernel would be an import cycle).
// Moving the constructor to platform/android would force the whole suite to
// the external kernel_test package with test-only exports of Context
// internals — far more churn for no design gain. platform/android re-exports
// this constructor as android.NewSyscallTable, so the composition root still
// sources every platform piece (transport, table, codecs) from the platform
// package, and the dependency direction stays platform/android → kernel → emu.

// Only the numbers golem's handler set implements / that bionic is likely to
// invoke on the call path are listed.
const (
	SYS_getcwd            = 17
	SYS_mkdirat           = 34
	SYS_ioctl             = 29
	SYS_faccessat         = 48
	SYS_openat            = 56
	SYS_close             = 57
	SYS_pipe2             = 59
	SYS_getdents64        = 61
	SYS_lseek             = 62
	SYS_read              = 63
	SYS_write             = 64
	SYS_writev            = 66
	SYS_pread64           = 67
	SYS_ppoll             = 73
	SYS_readlinkat        = 78
	SYS_newfstatat        = 79
	SYS_fstat             = 80
	SYS_exit              = 93
	SYS_exit_group        = 94
	SYS_set_tid_address   = 96
	SYS_futex             = 98
	SYS_set_robust_list   = 99
	SYS_nanosleep         = 101
	SYS_clock_gettime     = 113
	SYS_clock_nanosleep   = 115 // intercepted by the emulator's scheduler, no handler
	SYS_sched_getaffinity = 123
	SYS_sched_yield       = 124
	SYS_kill              = 129
	SYS_tgkill            = 131
	SYS_rt_sigaction      = 134
	SYS_rt_sigprocmask    = 135
	SYS_rt_sigtimedwait   = 137
	SYS_uname             = 160
	SYS_prctl             = 167
	SYS_gettimeofday      = 169
	SYS_getpid            = 172
	SYS_getppid           = 173
	SYS_getuid            = 174
	SYS_geteuid           = 175
	SYS_gettid            = 178
	SYS_sysinfo           = 179
	SYS_socket            = 198
	SYS_connect           = 203
	SYS_brk               = 214
	SYS_munmap            = 215
	SYS_mremap            = 216
	SYS_clone             = 220
	SYS_mmap              = 222
	SYS_mprotect          = 226
	SYS_madvise           = 233
	SYS_prlimit64         = 261
	SYS_getrandom         = 278
	SYS_statx             = 291
)

// NewAndroidARM64Table builds the Android/AArch64 syscall dispatch table:
// asm-generic numbers bound to the kernel's semantics handlers, plus trace
// names. Unimplemented numbers fall through Dispatch to a logged ENOSYS,
// which is how you discover the next syscall to implement when bringing a new
// .so up.
func NewAndroidARM64Table() *Table {
	return &Table{
		Handlers: map[uint64]Handler{
			SYS_getpid:          func(c *Context, _ *SyscallFrame) Result { return Result{Value: uint64(c.Pid)} },
			SYS_getppid:         func(c *Context, _ *SyscallFrame) Result { return Result{Value: 1} },
			SYS_gettid:          func(c *Context, _ *SyscallFrame) Result { return Result{Value: uint64(c.Pid)} },
			SYS_getuid:          func(c *Context, _ *SyscallFrame) Result { return Result{Value: 10000} },
			SYS_geteuid:         func(c *Context, _ *SyscallFrame) Result { return Result{Value: 10000} },
			SYS_sched_yield:     stub0,
			SYS_set_tid_address: func(c *Context, _ *SyscallFrame) Result { return Result{Value: uint64(c.Pid)} },
			SYS_set_robust_list: stub0,
			SYS_rt_sigaction:    stub0,
			SYS_rt_sigprocmask:  stub0,
			SYS_prctl:           stub0,
			SYS_madvise:         stub0,

			SYS_mmap:     SysMmap,
			SYS_munmap:   SysMunmap,
			SYS_mprotect: SysMprotect,

			SYS_exit:       SysExit,
			SYS_exit_group: SysExit,

			SYS_brk:               SysBrk,
			SYS_openat:            SysOpenat,
			SYS_close:             SysClose,
			SYS_read:              SysRead,
			SYS_write:             SysWrite,
			SYS_writev:            SysWritev,
			SYS_readlinkat:        SysReadlinkat,
			SYS_newfstatat:        SysNewfstatat,
			SYS_fstat:             SysFstat,
			SYS_faccessat:         SysFaccessat,
			SYS_mkdirat:           SysMkdirat,
			SYS_lseek:             SysLseek,
			SYS_getcwd:            SysGetcwd,
			SYS_getdents64:        SysGetdents64,
			SYS_clock_gettime:     SysClockGettime,
			SYS_gettimeofday:      SysGettimeofday,
			SYS_uname:             SysUname,
			SYS_sysinfo:           SysSysinfo,
			SYS_getrandom:         SysGetrandom,
			SYS_prlimit64:         SysPrlimit64,
			SYS_futex:             SysFutex,
			SYS_ioctl:             SysIoctl,
			SYS_statx:             SysStatx,
			SYS_sched_getaffinity: SysSchedGetaffinity,
		},
		Names: map[uint64]string{
			SYS_getcwd: "getcwd", SYS_ioctl: "ioctl", SYS_faccessat: "faccessat",
			SYS_openat: "openat", SYS_close: "close", SYS_getdents64: "getdents64",
			SYS_lseek: "lseek", SYS_read: "read", SYS_write: "write", SYS_writev: "writev",
			SYS_pread64: "pread64", SYS_ppoll: "ppoll", SYS_readlinkat: "readlinkat",
			SYS_newfstatat: "newfstatat", SYS_fstat: "fstat", SYS_exit: "exit",
			SYS_exit_group: "exit_group", SYS_set_tid_address: "set_tid_address",
			SYS_futex: "futex", SYS_set_robust_list: "set_robust_list",
			SYS_clock_gettime: "clock_gettime", SYS_uname: "uname", SYS_getpid: "getpid",
			SYS_getppid: "getppid", SYS_getuid: "getuid", SYS_geteuid: "geteuid",
			SYS_gettid: "gettid", SYS_sysinfo: "sysinfo", SYS_brk: "brk",
			SYS_munmap: "munmap", SYS_mremap: "mremap", SYS_mmap: "mmap",
			SYS_mprotect: "mprotect", SYS_madvise: "madvise", SYS_prctl: "prctl",
			SYS_prlimit64: "prlimit64", SYS_getrandom: "getrandom", SYS_statx: "statx",
			SYS_socket: "socket", SYS_connect: "connect", SYS_rt_sigaction: "rt_sigaction",
			SYS_rt_sigprocmask: "rt_sigprocmask", SYS_sched_yield: "sched_yield",
			SYS_sched_getaffinity: "sched_getaffinity", SYS_mkdirat: "mkdirat",
			SYS_gettimeofday: "gettimeofday", SYS_nanosleep: "nanosleep",
			SYS_clock_nanosleep: "clock_nanosleep",
		},
	}
}

// stub0 is an optimistic stub: success for syscalls real kernels commonly
// answer trivially. Kept quiet deliberately — these fire constantly (prctl,
// rt_sigprocmask, ...) and the unimplemented-ENOSYS log already covers the
// discovery path for syscalls that matter.
func stub0(c *Context, _ *SyscallFrame) Result { return Result{} }
