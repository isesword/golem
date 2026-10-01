package android

import "github.com/isesword/golem/internal/kernel"

// AArch64 syscall numbers (asm-generic unistd). Only the numbers golem's
// handler set implements / that bionic is likely to invoke on the call path
// are listed.
//
// the number -> semantic-handler binding lives here in the platform
// package; kernel exposes semantics only (kernel.DefaultHandlers()) and has
// no syscall-number knowledge.
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

// NewARM64SyscallTable builds the Android/AArch64 syscall dispatch table:
// asm-generic numbers bound to the kernel's semantic handlers, plus trace
// names. Unimplemented numbers fall through Dispatch to a logged ENOSYS,
// which is how you discover the next syscall to implement when bringing a new
// .so up.
func NewARM64SyscallTable(h kernel.Handlers) *kernel.Table {
	return &kernel.Table{
		Handlers: map[uint64]kernel.Handler{
			SYS_getpid:          h.Getpid,
			SYS_getppid:         h.Getppid,
			SYS_gettid:          h.Gettid,
			SYS_getuid:          h.Getuid,
			SYS_geteuid:         h.Geteuid,
			SYS_sched_yield:     h.SchedYield,
			SYS_set_tid_address: h.SetTidAddress,
			SYS_set_robust_list: h.SetRobustList,
			SYS_rt_sigaction:    h.RtSigaction,
			SYS_rt_sigprocmask:  h.RtSigprocmask,
			SYS_prctl:           h.Prctl,
			SYS_madvise:         h.Madvise,

			SYS_mmap:     h.Mmap,
			SYS_munmap:   h.Munmap,
			SYS_mprotect: h.Mprotect,

			SYS_exit:       h.Exit,
			SYS_exit_group: h.ExitGroup,

			SYS_brk:               h.Brk,
			SYS_openat:            h.Openat,
			SYS_close:             h.Close,
			SYS_read:              h.Read,
			SYS_write:             h.Write,
			SYS_writev:            h.Writev,
			SYS_readlinkat:        h.Readlinkat,
			SYS_newfstatat:        h.Newfstatat,
			SYS_fstat:             h.Fstat,
			SYS_faccessat:         h.Faccessat,
			SYS_mkdirat:           h.Mkdirat,
			SYS_lseek:             h.Lseek,
			SYS_getcwd:            h.Getcwd,
			SYS_getdents64:        h.Getdents64,
			SYS_clock_gettime:     h.ClockGettime,
			SYS_gettimeofday:      h.Gettimeofday,
			SYS_uname:             h.Uname,
			SYS_sysinfo:           h.Sysinfo,
			SYS_getrandom:         h.Getrandom,
			SYS_prlimit64:         h.Prlimit64,
			SYS_futex:             h.Futex,
			SYS_ioctl:             h.Ioctl,
			SYS_statx:             h.Statx,
			SYS_sched_getaffinity: h.SchedGetaffinity,
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
