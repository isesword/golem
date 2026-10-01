package android

import "github.com/isesword/golem/internal/kernel"

// x86-64 syscall numbers (arch/x86/entry/syscalls/syscall_64.tbl — the
// x86-64 table is NOT asm-generic; it predates it). Only the numbers golem's
// handler set implements / that an x86-64 bionic is likely to invoke on the
// call path are listed, mirroring the ARM64 table's selection.
//
// like the ARM64 table, the number -> semantic-handler binding lives in
// the platform package; kernel exposes semantics only.
const (
	SYSX_read              = 0
	SYSX_write             = 1
	SYSX_close             = 3
	SYSX_fstat             = 5
	SYSX_lseek             = 8
	SYSX_mmap              = 9
	SYSX_mprotect          = 10
	SYSX_munmap            = 11
	SYSX_brk               = 12
	SYSX_rt_sigaction      = 13
	SYSX_rt_sigprocmask    = 14
	SYSX_ioctl             = 16
	SYSX_pread64           = 17
	SYSX_writev            = 20
	SYSX_sched_yield       = 24
	SYSX_mremap            = 25
	SYSX_madvise           = 28
	SYSX_nanosleep         = 35
	SYSX_getpid            = 39
	SYSX_socket            = 41
	SYSX_connect           = 42
	SYSX_exit              = 60
	SYSX_kill              = 62
	SYSX_uname             = 63
	SYSX_getcwd            = 79
	SYSX_gettimeofday      = 96
	SYSX_sysinfo           = 99
	SYSX_getuid            = 102
	SYSX_geteuid           = 107
	SYSX_getppid           = 110
	SYSX_prctl             = 157
	SYSX_gettid            = 186
	SYSX_futex             = 202
	SYSX_sched_getaffinity = 204
	SYSX_getdents64        = 217
	SYSX_set_tid_address   = 218
	SYSX_clock_gettime     = 228
	SYSX_clock_nanosleep   = 230 // intercepted by the emulator's scheduler, no handler
	SYSX_exit_group        = 231
	SYSX_tgkill            = 234
	SYSX_openat            = 257
	SYSX_mkdirat           = 258
	SYSX_newfstatat        = 262
	SYSX_readlinkat        = 267
	SYSX_faccessat         = 269
	SYSX_set_robust_list   = 273
	SYSX_pipe2             = 293
	SYSX_prlimit64         = 302
	SYSX_getrandom         = 318
	SYSX_statx             = 332
)

// NewAMD64SyscallTable builds the Android/x86-64 syscall dispatch table:
// x86-64 numbers bound to the kernel's semantic handlers, plus trace names.
// The handler SET is identical to ARM64's (the syscall semantics are the same
// Linux); only the numbering differs. Unimplemented numbers fall through
// Dispatch to a logged ENOSYS.
func NewAMD64SyscallTable(h kernel.Handlers) *kernel.Table {
	return &kernel.Table{
		Handlers: map[uint64]kernel.Handler{
			SYSX_getpid:          h.Getpid,
			SYSX_getppid:         h.Getppid,
			SYSX_gettid:          h.Gettid,
			SYSX_getuid:          h.Getuid,
			SYSX_geteuid:         h.Geteuid,
			SYSX_sched_yield:     h.SchedYield,
			SYSX_set_tid_address: h.SetTidAddress,
			SYSX_set_robust_list: h.SetRobustList,
			SYSX_rt_sigaction:    h.RtSigaction,
			SYSX_rt_sigprocmask:  h.RtSigprocmask,
			SYSX_prctl:           h.Prctl,
			SYSX_madvise:         h.Madvise,

			SYSX_mmap:     h.Mmap,
			SYSX_munmap:   h.Munmap,
			SYSX_mprotect: h.Mprotect,

			SYSX_exit:       h.Exit,
			SYSX_exit_group: h.ExitGroup,

			SYSX_brk:               h.Brk,
			SYSX_openat:            h.Openat,
			SYSX_close:             h.Close,
			SYSX_read:              h.Read,
			SYSX_write:             h.Write,
			SYSX_writev:            h.Writev,
			SYSX_readlinkat:        h.Readlinkat,
			SYSX_newfstatat:        h.Newfstatat,
			SYSX_fstat:             h.Fstat,
			SYSX_faccessat:         h.Faccessat,
			SYSX_mkdirat:           h.Mkdirat,
			SYSX_lseek:             h.Lseek,
			SYSX_getcwd:            h.Getcwd,
			SYSX_getdents64:        h.Getdents64,
			SYSX_clock_gettime:     h.ClockGettime,
			SYSX_gettimeofday:      h.Gettimeofday,
			SYSX_uname:             h.Uname,
			SYSX_sysinfo:           h.Sysinfo,
			SYSX_getrandom:         h.Getrandom,
			SYSX_prlimit64:         h.Prlimit64,
			SYSX_futex:             h.Futex,
			SYSX_ioctl:             h.Ioctl,
			SYSX_statx:             h.Statx,
			SYSX_sched_getaffinity: h.SchedGetaffinity,
		},
		Names: map[uint64]string{
			SYSX_getcwd: "getcwd", SYSX_ioctl: "ioctl", SYSX_faccessat: "faccessat",
			SYSX_openat: "openat", SYSX_close: "close", SYSX_getdents64: "getdents64",
			SYSX_lseek: "lseek", SYSX_read: "read", SYSX_write: "write", SYSX_writev: "writev",
			SYSX_pread64: "pread64", SYSX_readlinkat: "readlinkat",
			SYSX_newfstatat: "newfstatat", SYSX_fstat: "fstat", SYSX_exit: "exit",
			SYSX_exit_group: "exit_group", SYSX_set_tid_address: "set_tid_address",
			SYSX_futex: "futex", SYSX_set_robust_list: "set_robust_list",
			SYSX_clock_gettime: "clock_gettime", SYSX_uname: "uname", SYSX_getpid: "getpid",
			SYSX_getppid: "getppid", SYSX_getuid: "getuid", SYSX_geteuid: "geteuid",
			SYSX_gettid: "gettid", SYSX_sysinfo: "sysinfo", SYSX_brk: "brk",
			SYSX_munmap: "munmap", SYSX_mremap: "mremap", SYSX_mmap: "mmap",
			SYSX_mprotect: "mprotect", SYSX_madvise: "madvise", SYSX_prctl: "prctl",
			SYSX_prlimit64: "prlimit64", SYSX_getrandom: "getrandom", SYSX_statx: "statx",
			SYSX_socket: "socket", SYSX_connect: "connect", SYSX_rt_sigaction: "rt_sigaction",
			SYSX_rt_sigprocmask: "rt_sigprocmask", SYSX_sched_yield: "sched_yield",
			SYSX_sched_getaffinity: "sched_getaffinity", SYSX_mkdirat: "mkdirat",
			SYSX_gettimeofday: "gettimeofday", SYSX_nanosleep: "nanosleep",
			SYSX_clock_nanosleep: "clock_nanosleep",
		},
	}
}
