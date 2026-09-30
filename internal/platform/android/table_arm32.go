package android

import "github.com/isesword/golem/internal/kernel"

// ARM32 (armv7 EABI) syscall numbers — the arch/arm LEGACY table
// (arch/arm/tools/syscall.tbl, EABI __NR_SYSCALL_BASE=0), NOT asm-generic.
// Verified against the kernel source; bionic's arm32 stubs use these
// (including the private range __ARM_NR_BASE=0x0f0000 for
// set_tls/cacheflush, which the guest must never reach because golem
// interposes __set_tls and friends). Only the numbers golem's handler set
// implements / that an arm32 bionic is likely to invoke on the call path
// are listed, mirroring the ARM64 table's selection.
//
// P6d: like the other tables, the number -> semantic-handler binding lives
// here in the platform package; kernel exposes semantics only.
const (
	SYSA_exit              = 1
	SYSA_read              = 3
	SYSA_write             = 4
	SYSA_open              = 5 // legacy shape (path in arg0) — named, deliberately NOT bound
	SYSA_close             = 6
	SYSA_lseek             = 19
	SYSA_getpid            = 20
	SYSA_getuid            = 24 // 16-bit legacy; bionic uses getuid32 (named only)
	SYSA_access            = 33 // legacy shape — named, deliberately NOT bound
	SYSA_kill              = 37
	SYSA_brk               = 45
	SYSA_geteuid           = 49 // 16-bit legacy; bionic uses geteuid32 (named only)
	SYSA_ioctl             = 54
	SYSA_getppid           = 64
	SYSA_gettimeofday      = 78
	SYSA_readlink          = 85 // legacy shape — named, deliberately NOT bound
	SYSA_munmap            = 91
	SYSA_sysinfo           = 116
	SYSA_uname             = 122
	SYSA_mprotect          = 125
	SYSA_writev            = 146
	SYSA_sched_yield       = 158
	SYSA_nanosleep         = 162
	SYSA_mremap            = 163
	SYSA_prctl             = 172
	SYSA_rt_sigaction      = 174
	SYSA_rt_sigprocmask    = 175
	SYSA_rt_sigtimedwait   = 177
	SYSA_pread64           = 180 // 64-bit offset in r2:r3 (EABI pair) — named only
	SYSA_getcwd            = 183
	SYSA_ugetrlimit        = 191
	SYSA_mmap2             = 192 // offset in 4KiB units (see the binding note below)
	SYSA_stat64            = 195 // legacy shape — named, deliberately NOT bound
	SYSA_lstat64           = 196 // legacy shape — named, deliberately NOT bound
	SYSA_fstat64           = 197
	SYSA_getuid32          = 199
	SYSA_geteuid32         = 201
	SYSA_getdents64        = 217
	SYSA_madvise           = 220
	SYSA_gettid            = 224
	SYSA_readahead         = 225 // 64-bit offset in r2:r3, r1 hole (EABI pair) — named only
	SYSA_futex             = 240
	SYSA_sched_getaffinity = 242
	SYSA_exit_group        = 248
	SYSA_set_tid_address   = 256
	SYSA_clock_gettime     = 263
	SYSA_clock_nanosleep   = 265 // intercepted by the emulator's scheduler, no handler
	SYSA_tgkill            = 268
	SYSA_socket            = 281
	SYSA_connect           = 283
	SYSA_openat            = 322
	SYSA_mkdirat           = 323
	SYSA_fstatat64         = 327
	SYSA_readlinkat        = 332
	SYSA_faccessat         = 334
	SYSA_ppoll             = 336
	SYSA_set_robust_list   = 338
	SYSA_pipe2             = 359
	SYSA_prlimit64         = 369
	SYSA_getrandom         = 384
	SYSA_statx             = 397
)

// NewARM32SyscallTable builds the Android/ARM32 syscall dispatch table: the
// arch/arm legacy numbers bound to the kernel's semantic handlers, plus
// trace names. The handler SET is identical to ARM64's (the syscall
// semantics are the same Linux); only the numbering differs. Unimplemented
// numbers fall through Dispatch to a logged ENOSYS, which is how you
// discover the next syscall to implement when bringing a new .so up.
//
// Binding notes:
//   - mmap2(192) -> Mmap: mmap2's pgoffset is in 4KiB units, not bytes; the
//     semantic handler only services anonymous mappings and never reads the
//     offset, so the binding is exact for everything golem supports. A
//     file-backed mmap would need a dedicated handler dividing the offset.
//   - fstat64/fstatat64 -> Fstat/Newfstatat: the arm32 stat buffer is the
//     104-byte stat64; the LAYOUT difference is carried by LinuxARM32Codecs,
//     not by the handler binding (QEMU-thunk split, DESIGN.md invariant 7).
//   - Legacy pre-*at entry points (open/readlink/stat64/access) are named
//     but NOT bound: their argument shapes differ from the *at handlers, and
//     arm32 bionic goes through the *at forms. A guest hitting one gets a
//     loud ENOSYS in the trace instead of a silently mis-decoded call.
//   - 64-bit-argument syscalls (pread64, readahead) are named only: their
//     EABI register-pair layout needs a pair-aware binding, which is handler
//     work beyond this stage (the transport surfaces the raw r0..r5 layout;
//     see LinuxARM32Transport).
func NewARM32SyscallTable(h kernel.Handlers) *kernel.Table {
	return &kernel.Table{
		Handlers: map[uint64]kernel.Handler{
			SYSA_getpid:          h.Getpid,
			SYSA_getppid:         h.Getppid,
			SYSA_gettid:          h.Gettid,
			SYSA_getuid32:        h.Getuid,
			SYSA_geteuid32:       h.Geteuid,
			SYSA_sched_yield:     h.SchedYield,
			SYSA_set_tid_address: h.SetTidAddress,
			SYSA_set_robust_list: h.SetRobustList,
			SYSA_rt_sigaction:    h.RtSigaction,
			SYSA_rt_sigprocmask:  h.RtSigprocmask,
			SYSA_prctl:           h.Prctl,
			SYSA_madvise:         h.Madvise,

			SYSA_mmap2:    h.Mmap,
			SYSA_munmap:   h.Munmap,
			SYSA_mprotect: h.Mprotect,

			SYSA_exit:       h.Exit,
			SYSA_exit_group: h.ExitGroup,

			SYSA_brk:               h.Brk,
			SYSA_openat:            h.Openat,
			SYSA_close:             h.Close,
			SYSA_read:              h.Read,
			SYSA_write:             h.Write,
			SYSA_writev:            h.Writev,
			SYSA_readlinkat:        h.Readlinkat,
			SYSA_fstatat64:         h.Newfstatat,
			SYSA_fstat64:           h.Fstat,
			SYSA_faccessat:         h.Faccessat,
			SYSA_mkdirat:           h.Mkdirat,
			SYSA_lseek:             h.Lseek,
			SYSA_getcwd:            h.Getcwd,
			SYSA_getdents64:        h.Getdents64,
			SYSA_clock_gettime:     h.ClockGettime,
			SYSA_gettimeofday:      h.Gettimeofday,
			SYSA_uname:             h.Uname,
			SYSA_sysinfo:           h.Sysinfo,
			SYSA_getrandom:         h.Getrandom,
			SYSA_prlimit64:         h.Prlimit64,
			SYSA_futex:             h.Futex,
			SYSA_ioctl:             h.Ioctl,
			SYSA_statx:             h.Statx,
			SYSA_sched_getaffinity: h.SchedGetaffinity,
		},
		Names: map[uint64]string{
			SYSA_exit: "exit", SYSA_read: "read", SYSA_write: "write", SYSA_open: "open",
			SYSA_close: "close", SYSA_lseek: "lseek", SYSA_getpid: "getpid",
			SYSA_getuid: "getuid", SYSA_access: "access", SYSA_kill: "kill", SYSA_brk: "brk",
			SYSA_geteuid: "geteuid", SYSA_ioctl: "ioctl", SYSA_getppid: "getppid",
			SYSA_gettimeofday: "gettimeofday", SYSA_readlink: "readlink", SYSA_munmap: "munmap",
			SYSA_sysinfo: "sysinfo", SYSA_uname: "uname", SYSA_mprotect: "mprotect",
			SYSA_writev: "writev", SYSA_sched_yield: "sched_yield", SYSA_nanosleep: "nanosleep",
			SYSA_mremap: "mremap", SYSA_prctl: "prctl", SYSA_rt_sigaction: "rt_sigaction",
			SYSA_rt_sigprocmask: "rt_sigprocmask", SYSA_rt_sigtimedwait: "rt_sigtimedwait",
			SYSA_pread64: "pread64", SYSA_getcwd: "getcwd", SYSA_ugetrlimit: "ugetrlimit",
			SYSA_mmap2: "mmap2", SYSA_stat64: "stat64", SYSA_lstat64: "lstat64",
			SYSA_fstat64: "fstat64", SYSA_getuid32: "getuid32", SYSA_geteuid32: "geteuid32",
			SYSA_getdents64: "getdents64", SYSA_madvise: "madvise", SYSA_gettid: "gettid",
			SYSA_readahead: "readahead", SYSA_futex: "futex",
			SYSA_sched_getaffinity: "sched_getaffinity", SYSA_exit_group: "exit_group",
			SYSA_set_tid_address: "set_tid_address", SYSA_clock_gettime: "clock_gettime",
			SYSA_clock_nanosleep: "clock_nanosleep", SYSA_tgkill: "tgkill",
			SYSA_socket: "socket", SYSA_connect: "connect", SYSA_openat: "openat",
			SYSA_mkdirat: "mkdirat", SYSA_fstatat64: "fstatat64", SYSA_readlinkat: "readlinkat",
			SYSA_faccessat: "faccessat", SYSA_ppoll: "ppoll", SYSA_set_robust_list: "set_robust_list",
			SYSA_pipe2: "pipe2", SYSA_prlimit64: "prlimit64", SYSA_getrandom: "getrandom",
			SYSA_statx: "statx",
		},
	}
}
