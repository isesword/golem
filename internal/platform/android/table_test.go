package android

import (
	"reflect"
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// handlerID identifies a handler function for identity comparison: every
// DefaultHandlers field is a package-level func (or the shared stub0), so
// code pointers are stable and comparable.
func handlerID(h kernel.Handler) uintptr { return reflect.ValueOf(h).Pointer() }

// TestARM64SyscallTableBinding pins the Android/AArch64 number -> semantic
// handler binding against the asm-generic unistd values, as migrated verbatim
// from the kernel's retired Android table constructor in. The literal
// numbers here are the pin: if a SYS_* constant's value or a binding line
// ever drifts, the expected key set or handler identity stops matching.
func TestARM64SyscallTableBinding(t *testing.T) {
	h := kernel.DefaultHandlers()
	tab := NewARM64SyscallTable(h)

	want := map[uint64]kernel.Handler{
		17:  h.Getcwd,
		29:  h.Ioctl,
		34:  h.Mkdirat,
		48:  h.Faccessat,
		56:  h.Openat,
		57:  h.Close,
		61:  h.Getdents64,
		62:  h.Lseek,
		63:  h.Read,
		64:  h.Write,
		66:  h.Writev,
		78:  h.Readlinkat,
		79:  h.Newfstatat,
		80:  h.Fstat,
		93:  h.Exit,
		94:  h.ExitGroup,
		96:  h.SetTidAddress,
		98:  h.Futex,
		99:  h.SetRobustList,
		113: h.ClockGettime,
		123: h.SchedGetaffinity,
		124: h.SchedYield,
		134: h.RtSigaction,
		135: h.RtSigprocmask,
		160: h.Uname,
		167: h.Prctl,
		169: h.Gettimeofday,
		172: h.Getpid,
		173: h.Getppid,
		174: h.Getuid,
		175: h.Geteuid,
		178: h.Gettid,
		179: h.Sysinfo,
		214: h.Brk,
		215: h.Munmap,
		222: h.Mmap,
		226: h.Mprotect,
		233: h.Madvise,
		261: h.Prlimit64,
		278: h.Getrandom,
		291: h.Statx,
	}

	if len(tab.Handlers) != len(want) {
		t.Errorf("table has %d handlers, want %d", len(tab.Handlers), len(want))
	}
	for num, wh := range want {
		gh, ok := tab.Lookup(num)
		if !ok {
			t.Errorf("syscall #%d missing from table", num)
			continue
		}
		if handlerID(gh) != handlerID(wh) {
			t.Errorf("syscall #%d bound to the wrong handler", num)
		}
	}
	for num := range tab.Handlers {
		if _, ok := want[num]; !ok {
			t.Errorf("unexpected syscall #%d in table", num)
		}
	}
}

// TestARM64SyscallTableNames pins the trace-name map exactly (including the
// named-but-unimplemented numbers: pread64/ppoll/nanosleep/clock_nanosleep/
// mremap/socket/connect) and that every implemented number has a name.
func TestARM64SyscallTableNames(t *testing.T) {
	tab := NewARM64SyscallTable(kernel.DefaultHandlers())

	wantNames := map[uint64]string{
		17: "getcwd", 29: "ioctl", 34: "mkdirat", 48: "faccessat",
		56: "openat", 57: "close", 61: "getdents64", 62: "lseek",
		63: "read", 64: "write", 66: "writev", 67: "pread64",
		73: "ppoll", 78: "readlinkat", 79: "newfstatat", 80: "fstat",
		93: "exit", 94: "exit_group", 96: "set_tid_address", 98: "futex",
		99: "set_robust_list", 101: "nanosleep", 113: "clock_gettime",
		115: "clock_nanosleep", 123: "sched_getaffinity", 124: "sched_yield",
		134: "rt_sigaction", 135: "rt_sigprocmask", 160: "uname", 167: "prctl",
		169: "gettimeofday", 172: "getpid", 173: "getppid", 174: "getuid",
		175: "geteuid", 178: "gettid", 179: "sysinfo", 198: "socket",
		203: "connect", 214: "brk", 215: "munmap", 216: "mremap",
		222: "mmap", 226: "mprotect", 233: "madvise", 261: "prlimit64",
		278: "getrandom", 291: "statx",
	}
	if !reflect.DeepEqual(tab.Names, wantNames) {
		t.Errorf("Names = %v, want %v", tab.Names, wantNames)
	}
	for num := range tab.Handlers {
		if tab.Name(num) == "" {
			t.Errorf("table syscall #%d has no Names entry", num)
		}
	}
}
