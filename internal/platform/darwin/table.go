package darwin

import "github.com/isesword/golem/internal/kernel"

// XNU/ARM64 BSD syscall numbers (bsd/sys/syscall.h). P5b binds only the
// pid/uid family the e2e acceptance chain exercises; every other number —
// and every Mach trap (negative) — falls through Dispatch to a logged ENOSYS,
// which is how you discover the next syscall to implement when bringing a new
// .dylib up. The number -> semantic-handler binding lives here in the
// platform package; kernel exposes semantics only (kernel.DefaultHandlers()).
const (
	SYS_getpid  = 20
	SYS_getuid  = 24
	SYS_geteuid = 25
	SYS_getppid = 39
)

// NewARM64SyscallTable builds the Darwin/ARM64 syscall dispatch table: XNU
// BSD numbers bound to the kernel's semantic handlers, plus trace names.
func NewARM64SyscallTable(h kernel.Handlers) *kernel.Table {
	return &kernel.Table{
		Handlers: map[uint64]kernel.Handler{
			SYS_getpid:  h.Getpid,
			SYS_getppid: h.Getppid,
			SYS_getuid:  h.Getuid,
			SYS_geteuid: h.Geteuid,
		},
		Names: map[uint64]string{
			SYS_getpid: "getpid", SYS_getppid: "getppid",
			SYS_getuid: "getuid", SYS_geteuid: "geteuid",
		},
	}
}
