package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// TestTableBindings pins the XNU number -> semantic-handler binding and the
// trace names. The table is deliberately minimal (P5b): every other number —
// and every Mach trap — misses and falls through to ENOSYS.
func TestTableBindings(t *testing.T) {
	tab := NewARM64SyscallTable(kernel.DefaultHandlers())
	for num, name := range map[uint64]string{
		SYS_getpid: "getpid", SYS_getppid: "getppid",
		SYS_getuid: "getuid", SYS_geteuid: "geteuid",
	} {
		h, ok := tab.Lookup(num)
		if !ok || h == nil {
			t.Errorf("number %d (%s) must be bound", num, name)
		}
		if got := tab.Name(num); got != name {
			t.Errorf("Name(%d) = %q, want %q", num, got, name)
		}
	}
	if _, ok := tab.Lookup(9999); ok {
		t.Error("9999 must miss the table")
	}
	if _, ok := tab.Lookup(machMsgTrap); ok {
		t.Error("a Mach trap (negative) must miss the table")
	}
}

// TestNumbersAreXNU guards against copy-pasting the asm-generic numbers:
// getpid is 172 on Linux/AArch64 and 20 on XNU.
func TestNumbersAreXNU(t *testing.T) {
	if SYS_getpid == 172 || SYS_getppid == 173 || SYS_getuid == 174 || SYS_geteuid == 175 {
		t.Fatal("these are the Linux asm-generic numbers, not XNU's")
	}
}
