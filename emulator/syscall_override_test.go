package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// P10 syscall override, live: the override must take effect through REAL
// guest code (native.so's uname_machine_len wraps libc uname → svc → our
// table) and must NOT leak across emulator instances.

func newBootedOverride(tb testing.TB) *Emulator {
	tb.Helper()
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	})
	if err != nil {
		tb.Skipf("boot: %v", err)
	}
	tb.Cleanup(func() { e.Close() })
	return e
}

func unameMachineLen(tb testing.TB, e *Emulator) uint64 {
	tb.Helper()
	v, err := e.CallSymbol("uname_machine_len")
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func TestSyscallOverrideLive(t *testing.T) {
	e := newBootedOverride(t)

	// Baseline through real bionic libc: machine = "aarch64" → strlen 7.
	const baseline = 7
	if got := unameMachineLen(t, e); got != baseline {
		t.Fatalf("baseline uname_machine_len = %d, want %d", got, baseline)
	}

	// Portable resolution: uname's number comes from the table by NAME.
	nr, ok := e.SyscallNumber("uname")
	if !ok {
		t.Fatal("SyscallNumber(uname) must resolve on the ARM64 table")
	}

	// Override: swap the handler for one that answers a different identity —
	// implemented by reusing the kernel's own encoder with custom data.
	if err := e.SetSyscallHandler(nr, func(c *kernel.Context, f *kernel.SyscallFrame) kernel.Result {
		c.Uname = &kernel.UnameInfo{Sysname: "Linux", Machine: "override"}
		return kernel.SysUname(c, f)
	}); err != nil {
		t.Fatal(err)
	}
	if got := unameMachineLen(t, e); got != 8 { // strlen("override")
		t.Fatalf("overridden uname_machine_len = %d, want 8", got)
	}

	// Isolation: a SECOND emulator (fresh table per Bind) is unaffected.
	e2 := newBootedOverride(t)
	if got := unameMachineLen(t, e2); got != baseline {
		t.Fatalf("second emulator uname_machine_len = %d, want %d — override leaked across instances", got, baseline)
	}

	// Error surface: nil handler refused; unknown name not resolved; the
	// emulator stays healthy after the refused set.
	if err := e.SetSyscallHandler(nr, nil); err == nil {
		t.Fatal("SetSyscallHandler(nil) must error")
	}
	if _, ok := e.SyscallNumber("no-such-syscall"); ok {
		t.Fatal("SyscallNumber(unknown) must not resolve")
	}
	if got := unameMachineLen(t, e); got != 8 {
		t.Fatalf("post-refusal uname_machine_len = %d, want 8 (override still active)", got)
	}
}

// TestSyscallNumberSurfaceOnFake pins the resolution surface without an
// engine (the table query is pure data; the personality is Android/ARM64).
func TestSyscallNumberSurfaceOnFake(t *testing.T) {
	e := newTestEmulator(t, nil)
	if _, ok := e.SyscallNumber("definitely-not-a-syscall"); ok {
		t.Fatal("unknown name must not resolve")
	}
	if _, ok := e.SyscallNumber("uname"); !ok {
		t.Fatal("uname must resolve on the android personality table")
	}
	if err := e.SetSyscallHandler(9999, nil); err == nil {
		t.Fatal("SetSyscallHandler(nil) must error")
	}
}
