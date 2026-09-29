//go:build unicorn && (darwin || linux)

// P5a.5 acceptance: the FULL emulator boot flow (emulator.New → LoadLibrary →
// CallSymbol) on an AMD64 target — the component-level P5a chain of
// internal/platform/android/e2e_x86_64_test.go, now driven through the real
// composition root. Boot resolves the Target from the ELF probe (EM_X86_64 →
// the amd64 Arch/CallABI/StubEncoder quad), selects the Android/AMD64 syscall
// personality (transport, number table, codecs, scheduler numbers) from
// Target.ID, and skips the AArch64-only bionic assets via the LoadModule
// machine check. At run time the SysV CallABI establishes every call frame
// and the two trap channels stay separate: host stubs on the int3
// (UC_HOOK_INTR) channel, the real getpid syscall on the syscall-instruction
// (UC_HOOK_INSN) channel.
package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform/android"
)

func TestBootAMD64EndToEnd(t *testing.T) {
	const so = "../examples/native/hello_amd64.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}

	hostMagicRan := 0
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 {
				hostMagicRan++
				return ctx.(*Hook).Arg(0) * 2
			},
		}),
	)))
	if err != nil {
		t.Fatalf("New (full AMD64 boot): %v", err)
	}
	defer e.Close()

	call := func(name string, args ...uint64) uint64 {
		t.Helper()
		v, err := e.CallSymbol(name, args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	}

	if got := call("add", 2, 3); got != 5 {
		t.Fatalf("add(2,3) = %d, want 5", got)
	}
	// 6 register args + 2 stack spill slots, established by PrepareCall.
	if got := call("sum8", 1, 2, 3, 4, 5, 6, 7, 8); got != 36 {
		t.Fatalf("sum8(1..8) = %d, want 36", got)
	}
	if got := call("sum8_observed_align"); got != 8 {
		t.Fatalf("sum8 entry RSP & 15 = %d, want 8 (post-`call` SysV convention)", got)
	}
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (RELATIVE + R_X86_64_64 relocations)", got)
	}
	// Real guest syscall: UC_HOOK_INSN → onSyscallTrap → LinuxAMD64Transport
	// decode (RAX=39) → AMD64 number table → getpid handler.
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242", got)
	}
	// Link-time import interposition: host_magic's GOT slot holds a guest
	// stub address; the int3 trap dispatches through onStubTrap to the bound
	// HostFunc, whose result WriteResult lands in RAX.
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if got := call("call_host_twice", 10); got != 42 {
		t.Fatalf("call_host_twice(10) = %d, want 42 (repeated interposition, stack intact)", got)
	}
	if hostMagicRan != 3 {
		t.Fatalf("host_magic ran %d times, want 3", hostMagicRan)
	}
}
