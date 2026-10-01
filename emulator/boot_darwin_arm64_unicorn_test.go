//go:build unicorn && (darwin || linux)

// acceptance: the FULL emulator boot flow (emulator.New → LoadLibrary →
// CallSymbol) on a Darwin/ARM64 target — the same ARM64 CPU as the Android
// targets, everything else flipped: Mach-O container (dyld rebase/bind
// opcodes instead of RELA), Darwin platform (x16 syscall number, svc #0x80,
// carry+errno result encoding, exec-style initial stack frame with NO auxv).
// Boot derives the platform from the probe (MH_MAGIC_64 -> Darwin), selects
// the Darwin personality (transport/table/codecs), and links the fixture's
// single import (host_magic) through the SymbolResolver contract to a host
// stub.
package emulator

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/darwin"
)

func TestBootDarwinARM64EndToEnd(t *testing.T) {
	const dylib = "../examples/native/hello_darwin_arm64.dylib"
	if _, err := os.Stat(dylib); err != nil {
		t.Skipf("fixture not present: %v", err)
	}

	hostMagicRan := 0
	e, err := New(Config{
		SOPath: dylib,
		Engine: "unicorn",
		Pid:    4242,
		// No AssetRoot: the Darwin boot must not touch the Android asset
		// tree (ships no Darwin runtime libraries).
	}, WithPlatformConfig(darwin.NewConfig(
		darwin.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 {
				hostMagicRan++
				v, _ := ctx.(*Hook).Arg(0)
				return v.Raw * 2
			},
		}),
	)))
	if err != nil {
		t.Fatalf("New (full Darwin boot): %v", err)
	}
	defer e.Close()

	// The probe-derived Target: Mach-O format, Darwin platform, ARM64 arch.
	if e.target.Format != loader.FormatMachO || e.target.Platform != platform.Darwin {
		t.Fatalf("target = (%v, %v), want (macho, darwin)", e.target.Format, e.target.Platform)
	}

	call := func(name string, args ...uint64) uint64 {
		t.Helper()
		v, err := e.CallSymbol(name, Words(args...)...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	}

	if got := call("add", 2, 3); got != 5 {
		t.Fatalf("add(2,3) = %d, want 5", got)
	}
	// REBASE_TYPE_POINTER: fptr_table[0] was relocated by the load bias and
	// is callable from guest code: seven() + add(1,2) = 10.
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (rebased internal pointer)", got)
	}
	// BIND_TYPE_POINTER: host_fp's slot went through the SymbolResolver to a
	// host stub; the call traps via svc #0 to the interposed HostFunc.
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if hostMagicRan != 1 {
		t.Fatalf("host_magic ran %d times, want 1", hostMagicRan)
	}
	// Real Darwin syscall: svc #0x80 -> onSyscallTrap -> DarwinARM64Transport
	// decode (x16=20) -> XNU number table -> getpid; success encoding clears
	// carry and returns the value in x0.
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242", got)
	}
	// Unimplemented Darwin syscall (0x7fff): table miss -> ENOSYS with the
	// DARWIN numbering (78, not Linux's 38) and carry set; the guest packs
	// (carry << 32) | errno.
	if got := call("guest_bogus_syscall"); got != (1<<32)|78 {
		t.Fatalf("guest_bogus_syscall() = %#x, want %#x (carry set + Darwin ENOSYS 78)", got, uint64((1<<32)|78))
	}

	// The StartupABI is the Darwin one — an exec-style initial stack frame,
	// NO auxv: argc sits at StackTop = StackBase+StackSize-StackTopReserve,
	// exactly where the boot parked SP.
	ds, ok := e.startup.(*darwin.StartupABI)
	if !ok {
		t.Fatalf("startup = %T, want *darwin.StartupABI (no auxv on Darwin)", e.startup)
	}
	wantSP := uint64(e.layout.StackBase) + uint64(e.layout.StackSize) - darwin.StackTopReserve
	if uint64(ds.StackTop()) != wantSP {
		t.Fatalf("StartupABI.StackTop = %#x, want %#x (SP the boot set)", ds.StackTop(), wantSP)
	}
	b, err := e.be.MemRead(ds.StackTop(), 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(b); got != 1 {
		t.Fatalf("argc at SP = %d, want 1 (exec-style initial frame)", got)
	}
}
