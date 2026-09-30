//go:build unicorn && (darwin || linux)

// P5d acceptance: the FULL emulator boot flow (emulator.New → LoadLibrary →
// CallSymbol) on a Darwin/ARM64 target whose Mach-O carries
// LC_DYLD_CHAINED_FIXUPS in pointer format DYLD_CHAINED_PTR_64 (2) — the
// modern chained container for PLAIN arm64, against P5b's classic opcodes
// and P5c's arm64e format 1. The fixture is the SAME source as P5b's
// (hello_darwin_arm64.c), so every behavior assertion is identical; only
// the fixup container differs: the rebase (fptr_table[0] -> seven) and the
// bind (host_fp <- host_magic) arrive through the format 2 chain decoder
// (chained.go) and the unchanged registered relocator.
package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/darwin"
)

func TestBootDarwinARM64ChainedEndToEnd(t *testing.T) {
	const dylib = "../examples/native/hello_darwin_arm64_chained.dylib"
	if _, err := os.Stat(dylib); err != nil {
		t.Skipf("fixture not present: %v", err)
	}

	// The fixture's own header: Mach-O / ARM64 / VariantGeneric — plain
	// arm64 (subtype 0), NOT the arm64e variant, despite the chained
	// container.
	fh, err := os.Open(dylib)
	if err != nil {
		t.Fatal(err)
	}
	format, id, variant, err := loader.Sniff(fh)
	_ = fh.Close()
	if err != nil {
		t.Fatalf("Sniff %s: %v", dylib, err)
	}
	if format != loader.FormatMachO || id != arch.IDARM64 || variant != arch.VariantGeneric {
		t.Fatalf("fixture identity = (%v, %v, %v), want (macho, arm64, generic)",
			format, id, variant)
	}

	hostMagicRan := 0
	e, err := New(Config{
		SOPath: dylib,
		Engine: "unicorn",
		Pid:    4242,
		// No AssetRoot: the Darwin boot must not touch the Android asset
		// tree (P5b ships no Darwin runtime libraries).
	}, WithPlatformConfig(darwin.NewConfig(
		darwin.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 {
				hostMagicRan++
				return mustArg(ctx.(*Hook), 0) * 2
			},
		}),
	)))
	if err != nil {
		t.Fatalf("New (full Darwin boot, format 2 chained fixups): %v", err)
	}
	defer e.Close()

	if e.target.Format != loader.FormatMachO || e.target.Platform != platform.Darwin || e.target.ID != arch.IDARM64 {
		t.Fatalf("target = (%v, %v, %v), want (macho, darwin, arm64)",
			e.target.Format, e.target.Platform, e.target.ID)
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
	// Format 2 rebase: fptr_table[0] materialized as bias + seven's vmaddr
	// (36-bit target) and is callable: seven() + add(1,2) = 10.
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (format 2 rebased internal pointer)", got)
	}
	// Format 2 bind: host_fp's slot went through the SymbolResolver to a
	// host stub; the call traps via svc #0 to the interposed HostFunc.
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if hostMagicRan != 1 {
		t.Fatalf("host_magic ran %d times, want 1", hostMagicRan)
	}
	// Real Darwin syscall: x16=20, svc #0x80.
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242", got)
	}
	// Unimplemented Darwin syscall: ENOSYS with the DARWIN numbering (78)
	// and carry set.
	if got := call("guest_bogus_syscall"); got != (1<<32)|78 {
		t.Fatalf("guest_bogus_syscall() = %#x, want %#x (carry set + Darwin ENOSYS 78)", got, uint64((1<<32)|78))
	}
}
