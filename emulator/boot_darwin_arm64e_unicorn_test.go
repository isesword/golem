//go:build unicorn && (darwin || linux)

// P5c acceptance: the FULL emulator boot flow on a Darwin/ARM64E target —
// the same ARM64 CPU and Darwin platform as P5b, flipped to the ARM64E
// variant with LC_DYLD_CHAINED_FIXUPS (format DYLD_CHAINED_PTR_ARM64E)
// instead of classic dyld opcodes. The fixture exercises all four chain
// entry kinds end to end:
//
//	auth-bind      host_fp      <- host_magic  -> HostResolver stub (ReplaceFns)
//	bind           host_val_ptr <- host_value  -> GlobalResolver (hostdata's export)
//	auth-rebase    fptr_table[0] -> seven      -> bare image-base + runtimeOffset
//	rebase         local_ptr     -> local_val  -> bare image-base + vmaddr
//
// Authenticated entries materialize BARE addresses under PACPolicyStrip
// (loader/macho/chained.go) — and the fixture carries no PAC instructions
// at all (explicit `blr` call sites, -fno-ptrauth-returns): golem emulates
// no PAC instruction semantics.
//
// Boot shape: SOPath is the hostdata dylib (plain arm64 classic Mach-O —
// the probe still derives the Mach-O/Darwin target), so host_value is in
// the global scope BEFORE the arm64e library links; the arm64e library
// itself then loads through the public LoadLibrary path. The arm64e
// VARIANT identity of that library is asserted directly via loader.Sniff
// (the registered quad is variant-independent — c1 pinned the same-quad
// registration — so the boot target resolved from hostdata exercises the
// identical CPU/ABI/stub/features set).
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

func TestBootDarwinARM64EEndToEnd(t *testing.T) {
	const dylib = "../examples/native/hello_darwin_arm64e.dylib"
	const hostdata = "../examples/native/hostdata_darwin_arm64.dylib"
	for _, f := range []string{dylib, hostdata} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("fixture not present: %v", err)
		}
	}

	// The arm64e library's own header: Mach-O / ARM64 / VariantARM64E —
	// this is the identity resolveTarget would derive for it (the probe
	// here ran on hostdata instead, for load ordering — see the header
	// comment).
	fh, err := os.Open(dylib)
	if err != nil {
		t.Fatal(err)
	}
	format, id, variant, err := loader.Sniff(fh)
	_ = fh.Close()
	if err != nil {
		t.Fatalf("Sniff %s: %v", dylib, err)
	}
	if format != loader.FormatMachO || id != arch.IDARM64 || variant != arch.VariantARM64E {
		t.Fatalf("arm64e fixture identity = (%v, %v, %v), want (macho, arm64, arm64e)",
			format, id, variant)
	}

	hostMagicRan := 0
	e, err := New(Config{
		SOPath: hostdata, // classic arm64 Mach-O: boots the Darwin target + exports host_value
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
		t.Fatalf("New (Darwin boot on hostdata): %v", err)
	}
	defer e.Close()

	if e.target.Format != loader.FormatMachO || e.target.Platform != platform.Darwin || e.target.ID != arch.IDARM64 {
		t.Fatalf("target = (%v, %v, %v), want (macho, darwin, arm64)",
			e.target.Format, e.target.Platform, e.target.ID)
	}

	// The P5c payload: load the ARM64E library — LC_DYLD_CHAINED_FIXUPS
	// decodes into the standard Reloc contract (chained.go) and links
	// through the resolver chain: host_magic to the HostResolver stub,
	// host_value to hostdata's global-scope export.
	if _, err := e.LoadLibrary(dylib); err != nil {
		t.Fatalf("LoadLibrary (arm64e, chained fixups): %v", err)
	}

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
	// AUTH rebase: fptr_table[0] materialized as the bare seven (load bias +
	// runtimeOffset) and is callable from guest code: seven() + add(1,2) = 10.
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (auth-rebased internal pointer, PACPolicyStrip)", got)
	}
	// AUTH bind: host_fp's slot materialized the bare HostResolver stub;
	// the call traps via svc #0 to the interposed HostFunc.
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if hostMagicRan != 1 {
		t.Fatalf("host_magic ran %d times, want 1", hostMagicRan)
	}
	// Non-auth BIND across modules: host_val_ptr resolved through the
	// global scope to hostdata's host_value export.
	if got := call("read_host_value"); got != 12345678 {
		t.Fatalf("read_host_value() = %d, want 12345678 (cross-module bind to hostdata)", got)
	}
	// Non-auth rebase: local_ptr materialized local_val's guest address.
	if got := call("read_local"); got != 55 {
		t.Fatalf("read_local() = %d, want 55 (rebased data pointer)", got)
	}
	// Real Darwin syscall on the arm64e variant: x16=20, svc #0x80.
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242", got)
	}
	// Unimplemented Darwin syscall: ENOSYS with the DARWIN numbering (78)
	// and carry set.
	if got := call("guest_bogus_syscall"); got != (1<<32)|78 {
		t.Fatalf("guest_bogus_syscall() = %#x, want %#x (carry set + Darwin ENOSYS 78)", got, uint64((1<<32)|78))
	}
}
