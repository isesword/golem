//go:build unicorn && (darwin || linux)

// P6e acceptance: the FULL emulator boot flow (emulator.New → LoadLibrary →
// CallSymbol) on an Android/ARM32 target — the THIRD architecture end to
// end: probe (EM_ARM) → Target(Android + ARM + ELF32) → unicorn ARM32
// backend → 32-bit LayoutPolicy → ELF32 map + REL relocations (implicit
// addend) → SymbolResolver → FinalizeImage → StartupABI32 (Elf32 auxv) →
// calls. The fixture is -nostdlib armv7 (zig cc), with the AArch64 bionic
// dropped by the boot's machine-mismatch skip (P5a.5 convention).
//
// What this test pins beyond "it boots":
//   - AAPCS32 pair semantics on REAL compiler output: add64lohi(u32, u64)
//     must read a from r0 and b from r2:r3 — only the typed CallArg entry
//     places b there; the naive word entry misplaces it (asserted wrong).
//   - Thumb interworking: thumb_add's export value carries bit0; the call
//     chain (PrepareCall setPCBX + backend Thumb entry) must decode Thumb.
//   - REL relocation kinds the P6c relocator covers: R_ARM_RELATIVE (the
//     fptr_table rebase), R_ARM_ABS32 (the host_magic bind), R_ARM_GLOB_DAT.
//   - The ARM32 Linux syscall ABI: r7 number, svc #0 (P6d transport/table).
package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
)

func TestBootAndroidARM32EndToEnd(t *testing.T) {
	const so = "../examples/native/hello_android_arm32.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	// The ARM32 boot loads the platform RuntimeLibs (32-bit bionic, factory.go),
	// which are NOT tracked in git (public repo — see .gitignore); fetch them
	// with scripts/fetch_bionic_arm32.sh.
	const bionic = "../assets/android/sdk23/lib/libc.so"
	if _, err := os.Stat(bionic); err != nil {
		t.Skipf("ARM32 bionic assets not fetched: %v (run scripts/fetch_bionic_arm32.sh)", err)
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
				v, _ := ctx.(*Hook).Arg(0)
				return v.Raw * 2
			},
		}),
	)))
	if err != nil {
		t.Fatalf("New (full Android/ARM32 boot): %v", err)
	}
	defer e.Close()

	// The probe-derived Target: ELF format, Android platform, EM_ARM arch,
	// generic variant.
	if e.target.Format != loader.FormatELF || e.target.Platform != platform.Android ||
		e.target.ID != arch.IDARM || e.target.Variant != arch.VariantGeneric {
		t.Fatalf("target = (%v, %v, %v, %v), want (elf, android, arm, generic)",
			e.target.Format, e.target.Platform, e.target.ID, e.target.Variant)
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

	// AAPCS32 pair semantics, live: add64lohi(u32 a, u64 b) = a + lo(b) +
	// hi(b). The naive WORD entry runs FIRST, on the fresh engine: it
	// truncates b to one slot (r1), the callee reads the pair from r2:r3 —
	// never written, still the engine's zero-init state — and computes a
	// visibly wrong 1. (Run second it would accidentally read the typed
	// call's leftover pair and pass — ArgKind being load-bearing is
	// sequence-dependent EXACTLY because registers are call state.)
	const want64 = 1 + 0x55667788 + 0x11223344
	if naive := call("add64lohi", 1, 0x1122334455667788); naive == want64 {
		t.Fatalf("word-entry add64lohi = %#x — must DIFFER from %#x (b truncated to r1, pair never set)", naive, uint64(want64))
	}
	// The typed entry places a in r0 and b in the r2:r3 pair — the P6
	// Architecture Exception #1 payoff on real compiler output.
	typed, err := e.CallSymbolArgs("add64lohi",
		arch.CallArg{Value: 1, Kind: arch.ArgWord},
		arch.CallArg{Value: 0x1122334455667788, Kind: arch.ArgU64})
	if err != nil {
		t.Fatalf("add64lohi (typed): %v", err)
	}
	if typed != want64 {
		t.Fatalf("add64lohi(1, 0x1122334455667788) = %#x, want %#x (a=r0, b=r2:r3)", typed, uint64(want64))
	}

	// R_ARM_RELATIVE: fptr_table[0] was relocated by the load bias and is
	// callable from guest code: seven() + add(1,2) = 10.
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (REL rebased internal pointer)", got)
	}
	// R_ARM_ABS32 bind: host_fp's slot went through the SymbolResolver to a
	// host stub; the call traps via the ARM-state stub's svc to the
	// interposed HostFunc.
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if hostMagicRan != 1 {
		t.Fatalf("host_magic ran %d times, want 1", hostMagicRan)
	}
	// THUMB interworking: thumb_add's export carries bit0; the call must
	// enter Thumb state (setPCBX + odd-start backend rule): 2*3+4 = 10.
	if got := call("thumb_add", 3, 4); got != 10 {
		t.Fatalf("thumb_add(3,4) = %d, want 10 (Thumb decode via the bit0 chain)", got)
	}
	// Real Linux syscall on ARM32: getpid, number in r7, svc #0 — the P6d
	// transport/table path.
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242", got)
	}
}
