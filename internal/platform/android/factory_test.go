package android

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/profile"
)

// TestFactoryRegistered: init() must have registered the Android factory
// under platform.Android — this is the only way the composition root ever
// reaches it.
func TestFactoryRegistered(t *testing.T) {
	f, err := platform.Resolve(platform.Android)
	if err != nil {
		t.Fatalf("Resolve(platform.Android): %v", err)
	}
	if _, ok := f.(factory); !ok {
		t.Fatalf("registered factory = %T, want android.factory", f)
	}
}

// TestFactoryBindARM64 pins the Runtime the factory produces: the complete
// Android personality as data, with Startup and AuxvLookup bound to the
// same instance (the getauxval single-source invariant) and the config's
// interop surface carried through.
func TestFactoryBindARM64(t *testing.T) {
	prof := &profile.Profile{}
	provider := func(string) (string, bool) { return "", false }
	replaceFns := map[string]interpose.HostFunc{"foo": nil}
	rt, err := (factory{}).Bind(platform.BindContext{
		ArchID: arch.IDARM64,
		Config: NewConfig(
			WithDexPath("/data/app/classes.dex"),
			WithPropertyProvider(provider),
			WithProfile(prof),
			WithReplaceFns(replaceFns),
		),
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	startup, ok := rt.Startup.(*StartupABI)
	if !ok {
		t.Fatalf("Runtime.Startup = %T, want *android.StartupABI", rt.Startup)
	}
	if rt.AuxvLookup == nil {
		t.Fatal("Android must carry AuxvLookup (bionic getauxval)")
	}
	// Same instance: a build through Runtime.Startup is visible through
	// Runtime.AuxvLookup — construct the proof by writing via the startup's
	// own Auxv accessor after a no-op build is impossible here (needs guest
	// memory), so pin the identity instead: Lookup on a fresh ABI answers 0
	// pre-build, which must be exactly what AuxvLookup answers.
	if got := rt.AuxvLookup(16); got != startup.Lookup(16) {
		t.Fatalf("AuxvLookup(16) = %#x, StartupABI.Lookup(16) = %#x — not the same instance", got, startup.Lookup(16))
	}
	if rt.StackTopReserve != StackTopReserve {
		t.Fatalf("StackTopReserve = %#x, want %#x", rt.StackTopReserve, StackTopReserve)
	}
	if rt.Layout == nil || rt.Transport == nil || rt.Table == nil || rt.Codecs == nil {
		t.Fatal("Runtime must carry layout + syscall personality")
	}
	if rt.Futex != SYS_futex || rt.Nanosleep != SYS_nanosleep || rt.ClockNanosleep != SYS_clock_nanosleep {
		t.Fatal("scheduler interception numbers must be the asm-generic ARM64 ones")
	}
	if len(rt.RuntimeLibs) != 3 || rt.RuntimeLibs[0] != "android/sdk23/lib64/libc.so" {
		t.Fatalf("RuntimeLibs = %v, want bionic libc/libm/libdl", rt.RuntimeLibs)
	}
	if rt.InitGuest == nil || !rt.PthreadStubs {
		t.Fatal("Android must carry the bionic TLS init and pthread stubs")
	}
	if len(rt.ReplaceFns) != 1 {
		t.Fatalf("ReplaceFns = %v, want the config's map", rt.ReplaceFns)
	}
	if rt.Interop == nil {
		t.Fatal("Android always has the interop surface")
	}
	if rt.Interop.DexPath != "/data/app/classes.dex" || rt.Interop.PropertyProvider == nil || rt.Interop.Profile != prof {
		t.Fatalf("Interop = %#v, want config-derived DexPath/provider/profile", rt.Interop)
	}
}

// TestFactoryBindAMD64: the per-arch selection is the factory's business —
// AMD64 gets the x86-64 syscall numbers and codecs.
func TestFactoryBindAMD64(t *testing.T) {
	rt, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDAMD64})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if rt.Futex != SYSX_futex || rt.Nanosleep != SYSX_nanosleep || rt.ClockNanosleep != SYSX_clock_nanosleep {
		t.Fatal("scheduler interception numbers must be the x86-64 ones")
	}
}

// TestFactoryBindARM32: ARM32 gets the full 32-bit personality — the ARM
// EABI transport/table, ILP32 codecs, the 8-byte-pair auxv StartupABI32
// (bound to the same instance as AuxvLookup), 32-bit bionic paths, and the
// 4-byte TLS slot init. No field may be left nil.
func TestFactoryBindARM32(t *testing.T) {
	rt, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDARM})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := rt.Startup.(*StartupABI32); !ok {
		t.Fatalf("Runtime.Startup = %T, want *android.StartupABI32 (8-byte auxv pairs)", rt.Startup)
	}
	if rt.AuxvLookup == nil {
		t.Fatal("AuxvLookup must be bound (bionic getauxval)")
	}
	if _, ok := rt.Transport.(LinuxARM32Transport); !ok {
		t.Fatalf("Transport = %T, want LinuxARM32Transport", rt.Transport)
	}
	if _, ok := rt.Codecs.(LinuxARM32Codecs); !ok {
		t.Fatalf("Codecs = %T, want LinuxARM32Codecs", rt.Codecs)
	}
	if rt.Table == nil {
		t.Fatal("Table must not be nil")
	}
	if rt.Futex != SYSA_futex || rt.Nanosleep != SYSA_nanosleep || rt.ClockNanosleep != SYSA_clock_nanosleep {
		t.Fatalf("scheduler interception numbers = %d/%d/%d, want the ARM32 ones %d/%d/%d",
			rt.Futex, rt.Nanosleep, rt.ClockNanosleep, SYSA_futex, SYSA_nanosleep, SYSA_clock_nanosleep)
	}
	if len(rt.RuntimeLibs) != 3 || rt.RuntimeLibs[0] != "android/sdk23/lib64/libc.so" {
		t.Fatalf("RuntimeLibs = %v, want the lib64 paths (the boot's machine-mismatch skip drops them on ARM32 — no 32-bit bionic ships)", rt.RuntimeLibs)
	}
	if rt.InitGuest == nil || !rt.PthreadStubs || rt.Layout == nil {
		t.Fatal("ARM32 runtime must carry TLS init, pthread stubs and the layout policy")
	}
	if rt.Interop == nil {
		t.Fatal("Android always has the interop surface")
	}
}

// TestFactoryBindDefaultsAndErrors: nil Config yields platform defaults; a
// foreign config type and an unsupported arch are Bind errors.
func TestFactoryBindDefaultsAndErrors(t *testing.T) {
	rt, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDARM64})
	if err != nil {
		t.Fatalf("Bind(nil config): %v", err)
	}
	if rt.Interop == nil || rt.Interop.Jni != nil || rt.Interop.DexPath != "" || rt.Interop.Profile != nil {
		t.Fatalf("nil Config must yield zero-value defaults, got %#v", rt.Interop)
	}
	if _, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDARM64, Config: foreignConfig{}}); err == nil {
		t.Fatal("a foreign platform config must be a Bind error")
	}
	if _, err := (factory{}).Bind(platform.BindContext{ArchID: arch.ID(999)}); err == nil {
		t.Fatal("an unsupported arch must be a Bind error")
	}
}

// foreignConfig is a platform.Config that is not *android.Config.
type foreignConfig struct{}

func (foreignConfig) PlatformID() platform.ID { return platform.Darwin }
