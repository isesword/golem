package emulator

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/platform/darwin"
	"github.com/isesword/golem/internal/profile"
	"github.com/isesword/golem/internal/target"
)

// androidNormTarget / darwinNormTarget are the minimal probed targets the
// platform-config normalization needs (only .Platform is consulted).
var (
	androidNormTarget = &target.Target{Platform: platform.Android}
	darwinNormTarget  = &target.Target{Platform: platform.Darwin}
)

// ---- legacy shim ------------------------------------------------------------

type shimJni struct{ dvm.AbstractJni }

// TestLegacyShimEquivalence proves the deprecated Config.Android field and
// the android.NewConfig options path produce the same normalized platform
// config — the two boot paths must converge on identical key fields .
func TestLegacyShimEquivalence(t *testing.T) {
	jni := shimJni{}
	prof := &profile.Profile{}
	provider := func(key string) (string, bool) { return "v-" + key, true }
	legacyFn := func(h *Hook) uint64 { return 42 }

	cfg := Config{Android: AndroidConfig{
		JNI:              jni,
		DexPath:          "/data/classes.dex",
		ReplaceFns:       map[string]func(h *Hook) uint64{"clock": legacyFn},
		PropertyProvider: provider,
		Profile:          prof,
	}}
	if err := normalizePlatformConfig(&cfg, androidNormTarget); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	shimmed, ok := cfg.pcfg.(*android.Config)
	if !ok {
		t.Fatalf("shimmed config = %T, want *android.Config stored in cfg.pcfg (single read site)", cfg.pcfg)
	}

	direct := android.NewConfig(
		android.WithJNI(jni),
		android.WithDexPath("/data/classes.dex"),
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"clock": func(ctx interpose.CallContext) uint64 { return 42 },
		}),
		android.WithPropertyProvider(provider),
		android.WithProfile(prof),
	)

	if shimmed.PlatformID() != platform.Android || direct.PlatformID() != platform.Android {
		t.Fatal("both paths must report platform.Android")
	}
	if shimmed.JNI != direct.JNI {
		t.Fatalf("JNI mismatch: %T vs %T", shimmed.JNI, direct.JNI)
	}
	if shimmed.DexPath != direct.DexPath {
		t.Fatalf("DexPath mismatch: %q vs %q", shimmed.DexPath, direct.DexPath)
	}
	if len(shimmed.ReplaceFns) != len(direct.ReplaceFns) {
		t.Fatalf("ReplaceFns size mismatch: %d vs %d", len(shimmed.ReplaceFns), len(direct.ReplaceFns))
	}
	// The legacy map values are adapted to interpose.HostFunc by the shim;
	// invoking through a zero Hook (the fn ignores its context) must match.
	if got := shimmed.ReplaceFns["clock"](&Hook{}); got != 42 {
		t.Fatalf("shimmed ReplaceFns entry: got %d, want 42", got)
	}
	if got := direct.ReplaceFns["clock"](&Hook{}); got != 42 {
		t.Fatalf("direct ReplaceFns entry: got %d, want 42", got)
	}
	vs, oks := shimmed.PropertyProvider("ro.x")
	vd, okd := direct.PropertyProvider("ro.x")
	if vs != vd || oks != okd {
		t.Fatalf("PropertyProvider mismatch: (%q,%v) vs (%q,%v)", vs, oks, vd, okd)
	}
	if shimmed.Profile != direct.Profile {
		t.Fatal("Profile pointer mismatch")
	}
}

// TestLegacyShimZeroConfig: neither legacy field nor option → pcfg stays
// nil; the platform factory's Bind supplies the zero-value defaults .
func TestLegacyShimZeroConfig(t *testing.T) {
	cfg := Config{}
	if err := normalizePlatformConfig(&cfg, androidNormTarget); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if cfg.pcfg != nil {
		t.Fatalf("empty legacy + no option must leave pcfg nil (factory defaults), got %T", cfg.pcfg)
	}
}

// TestLegacyShimConflict: the deprecated field and WithPlatformConfig are
// mutually exclusive — setting both must error, never silently pick one.
func TestLegacyShimConflict(t *testing.T) {
	cfg := Config{Android: AndroidConfig{DexPath: "/x.dex"}}
	opt := WithPlatformConfig(android.NewConfig())
	if err := opt(&cfg); err != nil {
		t.Fatalf("apply option: %v", err)
	}
	if err := normalizePlatformConfig(&cfg, androidNormTarget); err == nil {
		t.Fatal("legacy field + WithPlatformConfig must be an ambiguity error")
	}
}

// TestWithPlatformConfigValidation: nil is rejected at the option boundary;
// any non-nil platform.Config is accepted and stored, routed by PlatformID()
// only (— no type-switch). A config for a platform that doesn't match
// the probed target fails in the normalization step.
func TestWithPlatformConfigValidation(t *testing.T) {
	var cfg Config
	if err := WithPlatformConfig(nil)(&cfg); err == nil {
		t.Fatal("WithPlatformConfig(nil) must error")
	}
	// An unknown platform config implementation is accepted at the boundary
	// (stored as-is) — and fails normalization against the probed target.
	if err := WithPlatformConfig(fakePlatformConfig{})(&cfg); err != nil {
		t.Fatalf("any platform.Config must be accepted at the boundary: %v", err)
	}
	if cfg.pcfg != platform.Config(fakePlatformConfig{}) {
		t.Fatal("the config must land in cfg.pcfg as supplied")
	}
	if err := normalizePlatformConfig(&cfg, androidNormTarget); err == nil {
		t.Fatal("an unknown-platform config must fail normalization against the probed target")
	}
	cfg = Config{}
	if err := WithPlatformConfig(android.NewConfig())(&cfg); err != nil {
		t.Fatalf("android config must be accepted: %v", err)
	}
	if cfg.pcfg == nil {
		t.Fatal("accepted config must land in cfg.pcfg")
	}
	cfg = Config{}
	if err := WithPlatformConfig(darwin.NewConfig())(&cfg); err != nil {
		t.Fatalf("darwin config must be accepted (P5b): %v", err)
	}
	if cfg.pcfg == nil {
		t.Fatal("accepted config must land in cfg.pcfg")
	}
}

// TestNormalizePlatformMismatch: the platform config must match the PROBED
// target platform — a mismatch is a boot-time error, never a silent mis-wire.
func TestNormalizePlatformMismatch(t *testing.T) {
	// darwin config with an android (ELF) target.
	cfg := Config{}
	if err := WithPlatformConfig(darwin.NewConfig())(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := normalizePlatformConfig(&cfg, androidNormTarget); err == nil {
		t.Fatal("darwin config + android target must error")
	}
	// explicit android config with a darwin (Mach-O) target.
	cfg = Config{}
	if err := WithPlatformConfig(android.NewConfig())(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := normalizePlatformConfig(&cfg, darwinNormTarget); err == nil {
		t.Fatal("android config + darwin target must error")
	}
	// the legacy Config.Android field with a darwin target.
	cfg = Config{Android: AndroidConfig{DexPath: "/x.dex"}}
	if err := normalizePlatformConfig(&cfg, darwinNormTarget); err == nil {
		t.Fatal("legacy Android field + darwin target must error")
	}
	// darwin target with no config at all: pcfg stays nil — the platform
	// factory's Bind supplies the defaults .
	cfg = Config{}
	if err := normalizePlatformConfig(&cfg, darwinNormTarget); err != nil {
		t.Fatal(err)
	}
	if cfg.pcfg != nil {
		t.Fatal("no config on a darwin target must leave pcfg nil (factory defaults)")
	}
}

type fakePlatformConfig struct{}

func (fakePlatformConfig) PlatformID() platform.ID { return platform.ID(99) }

// ---- Target resolution ------------------------------------------------------

// fake triple, registered under a test-only arch.ID to prove explicit
// Config.Arch precedence without touching the real arm64 registration.

type fakeArch struct{}

func (fakeArch) EngineArch() emu.Arch                        { return emu.ArchARM64 }
func (fakeArch) PC() emu.Reg                                 { return 0 }
func (fakeArch) SP() emu.Reg                                 { return 0 }
func (fakeArch) PtrSize() int                                { return 8 }
func (fakeArch) ByteOrder() binary.ByteOrder                 { return binary.LittleEndian }
func (fakeArch) SetTLSBase(emu.Backend, emu.GuestAddr) error { return nil }
func (fakeArch) Caps() arch.AddressSpaceCaps {
	return arch.AddressSpaceCaps{PointerBits: 64, VABits: 39, PageSize: 0x1000, MaxUserVA: 1 << 39}
}
func (fakeArch) NormalizeCodeAddr(a emu.GuestAddr) emu.GuestAddr {
	return a
}

type fakeCallABI struct{}

func (fakeCallABI) ArgReg(i int) (emu.Reg, bool) {
	return emu.Reg(i), true
}
func (fakeCallABI) PrepareCall(emu.Backend, arch.CallRequest) error { return nil }
func (fakeCallABI) ReadArgs(emu.Backend, int) ([]uint64, error) {
	return nil, nil
}
func (fakeCallABI) WriteResult(emu.Backend, arch.CallResult) error       { return nil }
func (fakeCallABI) ReadResult(emu.Backend) (arch.CallResult, error)      { return arch.CallResult{}, nil }
func (fakeCallABI) ReturnFromCall(emu.Backend) error                     { return nil }
func (fakeCallABI) ReadReturnAddress(emu.Backend) (emu.GuestAddr, error) { return 0, nil }

type fakeStubEnc struct{}

func (fakeStubEnc) EmitStub(arch.StubKind) ([]byte, error) { return nil, nil }
func (fakeStubEnc) TrapStubAddr(pc emu.GuestAddr) emu.GuestAddr {
	return pc
}

type fakeFeatures struct{}

func (fakeFeatures) Has(arch.Feature) bool   { return false }
func (fakeFeatures) HWCAP() (uint64, uint64) { return 0, 0 }

// writeARM64ELFHeader writes just enough of an ELF64 header for
// loader.Sniff: magic, ELFDATA2LSB, e_machine=EM_AARCH64.
func writeARM64ELFHeader(t *testing.T) string {
	t.Helper()
	var hdr [20]byte
	copy(hdr[:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) // 64-bit, little-endian
	binary.LittleEndian.PutUint16(hdr[18:], uint16(arch.IDARM64))
	p := filepath.Join(t.TempDir(), "libprobe.so")
	if err := os.WriteFile(p, hdr[:], 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveTargetDefaultARM64(t *testing.T) {
	tgt, err := resolveTarget(Config{})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	real, _, _, _, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("arch.Resolve arm64: %v", err)
	}
	if tgt.Arch != real {
		t.Fatal("default target must be the registered arm64 Arch")
	}
	if tgt.CallABI == nil || tgt.Stubs == nil || tgt.Features == nil {
		t.Fatal("target must carry the full quad (CallABI, StubEncoder, CPUFeatures)")
	}
	if tgt.Format != loader.FormatELF || tgt.Platform != platform.Android || tgt.Variant != arch.VariantGeneric {
		t.Fatalf("default target = (%v, %v, %v), want (elf, android, generic)",
			tgt.Format, tgt.Platform, tgt.Variant)
	}
}

func TestResolveTargetSniffProbe(t *testing.T) {
	so := writeARM64ELFHeader(t)
	tgt, err := resolveTarget(Config{SOPath: so})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	real, _, _, _, _ := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if tgt.Arch != real {
		t.Fatal("probed arm64 header must resolve to the registered arm64 Arch")
	}
	if tgt.Format != loader.FormatELF {
		t.Fatalf("probed format = %v, want elf", tgt.Format)
	}
}

// writeMachOARM64Header writes just enough of a 64-bit little-endian Mach-O
// header for loader.Sniff: MH_MAGIC_64, cputype=ARM64, cpusubtype=ARM64_ALL.
func writeMachOARM64Header(t *testing.T) string {
	t.Helper()
	var hdr [12]byte
	binary.LittleEndian.PutUint32(hdr[0:], 0xfeedfacf) // MH_MAGIC_64
	binary.LittleEndian.PutUint32(hdr[4:], 0x0100000c) // CPU_TYPE_ARM64
	// cpusubtype 0 = CPU_SUBTYPE_ARM64_ALL
	p := filepath.Join(t.TempDir(), "libprobe.dylib")
	if err := os.WriteFile(p, hdr[:], 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestResolveTargetMachOProbeIsDarwin: the platform is DERIVED from the
// probed format — a Mach-O header flips the target to Darwin, and the
// Mach-O cputype maps onto the SAME arch id the ELF probe reports.
func TestResolveTargetMachOProbeIsDarwin(t *testing.T) {
	tgt, err := resolveTarget(Config{SOPath: writeMachOARM64Header(t)})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if tgt.Format != loader.FormatMachO || tgt.Platform != platform.Darwin {
		t.Fatalf("Mach-O target = (%v, %v), want (macho, darwin)", tgt.Format, tgt.Platform)
	}
	if tgt.ID != arch.IDARM64 {
		t.Fatalf("Mach-O arm64 cputype must map to the same arch id as ELF, got %v", tgt.ID)
	}
}

func TestResolveTargetExplicitArchWins(t *testing.T) {
	const fakeID = arch.ID(0xF0A4) // test-only, clear of EM_AARCH64 (183)
	arch.Register(fakeID, arch.VariantGeneric, fakeArch{}, fakeCallABI{}, fakeStubEnc{}, fakeFeatures{})

	// The probe says arm64; the explicit Config.Arch must win anyway, while
	// the probed format still lands in the Target.
	tgt, err := resolveTarget(Config{Arch: fakeID, SOPath: writeARM64ELFHeader(t)})
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if _, ok := tgt.Arch.(fakeArch); !ok {
		t.Fatalf("explicit Config.Arch must win over the probe, got %T", tgt.Arch)
	}
	if tgt.Format != loader.FormatELF {
		t.Fatalf("probed format must still be recorded, got %v", tgt.Format)
	}

	// Explicit arch without an SOPath: no probe, generic variant, ELF default.
	tgt, err = resolveTarget(Config{Arch: fakeID})
	if err != nil {
		t.Fatalf("resolveTarget (no SOPath): %v", err)
	}
	if _, ok := tgt.Arch.(fakeArch); !ok {
		t.Fatalf("explicit Config.Arch not honored, got %T", tgt.Arch)
	}
}

func TestResolveTargetProbeErrors(t *testing.T) {
	// Missing file: the probe fails fast (before any backend exists) instead
	// of the historical late parse failure inside boot — same New-level
	// error outcome, earlier and clearer.
	if _, err := resolveTarget(Config{SOPath: filepath.Join(t.TempDir(), "nope.so")}); err == nil {
		t.Fatal("missing SOPath must error")
	}
	// Non-ELF content.
	p := filepath.Join(t.TempDir(), "notelf.so")
	if err := os.WriteFile(p, []byte("MZ not an elf at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTarget(Config{SOPath: p}); err == nil {
		t.Fatal("non-ELF SOPath must error")
	}
	// Unknown arch id: registry miss must error, never silently fall back.
	if _, err := resolveTarget(Config{Arch: arch.ID(0x0DEF)}); err == nil {
		t.Fatal("unregistered arch ID must error")
	}
}
