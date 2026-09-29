package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/target"
	"github.com/isesword/golem/internal/vfs"
)

// newTestEmulator builds an Emulator for unit tests with the full platform
// personality injected — resolved Arch/CallABI/StubEncoder triple, cached role
// registers, and a kernel Context carrying the Android/AArch64 syscall
// transport, dispatch table and struct codecs exactly as New wires them (P2:
// no test may rely on zero-value coincidences; a bare &Emulator{} has a nil
// transport/table and its first guest syscall would panic). be may be nil for
// tests that never touch the backend (e.g. JNI clock tests).
func newTestEmulator(t *testing.T, be emu.Backend) *Emulator {
	t.Helper()
	cpuArch, callABI, stubEnc, feats, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatal(err)
	}
	// The layout comes from the platform's LayoutPolicy exactly as New wires
	// it (P4c) — no test-local copy of the address geometry.
	layout, err := android.LayoutPolicy{}.Resolve(
		platform.TargetInfo{Platform: platform.Android, Caps: cpuArch.Caps()},
		platform.LayoutOverrides{},
	)
	if err != nil {
		t.Fatal(err)
	}
	mem := memory.NewSpaceAt(layout.MmapRegion.Addr)
	fs := vfs.New(t.TempDir(), defaultPid, "testproc")
	pers, err := android.SyscallPersonalityFor(arch.IDARM64)
	if err != nil {
		t.Fatal(err)
	}
	// Startup and lookup are the SAME instance, exactly as the platform
	// factory binds them into the Runtime (P5b.5).
	startup := &android.StartupABI{}
	e := &Emulator{
		be:          be,
		arch:        cpuArch,
		callABI:     callABI,
		target:      &target.Target{ID: arch.IDARM64, Arch: cpuArch, CallABI: callABI, Stubs: stubEnc, Features: feats, Format: loader.FormatELF, Platform: platform.Android},
		startup:     startup,
		auxvLookup:  startup.Lookup,
		mem:         mem,
		fs:          fs,
		layout:      layout,
		as:          memory.NewAddressSpace(layout),
		dl:          loader.NewDynamicLinker(),
		jniDispatch: map[uint64]int{},
		kctx: &kernel.Context{
			B: be, Mem: mem, VFS: fs, Pid: defaultPid,
			Transport: pers.Transport,
			Table:     pers.Table,
			Codecs:    pers.Codecs,
		},
		sysFutex:         pers.Futex,
		sysNanosleep:     pers.Nanosleep,
		sysClockNanosleep: pers.ClockNanosleep,
	}
	// P2.5d: the interpose components New wires (stub manager over the
	// AddressSpace stub region; empty interposition table).
	e.stubMgr = interpose.NewStubManager(e.as, stubEnc, be)
	e.itab = interpose.NewInterposeTable()
	// P3.5: the boot resolver chain exactly as New wires it.
	e.resolver = loader.ChainResolvers(
		interpose.NewHostResolver(e.itab, e.stubMgr),
		e.dl.GlobalResolver(),
		interpose.NewUnresolvedStubResolver(e.stubMgr),
	)
	e.cacheRoleRegs()
	return e
}
