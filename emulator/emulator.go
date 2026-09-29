// Package emulator is golem's high-level API: a minimal unidbg in Go. It boots
// an emulated AArch64 Android process, maps + links real bionic (libc/libm/libdl)
// and your target .so into guest memory through a selectable CPU backend
// (Unicorn via purego), services Linux syscalls and the JNI/JavaVM surface, and
// lets you call native functions by symbol or offset and exchange memory.
//
// Typical use:
//
//	e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
//	defer e.Close()
//	ret, _ := e.CallSymbol("add", 2, 3)   // -> 5
//
// It is engine-agnostic and JVM-free: a single Go binary, fast cold start.
package emulator

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/platform/darwin"
	"github.com/isesword/golem/internal/profile"
	"github.com/isesword/golem/internal/target"
	"github.com/isesword/golem/internal/vfs"
)

// Config controls how an Emulator boots.
type Config struct {
	// AssetRoot is the directory containing android/sdk23/... (bionic libs +
	// synthetic /proc, properties, tzdata). Empty = auto-locate (see Locate).
	AssetRoot string
	// NoSharedModules opts out of Phase B page sharing: by default, read-only
	// segments of every loaded module are mapped zero-copy from ONE set of
	// host buffers (uc_mem_map_ptr), so a pool of engines loads each .so's
	// read-only pages into physical RAM exactly once. Since P2.5d guest .text
	// is immutable (function replacement is interposition via an execution
	// hook, not a memory patch), nothing ever writes a shared range. Set true
	// to disable (fresh anonymous memory per engine, pre-Phase-B behavior).
	NoSharedModules bool
	// SOPath is an optional "main" shared object to load+init at boot (its
	// DT_INIT/init_array run, and JNI_OnLoad if exported). Empty = boot bionic
	// only; load libraries yourself with LoadLibrary.
	SOPath string
	// ProcessName is the emulated process name reported via /proc/self/* etc.
	ProcessName string
	// Pid reported to the guest (getpid/gettid/...). 0 = a default.
	Pid int
	// Engine selects the CPU backend: "unicorn" | "" (auto /
	// $GOLEM_ENGINE / first compiled in).
	Engine string
	// FileResolver, if set, is consulted for guest file opens the built-in VFS
	// can't satisfy: return (content, true, nil) to supply a file, (nil, true,
	// err) to force an error (e.g. a missing/denied path), or (nil, false, nil)
	// to fall through to the default "no such file". Mirrors unidbg's IOResolver.
	FileResolver func(path string) ([]byte, bool, error)
	// Verbose logs each syscall / JNI call / unresolved import.
	Verbose bool
	// Epoch, if non-zero, pins the guest clock (gettimeofday/clock_gettime) to this
	// fixed Unix time (seconds) instead of the host clock — for deterministic,
	// reproducible runs (e.g. reverse-engineering a time-dependent signature).
	Epoch int64
	// Arch explicitly selects the guest CPU architecture (P4a). 0 = probe
	// SOPath's header (loader.Sniff) when set, else default to ARM64 — the
	// pre-P4 behavior. An explicit value wins over the probe.
	Arch arch.ID
	// TCGBufferMiB caps the CPU engine's translation (JIT) buffer, in MiB,
	// applied during construction — BEFORE boot runs any guest code, because
	// unicorn's UC_CTL_TCG_BUFFER_SIZE only takes effect ahead of the first
	// uc_emu_start. 0 = engine default: on Windows with PREALLOC the engine
	// commits 16 MiB upfront (measured: full throughput at 16 MiB, regression
	// at 256 MiB+); on POSIX the buffer is lazily committed and the engine
	// leaves the size alone. Unicorn-only — on any other engine (or a build
	// without the unicorn tag) New returns an error rather than silently
	// ignoring the value.
	TCGBufferMiB int
	// Android is the Android personality of the emulated process (JNI
	// handler, dex metadata, symbol replacements, system properties).
	//
	// Deprecated: P4a moved this personality to the typed platform config —
	// use android.NewConfig(android.WithJNI(...), ...) with the
	// WithPlatformConfig option instead. This field is read exactly once, by
	// the options normalization (legacy shim), which converts it to an
	// android.Config; no internal code touches it afterwards. Setting both
	// this field and WithPlatformConfig is an error.
	Android AndroidConfig

	// LayoutOverrides optionally overrides the platform's default guest
	// address-space layout (P4c). Platform-agnostic by design, so it sits at
	// the Config top level rather than inside a platform personality. The
	// zero value means "platform defaults" and is currently the only
	// supported value (reserved for P5+).
	LayoutOverrides platform.LayoutOverrides

	// acfg is the normalized Android platform config, set by
	// WithPlatformConfig and resolved by the legacy shim in New. Never set
	// it directly; it is unexported so positional Config literals outside
	// this package already fail to compile.
	acfg *android.Config
	// dcfg is the normalized Darwin platform config (P5b) — same contract as
	// acfg. Exactly one of acfg/dcfg is non-nil after New's normalization,
	// matching the probed target platform.
	dcfg *darwin.Config
}

// AndroidConfig is the Android personality of an emulated process: the pieces
// that only make sense for an Android-flavoured guest, grouped so that a
// future iOS personality can sit next to them without polluting the
// platform-agnostic top-level Config.
//
// Deprecated: P4a re-homed this personality as android.Config — build it with
// android.NewConfig(android.WithJNI(...), ...) and pass it via
// emulator.WithPlatformConfig. This struct remains as the legacy shim input
// and is converted exactly once during options normalization.
type AndroidConfig struct {
	// JNI is the Java callback handler the guest's JNIEnv calls dispatch to.
	// nil = dvm.AbstractJni{} (everything returns null/0). Implement dvm.Jni (or
	// embed dvm.AbstractJni and override a few methods) to model the Java side.
	JNI dvm.Jni
	// DexPath optionally loads a classes.dex at boot so FindClass/GetMethodID/
	// GetFieldID resolve against real class/method/field metadata (signatures,
	// superclasses) instead of being synthesized. Metadata only — no bytecode.
	DexPath string
	// ReplaceFns installs Go implementations by symbol name, with two binding
	// paths: names the loaded modules import as UNRESOLVED symbols get their
	// stub bound to the implementation (before linking); names the loaded
	// modules EXPORT are interposed (Replace) after boot completes — an entry
	// execution hook, not a code patch. Model NDK/libc functions the guest
	// calls here (e.g. the AAssetManager family).
	ReplaceFns map[string]func(h *Hook) uint64
	// PropertyProvider, if set, answers the loaded .so's __system_property_get(key)
	// calls: return (value, true) to supply a value, or ("", false) for "unset".
	PropertyProvider func(key string) (string, bool)
	// Profile, if non-nil, installs a deterministic device-liveness model:
	// the kernel clock's monotonic origin becomes the persona's boot time (so
	// uptime/elapsedRealtime report a device that has been up for days), the
	// battery sysfs files follow a plausible charge/discharge rhythm, and the
	// JNI time getters (System.currentTimeMillis/nanoTime,
	// SystemClock.elapsedRealtime/uptimeMillis) derive uptime from the same
	// virtual clock — the cross-check consistency risk-control probes look for.
	// nil = previous behavior (host clock, no battery files). Config.Epoch still
	// takes precedence when both are set (deterministic signing mode).
	Profile *profile.Profile
}

const defaultPid = 28859

const sentinel = 0xFFFFFF00 // top-level return address for CallFunc frames (ARM64: LR; AMD64: pushed on the stack) — emu stops when PC hits it

// Module is one loaded shared object.
type Module struct {
	Name string
	Base uint64
	Img  *loader.Image
}

// Emulator is one isolated guest process.
type Emulator struct {
	cfg    Config
	engine string // resolved CPU engine name ("unicorn")
	be     emu.Backend
	mem    *memory.Space
	alloc  allocArena
	vm     *dvm.VM
	fs     *vfs.VFS
	kctx   *kernel.Context

	arch    arch.Arch            // CPU properties, from e.target (P2.5b; always ARM64 until P5)
	callABI arch.CallABI         // function calling convention (AAPCS64) — args/results/return flow
	target  *target.Target       // immutable single source of truth for arch/format/platform (P4a, DESIGN.md §4)
	layout  memory.Layout        // guest address-space layout in use
	as      *memory.AddressSpace // single guest VA allocation entry (P2.5c, invariant 12)

	// P2.5d (DESIGN.md §3.8, invariant 11): all guest trampolines are owned by
	// the StubManager; exported-symbol replacement is Function Interposition
	// via the InterposeTable + a per-entry execution hook — guest .text is
	// never patched.
	stubMgr interpose.StubManager
	itab    interpose.InterposeTable

	// Boot-cached role registers (P1, DESIGN.md §8: no interface walks on hot
	// paths). After the P5a.5 CallABI reshape only the Arch's own PC/SP remain
	// cached: argument/result/return-address flow goes through the CallABI's
	// whole-call operations (PrepareCall/ReadArgs/WriteResult/ReadResult), so
	// no call-convention register identity is cached here anymore. Callers
	// that build an Emulator literal directly (tests) must call cacheRoleRegs
	// after setting arch.
	pcReg emu.Reg // arch.PC()
	spReg emu.Reg // arch.SP()

	modules []*Module
	main    *Module // the Config.SOPath module, if any
	aForm   bool    // 当前 JNI 调用为 Call*MethodA（jvalue 数组）形式
	scCount int     // syscalls in current CallFunc (runaway guard)

	// P3.5 (DESIGN.md §3.3): symbol resolution is a first-class loader
	// component. dl owns the module graph + global symbol scope; resolver is
	// the boot chain — host replacement symbols (InterposeTable via
	// interpose.HostResolver) → global guest exports (dl.GlobalResolver) →
	// unresolved fallback stub (interpose.UnresolvedStubResolver) — the exact
	// historical resolveSymbol order, expressed as a resolver chain.
	dl       *loader.DynamicLinker
	resolver loader.SymbolResolver

	jniEnv       uint64         // guest JNIEnv* (points to a stub function table)
	javaVM       uint64         // guest JavaVM*
	getEnvStub   uint64         // JavaVM->GetEnv svc stub (special-cased)
	jniDispatch  map[uint64]int // JNIEnv stub addr -> JNINativeInterface index
	classRefs    map[string]dvm.Ref
	shared       []sharedRange          // guest ranges mapped via MemMapPtr (Phase B page sharing; P2.5d: diagnostic tracking, the privatize-on-write compensation retired with text patching)
	poisonErr    error                  // set when a failed address-space transition leaves the emulator unusable
	pendingPanic any                    // panic recovered inside a guarded backend callback; poisons at the next run boundary
	classMeta    *dvm.Class             // java/lang/Class
	natives      map[string]uint64      // "class.name+sig" -> registered native fn ptr
	methods      map[dvm.Ref]*methodRef // jmethodID -> (class, method)
	fields       map[dvm.Ref]*fieldRef  // jfieldID -> (class, field)
	classFilter  map[string]bool        // FindClass allow-set (nil = allow all)
	arrayPins    map[uint64]pinEntry    // GetByteArrayElements ptr -> array ref (copy-back)
	pinGen       uint64                 // bumped per host-initiated native call
	pendingExc   bool                   // a pending JNI exception (Throw/ThrowNew)

	// P4d (DESIGN.md §3.4, invariant 10): the process initial state is built
	// ONCE by the platform's StartupABI — Android materializes the auxv data
	// block (HWCAP from target.Features, PHDR/ENTRY from the main image
	// metadata, deterministic AT_RANDOM) and the interposed getauxval serves
	// from that same vector; Darwin (P5b) materializes an exec-style initial
	// stack frame (argc/argv/envp/apple) and has no auxv at all.
	startup      platform.StartupABI
	startupBuilt bool

	// cooperative scheduler state (see scheduler.go)
	fibers      []*fiber // pthread_create'd threads
	curFiber    *fiber   // fiber currently in a slice (nil = main thread)
	nextFiberID int
	threadCap   int    // per-slice syscall budget for the running fiber (0 = main)
	threadOps   int    // syscalls serviced in the current slice
	yieldReason int    // why the current slice stopped (yield*)
	yieldAddr   uint64 // futex uaddr the fiber parked on

	// Scheduler interception numbers, from the platform's SyscallPersonality
	// (P5a.5 — the numbers differ per guest arch; the emulator holds data,
	// not arch knowledge).
	sysFutex          uint64
	sysNanosleep      uint64
	sysClockNanosleep uint64
}

// hostFn is a native function implemented on the Go side (args in X0.., ret X0).
type hostFn func(e *Emulator, b emu.Backend)

// Modules returns the loaded modules in load order.
func (e *Emulator) Modules() []*Module { return e.modules }

// MainModule returns the Config.SOPath module (nil if none was given).
func (e *Emulator) MainModule() *Module { return e.main }

// VM returns the fake Dalvik VM (class registry + handle table).
func (e *Emulator) VM() *dvm.VM { return e.vm }

// SetFoundClassFilter restricts which classes FindClass reports as found: a
// class not on the list resolves to NULL with a pending exception (like
// unidbg's vm.addFilterFoundClass, which native anti-tamper checks rely on).
// Pass the full allow-list; nil/empty clears the filter (every class found).
func (e *Emulator) SetFoundClassFilter(names []string) {
	if len(names) == 0 {
		e.classFilter = nil
		return
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	e.classFilter = m
}

// LoadDex parses a classes.dex and registers its classes/methods/fields into the
// VM (metadata only — no bytecode execution). Returns the class count.
func (e *Emulator) LoadDex(path string) (int, error) { return e.vm.LoadDexFile(path) }

// GuestExited reports whether the guest called exit/exit_group and its code.
func (e *Emulator) GuestExited() (bool, int) { return e.kctx.Exited, e.kctx.ExitCode }

// Engine reports which CPU engine this emulator is running on ("unicorn" /
// as resolved from Config.Engine / $GOLEM_ENGINE / the default.
func (e *Emulator) Engine() string { return e.engine }

// Backend exposes the CPU engine (for engine-level capabilities such as
// emu.SetTCGBufferSize). Prefer the Emulator's own APIs when they cover the
// need; this is the escape hatch for backend-specific configuration.
func (e *Emulator) Backend() emu.Backend { return e.be }

// MemStats reports guest address-space bookkeeping: the region count and the
// mmap high-water cursor. Diagnostic aid for long-lived emulators — a region
// count that grows on every call indicates the guest (or the call path) is
// leaking guest VA.
func (e *Emulator) MemStats() (regions int, mmapTop uint64) {
	return len(e.mem.Regions()), e.mem.MmapTop()
}

// New boots an emulator: prepares the address space, maps bionic, and (if
// Config.SOPath is set) loads + initializes the main library.
//
// Boot follows the DESIGN.md §4 sequence, as explicitly staged below (P4e
// boot-sequence consolidation — the stages are ordered statements in this
// function, locked by the invariant tests in boot_order_test.go):
//
//	stage 1  apply functional options (the Config.Android legacy shim runs
//	         inside the platform-config normalization, after the probe —
//	         the config must match the PROBED platform, P5b)
//	stage 2  lightweight probe (loader.Sniff: SO header only — no mapping,
//	         no relocation, no backend)
//	stage 3  resolve Arch + CallABI + StubEncoder + Features + Format +
//	         Platform and build the immutable Target — after this point no
//	         lower layer may re-guess arch/platform from header or config;
//	         then normalize the platform config against the probed platform
//	stage 4  LayoutPolicy → memory.Layout (pure geometry)
//	stage 5  emu.NewNamed: create the CPU backend
//	stage 6  pre-run backend settings (TCG buffer — must land before the
//	         first guest execution; fails fast before any mapping)
//	stage 7  Emulator skeleton: AddressSpace (the single VA allocation
//	         entry), StubManager/InterposeTable, resolver chain
//	stage 8  platform runtime components (syscall transport/table/codecs,
//	         StartupABI, host functions, JNI handler)
//	stage 9  materialize the layout: reserve + map stack/TLS/stub regions,
//	         set SP, set TLS base
//	stage 10 install runtime hooks/traps (SVC routing, invalid-mem
//	         diagnostics) — inert until execution, but they must be live
//	         before stage 11 because LoadLibrary couples loading with init
//	         execution
//	stage 11 boot(): Load images → Relocate/bind (SymbolResolver) →
//	         FinalizeImage (RW→RX) → StartupABI.BuildInitialState (main
//	         image only, after FinalizeImage, before init) → run init
//	stage 12 post-boot: interpose exported ReplaceFns symbols; New returns
//	         with guest execution now allowed
//
// opts are P4a functional options (WithPlatformConfig, ...); existing callers
// passing just a Config are unaffected.
func New(cfg Config, opts ...Option) (e *Emulator, err error) {
	// §4 stage 1: apply functional options.
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	// §4 stages 2–3: probe → resolve arch triple → immutable Target.
	tgt, err := resolveTarget(cfg)
	if err != nil {
		return nil, err
	}
	// Then normalize the platform config against the PROBED platform (P5b):
	// this is the legacy shim's only read site of Config.Android, and the
	// android/darwin config <-> target platform mismatch check. Exactly one
	// of acfg/dcfg comes back non-nil.
	acfg, dcfg, err := normalizePlatformConfig(&cfg, tgt)
	if err != nil {
		return nil, err
	}
	// §4 stage 4: the platform's LayoutPolicy plans the initial guest address
	// space (pure geometry — no Map/Alloc/Reserve here, P4c). This precedes
	// backend creation so a layout failure never leaves an engine behind.
	layout, err := resolveLayout(tgt, cfg.LayoutOverrides)
	if err != nil {
		return nil, err
	}
	// §4 stage 5: create the CPU backend — never before the Target exists
	// (boot_order_test.go locks probe/target → backend ordering).
	engine, err := emu.Resolve(cfg.Engine)
	if err != nil {
		return nil, fmt.Errorf("backend: %w", err)
	}
	be, err := emu.NewNamed(engine, tgt.Arch.EngineArch())
	if err != nil {
		return nil, fmt.Errorf("backend(%s): %w", engine, err)
	}
	// §4 stage 6: pre-run backend settings. TCG buffer sizing must land
	// before the first uc_emu_start (boot runs guest code), and this point
	// precedes the half-booted cleanup defer below (it only fires once e is
	// assigned) — so failures here close the fresh backend by hand. A
	// non-unicorn engine reports the setting as an error via
	// SetTCGBufferSize rather than silently ignoring it.
	if cfg.TCGBufferMiB != 0 {
		if cfg.TCGBufferMiB < 0 {
			be.Close()
			return nil, fmt.Errorf("backend(%s): TCGBufferMiB must be >= 0, got %d", engine, cfg.TCGBufferMiB)
		}
		if err := emu.SetTCGBufferSize(be, uint32(cfg.TCGBufferMiB)<<20); err != nil {
			be.Close()
			return nil, fmt.Errorf("backend(%s): set TCG buffer to %d MiB: %w", engine, cfg.TCGBufferMiB, err)
		}
	}
	pid := cfg.Pid
	if pid == 0 {
		pid = defaultPid
	}
	// §4 stage 7: the Emulator skeleton — including the AddressSpace, the
	// single guest VA allocation entry (P2.5c, invariant 12) planned by the
	// stage-4 LayoutPolicy.
	e = &Emulator{
		cfg:         cfg,
		engine:      engine,
		be:          be,
		arch:        tgt.Arch,
		callABI:     tgt.CallABI,
		target:      tgt,
		layout:      layout,
		as:          memory.NewAddressSpace(layout),
		dl:          loader.NewDynamicLinker(),
		mem:         memory.NewSpaceAt(layout.MmapRegion.Addr),
		vm:          dvm.NewVM(),
		fs:          vfs.New(cfg.AssetRoot, pid, cfg.ProcessName),
		jniDispatch: map[uint64]int{},
		classRefs:   map[string]dvm.Ref{},
		shared:      []sharedRange{},
		natives:     map[string]uint64{},
		methods:     map[dvm.Ref]*methodRef{},
		fields:      map[dvm.Ref]*fieldRef{},
		arrayPins:   map[uint64]pinEntry{},
	}
	// P2.5d: trampolines and interposition state live in the interpose
	// package (DESIGN.md §3.8); the stub manager draws slots from the
	// AddressSpace's stub region and encodes them with the StubEncoder.
	e.stubMgr = interpose.NewStubManager(e.as, tgt.Stubs, be)
	e.itab = interpose.NewInterposeTable()
	// P4d/P5b: the platform's StartupABI builds the process initial state once
	// the main image's metadata is complete (LoadLibrary) or, bionic-only,
	// lazily at the first getauxval — a deliberate P4e rule, see
	// ensureStartup. Android builds the auxv data block; Darwin builds the
	// exec-style initial stack frame (no auxv exists on XNU).
	switch tgt.Platform {
	case platform.Darwin:
		e.startup = &darwin.StartupABI{}
	default:
		e.startup = &android.StartupABI{}
	}
	// P3.5: the boot symbol-resolution chain — host replacement symbols
	// (InterposeTable via the HostResolver adapter) → global guest exports
	// (DynamicLinker scope) → unresolved fallback stub. The historical
	// resolveSymbol order, as composable loader.SymbolResolvers.
	e.resolver = loader.ChainResolvers(
		interpose.NewHostResolver(e.itab, e.stubMgr),
		e.dl.GlobalResolver(),
		interpose.NewUnresolvedStubResolver(e.stubMgr),
	)
	e.cacheRoleRegs()
	// On any construction failure the half-booted engine must be torn down:
	// it already holds unicorn mappings, and repeated failed New calls would
	// otherwise leak engines. The cleanup must catch panics too — close the
	// backend, then re-panic to preserve the original signal.
	defer func() {
		if r := recover(); r != nil {
			if e != nil {
				e.be.Close()
			}
			panic(r)
		}
		if err != nil && e != nil {
			e.be.Close()
		}
	}()
	// §4 stage 8: platform runtime components — host functions, the JNI
	// handler (Android only — a Darwin guest has no Java runtime), and the
	// injected syscall personality.
	if cfg.FileResolver != nil {
		e.fs.SetFallback(cfg.FileResolver)
	}
	// replaceFns is the per-platform view of the ReplaceFns contract: both
	// personalities carry the same interpose.HostFunc map, and the two
	// binding passes (import-override below, export interposition in stage
	// 12) consume this view, never a concrete config type.
	var replaceFns map[string]interpose.HostFunc
	switch tgt.Platform {
	case platform.Darwin:
		replaceFns = dcfg.ReplaceFns
		// No classMeta/SetJni/Dex/registerHostFns/profile battery: no Java
		// runtime on Darwin, and P5b ships no Darwin libc, so there are no
		// platform host functions — ReplaceFns is the only interposition
		// source.
	default: // platform.Android
		replaceFns = acfg.ReplaceFns
		e.classMeta = e.vm.ResolveClass("java/lang/Class")
		jni := acfg.JNI
		if jni == nil {
			jni = dvm.AbstractJni{}
		}
		// The four JNI time getters are always modeled from the kernel clock (see
		// clockJni) — returning 0 for currentTimeMillis is a louder emulator tell
		// than answering them, and Epoch mode keeps them deterministic.
		e.vm.SetJni(&clockJni{Jni: jni, e: e, prof: acfg.Profile})
		if acfg.DexPath != "" {
			nc, derr := e.vm.LoadDexFile(acfg.DexPath)
			if derr != nil {
				return nil, fmt.Errorf("load dex: %w", derr)
			}
			if cfg.Verbose {
				fmt.Printf("[dex] %s -> %d classes\n", acfg.DexPath, nc)
			}
		}
		registerHostFns(e)
	}
	for name, hf := range replaceFns {
		hf := hf
		// Import-override path (P3.5): bind by NAME in the InterposeTable —
		// the HostResolver then binds every unresolved import of that name to
		// a host stub at link time. (The pre-boot e.syms branch of the old
		// first pass was dead: no module is loaded yet, so no export can
		// exist. Exported-symbol replacement happens in the post-boot second
		// pass below, via ReplaceE.)
		e.bindHostFn(name, e.guardHostFn(func(em *Emulator, b emu.Backend) {
			ret := hf(&Hook{em})
			_ = em.callABI.WriteResult(b, arch.CallResult{Value: ret})
		}))
	} // libc functions we implement in Go (need no libc init)
	// P2/P4b/P5a.5: the syscall transport ABI, dispatch table, guest struct
	// codecs and scheduler interception numbers are injected platform
	// personality, resolved by the platform package from the Target's machine
	// identity — the kernel and the emulator hold no syscall numbers and no
	// per-arch register knowledge. The binding is assembled by hand here at
	// the composition root; a platform.Factory.Bind taking only a minimal
	// BindContext (TargetInfo/Layout/Features) is the P5 wiring point
	// (DESIGN.md §4), deliberately not pre-built in P4.
	var (
		persTransport kernel.SyscallTransport
		persTable     *kernel.Table
		persCodecs    kernel.StructCodecs
	)
	switch tgt.Platform {
	case platform.Darwin:
		pers, perr := darwin.SyscallPersonalityFor(tgt.ID)
		if perr != nil {
			return nil, fmt.Errorf("platform personality: %w", perr)
		}
		persTransport, persTable, persCodecs = pers.Transport, pers.Table, pers.Codecs
		e.sysFutex, e.sysNanosleep, e.sysClockNanosleep = pers.Futex, pers.Nanosleep, pers.ClockNanosleep
	default: // platform.Android
		pers, perr := android.SyscallPersonalityFor(tgt.ID)
		if perr != nil {
			return nil, fmt.Errorf("platform personality: %w", perr)
		}
		persTransport, persTable, persCodecs = pers.Transport, pers.Table, pers.Codecs
		e.sysFutex, e.sysNanosleep, e.sysClockNanosleep = pers.Futex, pers.Nanosleep, pers.ClockNanosleep
	}
	e.kctx = &kernel.Context{
		B: be, Mem: e.mem, VFS: e.fs, Pid: pid, Verbose: cfg.Verbose, Epoch: cfg.Epoch,
		Transport: persTransport,
		Table:     persTable,
		Codecs:    persCodecs,
	}
	// A device profile anchors the monotonic clock at the persona's boot time
	// and serves live battery sysfs (Android persona only). Epoch keeps
	// winning (kernel.clock checks it first), so deterministic signing runs
	// are unaffected.
	if acfg != nil && acfg.Profile != nil {
		e.kctx.Clock = profileClock{prof: acfg.Profile}
		prof := acfg.Profile
		e.fs.MountBattery(func() (int, bool) { return prof.Battery(time.Now()) })
	}

	// §4 stage 9: materialize the layout — reserve fixed regions, then map
	// them. Every guest VA range is registered with the AddressSpace first
	// (P2.5c, invariant 12: the single VA allocation entry); the backend
	// MemMap calls below only back ranges the AddressSpace owns.
	l := e.layout
	if err := e.as.Reserve(emu.GuestAddr(l.StackBase), l.StackSize, memory.PurposeStack); err != nil {
		return nil, fmt.Errorf("reserve stack: %w", err)
	}
	if err := e.as.Reserve(emu.GuestAddr(l.TLSBase), l.TLSSize, memory.PurposeTLS); err != nil {
		return nil, fmt.Errorf("reserve tls: %w", err)
	}
	// The mmap arena (memory.Space) and the brk heap (kernel brk cursor) keep
	// their existing internal management this stage; only their region
	// OWNERSHIP moves into the AddressSpace, so the module bump allocator can
	// never drift into them. Both windows come from the Layout the platform's
	// LayoutPolicy planned (P4c) — no boundary arithmetic here.
	if err := e.as.Reserve(emu.GuestAddr(l.HeapRegion.Addr), l.HeapRegion.Size, memory.PurposeHeap); err != nil {
		return nil, fmt.Errorf("reserve heap: %w", err)
	}
	if err := e.as.Reserve(emu.GuestAddr(l.MmapRegion.Addr), l.MmapRegion.Size, memory.PurposeMmap); err != nil {
		return nil, fmt.Errorf("reserve mmap arena: %w", err)
	}
	if err := be.MemMap(emu.GuestAddr(l.StubBase), l.StubSize, emu.ProtAll); err != nil {
		return nil, fmt.Errorf("map stubs: %w", err)
	}
	if err := be.MemMap(emu.GuestAddr(l.StackBase), l.StackSize, emu.ProtRead|emu.ProtWrite); err != nil {
		return nil, fmt.Errorf("map stack: %w", err)
	}
	if err := be.MemMap(emu.GuestAddr(l.TLSBase), l.TLSSize, emu.ProtRead|emu.ProtWrite); err != nil {
		return nil, fmt.Errorf("map tls: %w", err)
	}
	// SP near top of stack (16-aligned); the headroom reserve is owned by the
	// platform's StartupABI (P4d, invariant 10): Android parks the auxv block
	// just below it, Darwin lays out the exec-style initial frame with argc
	// AT that SP. The constant travels with the platform.
	_ = be.RegWrite(e.spReg, l.StackBase+l.StackSize-stackTopReserve(tgt.Platform))

	// The thread-pointer register itself is platform-neutral: every 64-bit
	// guest expects TLSBase reachable through it.
	if err := tgt.Arch.SetTLSBase(be, emu.GuestAddr(l.TLSBase)); err != nil {
		return nil, fmt.Errorf("set TLS base: %w", err)
	}
	if tgt.Platform == platform.Android {
		// bionic TLS slot layout: TPIDR_EL0 -> slot array;
		// slot[TLS_SLOT_THREAD_ID] -> a mapped pthread_internal_t (zeroed).
		// Without this, libc reads a NULL thread ptr and faults writing
		// thread-local fields. The struct lives inside the TLS region so its
		// fields are always mapped. Darwin's TLS layout is dyld's business
		// and P5b models none of it.
		const (
			tlsSlotSelf     = 0 // __get_tls()[0] = tls base
			tlsSlotThreadID = 1 // -> pthread_internal_t*
		)
		pthreadStruct := l.TLSBase + 0x1000
		_ = putU64(be, l.TLSBase+tlsSlotSelf*8, l.TLSBase)
		_ = putU64(be, l.TLSBase+tlsSlotThreadID*8, pthreadStruct)
	}

	// §4 stage 10: install runtime hooks/traps. Two kind-annotated channels
	// through the backend's core InstallTrap (P5a.5 — the raw InterruptHooker
	// path is gone from the emulator):
	//
	//   - TrapHostCall → onStubTrap: host-call trampolines (svc stubs on
	//     ARM64, int3 stubs on AMD64), classified by trap-source ADDRESS via
	//     the StubManager — never by anything encoded in the stub bytes;
	//   - TrapSyscall → onSyscallTrap: real guest syscalls. On ARM64 both
	//     registrations share the engine's single interrupt hook (every svc
	//     fires every handler, so each handler first checks whether the trap
	//     source is a known stub and declines if so/not); on AMD64 the
	//     syscall instruction routes through a strictly separate engine
	//     channel (unicorn: UC_HOOK_INSN) that never carries stub traps.
	//
	// Every Go callback handed to the backend goes through the panic guard
	// (guard.go): a panic must never escape across the purego trampoline.
	// InvalidMemHooker stays a capability probe (P2.5a): an engine without it
	// fails New with ErrUnsupported, matching the old unconditional-method
	// error path.
	//
	// §4 lists hook installation after StartupABI; here it deliberately sits
	// BEFORE stage 11's load: golem's LoadLibrary couples loading with init
	// execution (RunInit runs guest code that can trap), so the trap path
	// must be live before the first image executes. The hooks are inert
	// until guest code runs, so the placement changes no behavior.
	if _, err := be.InstallTrap(emu.TrapHostCall, e.guardTrap(e.onStubTrap)); err != nil {
		return nil, fmt.Errorf("install host-call trap: %w (engine %q)", err, e.engine)
	}
	if _, err := be.InstallTrap(emu.TrapSyscall, e.guardTrap(e.onSyscallTrap)); err != nil {
		return nil, fmt.Errorf("install syscall trap: %w (engine %q)", err, e.engine)
	}
	// Diagnose unmapped/protected accesses during bring-up.
	inv, ok := be.(emu.InvalidMemHooker)
	if !ok {
		return nil, fmt.Errorf("hook mem-invalid: %w (engine %q)", emu.ErrUnsupported, e.engine)
	}
	if _, err := inv.HookMemInvalid(e.guardMemInvalid(func(b emu.Backend, typ int, addr uint64, size int, val int64) bool {
		pc, _ := b.RegRead(e.pcReg)
		if e.cfg.Verbose {
			fmt.Printf("[mem] INVALID access type=%d addr=0x%x size=%d value=0x%x pc=0x%x (%s)\n",
				typ, addr, size, uint64(val), pc, e.NearestSym(pc))
		}
		return false // do not auto-recover; surface the error
	})); err != nil {
		return nil, err
	}

	// §4 stage 11: load + link + finalize + startup + init (see boot,
	// LoadModule, LoadLibrary).
	if err := e.boot(); err != nil {
		return nil, err // cleanup via the deferred Close above
	}
	// §4 stage 12 — ReplaceFns second pass: exports of the freshly loaded
	// modules are only in the DynamicLinker's global scope now. Names bound
	// as import overrides during linking are not in the scope (they resolved
	// to stubs) and are naturally skipped; exported symbols get an
	// interposition entry hook (P2.5d).
	for name, hf := range replaceFns {
		if addr, ok := e.dl.LookupGlobal(name); ok {
			if err := e.interposeE(uint64(addr), hf); err != nil {
				return nil, fmt.Errorf("ReplaceFns %s: %w", name, err)
			}
		}
	}
	return e, nil
}

// cacheRoleRegs snapshots the Arch's role registers into plain fields at
// boot, so hot paths never walk the interface per call. Callers that build an
// Emulator literal directly (tests) must call this after setting arch.
func (e *Emulator) cacheRoleRegs() {
	e.pcReg = e.arch.PC()
	e.spReg = e.arch.SP()
}

// stackTopReserve is the platform StartupABI's SP-headroom constant (P4d,
// invariant 10): Android's auxv block sits below the reserve, Darwin's
// exec-style initial frame parks argc exactly at SP. The boot sets SP from
// this and the StartupABI builds against the same constant, so the two never
// drift.
func stackTopReserve(p platform.ID) uint64 {
	if p == platform.Darwin {
		return darwin.StackTopReserve
	}
	return android.StackTopReserve
}

// boot is §4 stage 11: map + link the platform runtime libraries (LoadModule:
// Load → Relocate/bind → FinalizeImage per image, no init run), then (if
// configured) load + initialize the main library (LoadLibrary adds
// StartupABI + init execution).
func (e *Emulator) boot() error {
	if e.target.Platform == platform.Android {
		// Android runtime libraries: bionic from the asset tree. Darwin has
		// NO runtime libraries in P5b — the asset tree ships no dyld/libSystem
		// and a Darwin guest links against nothing but its own image plus host
		// stubs (ReplaceFns / unresolved fallbacks).
		lib := e.cfg.AssetRoot + "/android/sdk23/lib64/"
		for _, l := range []string{"libc.so", "libm.so", "libdl.so"} {
			// P5a.5 transitional: the asset tree only ships AArch64 bionic
			// (sdk23/lib64), so on a non-ARM64 target these modules would fail
			// the LoadModule machine check. Pre-parse via CompileOnce (cached,
			// no double parse) and skip with a verbose note instead of erroring;
			// LoadModule keeps the hard check for every other caller.
			if img, err := loader.CompileOnce(lib + l); err == nil && img.Machine != e.target.ID {
				if e.cfg.Verbose {
					fmt.Printf("[boot] skip %s: machine %v != target %v (asset tree is AArch64-only)\n", l, img.Machine, e.target.ID)
				}
				continue
			}
			if _, err := e.LoadModule(lib+l, l); err != nil {
				return fmt.Errorf("load %s: %w", l, err)
			}
		}
	}
	if e.cfg.SOPath == "" {
		return nil // runtime libraries only; caller will LoadLibrary explicitly
	}
	m, err := e.LoadLibrary(e.cfg.SOPath)
	if err != nil {
		return err
	}
	e.main = m
	return nil
}

// LoadLibrary maps + links a shared object, runs its initializers (DT_INIT +
// init_array) and, if it exports JNI_OnLoad, calls that with the JavaVM.
// Analogous to unidbg's Emulator.loadLibrary. Returns the loaded Module.
func (e *Emulator) LoadLibrary(path string) (*Module, error) {
	m, err := e.LoadModule(path, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	// P4d/P4e (DESIGN.md §4, locked by boot_order_test.go): build the process
	// initial state — the auxv data block — once the first LoadLibrary'd
	// image's metadata is complete. Ordering: this runs AFTER the image's
	// FinalizeImage (inside LoadModule above) and BEFORE RunInit executes any
	// guest code, so bionic's getauxval callers see the real vector from the
	// first guest instruction. Built once per emulator; later libraries keep
	// the first-built vector.
	if err := e.ensureStartup(m.Img, m.Base); err != nil {
		return nil, fmt.Errorf("startup ABI: %w", err)
	}
	if err := e.RunInit(m); err != nil {
		return nil, err
	}
	if jni, ok := e.Sym("JNI_OnLoad"); ok {
		if _, err := e.CallFunc(jni, e.JavaVM(), 0); err != nil {
			return nil, fmt.Errorf("JNI_OnLoad: %w", err)
		}
		e.vm.EndCall() // seal locals boxed during boot (RegisterNatives etc.)
		if exited, code := e.GuestExited(); exited {
			return nil, fmt.Errorf("guest exit_group(%d) during JNI_OnLoad", code)
		}
	}
	return m, nil
}

// LoadModule maps + links a shared object and records its exports (no init run).
func (e *Emulator) LoadModule(path, name string) (*Module, error) {
	// CompileOnce: a pool of engines parses each .so exactly once, and the
	// Image's cached Plan carries the shared host buffers that make read-only
	// pages exist once in RAM across all engines.
	img, err := loader.CompileOnce(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	// P5a.5: refuse to map an image built for a different machine — running
	// foreign instructions would fault deep inside guest execution with no
	// diagnosable cause. (boot's bionic loop pre-filters via CompileOnce and
	// skips instead, because the asset tree is AArch64-only for now.)
	if e.target != nil && img.Machine != e.target.ID {
		return nil, fmt.Errorf("load %s: image machine %v does not match target %v", name, img.Machine, e.target.ID)
	}
	// Module bases bump upward through the AddressSpace, keeping the 1 MiB
	// inter-module gap of the pre-P2.5c module cursor.
	span := (img.LoadSpan + 0xfff) &^ 0xfff
	baseAddr, err := e.as.Alloc(memory.PurposeModule, span+0x100000)
	if err != nil {
		return nil, fmt.Errorf("alloc module %s: %w", name, err)
	}
	base := uint64(baseAddr)

	plan, err := img.Plan()
	if err != nil {
		return nil, fmt.Errorf("plan %s: %w", name, err)
	}
	if err := e.applyPlan(plan, base, e.resolver); err != nil {
		return nil, fmt.Errorf("link %s: %w", name, err)
	}
	// Record the module in the linker's module graph; its exports fold into
	// the global scope first-wins (the historical e.syms semantics).
	e.dl.AddModule(name, img, base)
	m := &Module{Name: name, Base: base, Img: img}
	e.modules = append(e.modules, m)
	if e.cfg.Verbose {
		fmt.Printf("[load] %-20s base=0x%x span=0x%x exports=%d\n", name, base, span, len(img.Exports))
	}
	return m, nil
}

// ensureStartup builds the process initial state — the auxv data block —
// through the platform's StartupABI exactly once per emulator (P4d, DESIGN.md
// §3.4 invariant 10). img/base carry the main image's startup metadata
// (PHDR/ENTRY); a nil img (bionic-only boot, first getauxval before any
// LoadLibrary) builds the vector without AT_PHDR/AT_PHNUM/AT_ENTRY, which
// then read as 0 — the pre-P4d default for unknown keys.
//
// Build-time ordering rule (P4e, pinned and locked by boot_order_test.go):
//   - WITH a main image: the build runs inside LoadLibrary, after the
//     image's FinalizeImage (LoadModule → plan.Apply) and BEFORE RunInit
//     executes any guest init code — the auxv is complete from the first
//     guest instruction.
//   - WITHOUT a main image (bionic-only boot): the build is deliberately
//     deferred to the first interposed getauxval (hostGetauxval). This is
//     the chosen semantics, not a gap: there is no main-image metadata to
//     consume yet, and bionic's pre-init getauxval callers must still get
//     answers. A later LoadLibrary does NOT rebuild (auxv is built once);
//     the main image's PHDR/ENTRY simply never enter the vector — the
//     historical bionic-only behavior.
func (e *Emulator) ensureStartup(img *loader.Image, base uint64) error {
	if e.startupBuilt {
		return nil
	}
	if e.startup == nil {
		// Lazy fallback for Emulators built by hand in tests (New always
		// instantiates per platform): the lazy path exists for bionic-only
		// boots whose first getauxval precedes any LoadLibrary, so Android is
		// the honest default here.
		e.startup = &android.StartupABI{}
	}
	if e.target == nil || e.target.Features == nil {
		return fmt.Errorf("startup ABI: the Target carries no CPUFeatures")
	}
	if e.be == nil {
		return fmt.Errorf("startup ABI: no backend to materialize the auxv block into")
	}
	if err := e.startup.BuildInitialState(&platform.StartupContext{
		Image:    img,
		Base:     emu.GuestAddr(base),
		AS:       e.as,
		Stack:    memory.Region{Addr: e.layout.StackBase, Size: e.layout.StackSize},
		Mem:      e.be,
		Features: e.target.Features,
	}); err != nil {
		return err
	}
	e.startupBuilt = true
	return nil
}

// bindHostFn binds a Go-implemented function (libc override or ReplaceFns
// import override) by symbol name in the InterposeTable (P3.5): the
// HostResolver materializes one guest stub per name at link time, and the
// trap path dispatches back here via the stub descriptor. The hostFn keeps
// its historical contract — it writes the result register itself; the
// HostFunc return value is ignored on the trap path.
func (e *Emulator) bindHostFn(name string, fn hostFn) {
	e.itab.BindSymbol(name, interpose.HostFunc(func(ctx interpose.CallContext) uint64 {
		fn(e, e.be)
		return 0
	}))
}

// makeStub emits a trampoline at a fresh stub address through the StubManager
// (P2.5d): the slot comes from the AddressSpace's stub region and the bytes
// from the architecture's StubEncoder (arm64: `svc #0 ; ret`, which traps to
// onStubTrap, which returns to the caller). Used for unresolved imports,
// host functions and JNI table slots. Trap identity is decided by ADDRESS
// (the StubManager's descriptor table), not by anything in the emitted bytes
// — see arch.StubEncoder.
func (e *Emulator) makeStub(name string, kind arch.StubKind) uint64 {
	// No error channel exists on the resolution path, so allocation/encoding
	// failures (e.g. stub-region exhaustion) panic, as before P2.5d.
	a, err := e.stubMgr.Allocate(kind, name)
	if err != nil {
		panic(fmt.Sprintf("makeStub %s: %v", name, err))
	}
	return uint64(a)
}

// SetupJNI builds a minimal JavaVM + JNIEnv in guest memory: both are pointers
// to function tables filled with svc stubs, so any vm->/env-> call traps to Go.
// GetEnv is special-cased to hand back the JNIEnv. Sets e.javaVM.
func (e *Emulator) SetupJNI() uint64 {
	ps := uint64(e.arch.PtrSize()) // function-table slot stride = guest pointer width
	const envSlots = 256           // > 232 JNINativeInterface entries
	envTable := e.MustAlloc(envSlots*8, emu.ProtRead|emu.ProtWrite)
	for i := 0; i < envSlots; i++ {
		stub := e.makeStub(fmt.Sprintf("JNIEnv[%d]", i), arch.StubHostCall)
		e.jniDispatch[stub] = i // dispatched in onStubTrap -> handleJNI
		_ = putU64(e.be, envTable+uint64(i)*ps, stub)
	}
	envPtr := e.MustAlloc(8, emu.ProtRead|emu.ProtWrite)
	_ = putU64(e.be, envPtr, envTable)
	e.jniEnv = envPtr

	const vmSlots = 16 // JNIInvokeInterface
	vmTable := e.MustAlloc(vmSlots*8, emu.ProtRead|emu.ProtWrite)
	for i := 0; i < vmSlots; i++ {
		_ = putU64(e.be, vmTable+uint64(i)*ps, e.makeStub(fmt.Sprintf("JavaVM[%d]", i), arch.StubHostCall))
	}
	e.getEnvStub = e.makeStub("JavaVM!GetEnv", arch.StubHostCall)
	_ = putU64(e.be, vmTable+6*ps, e.getEnvStub) // GetEnv
	_ = putU64(e.be, vmTable+4*ps, e.getEnvStub) // AttachCurrentThread (also yields env)
	vmPtr := e.MustAlloc(8, emu.ProtRead|emu.ProtWrite)
	_ = putU64(e.be, vmPtr, vmTable)
	e.javaVM = vmPtr
	return vmPtr
}

// JavaVM returns the guest JavaVM*, building the JNI tables on first use.
func (e *Emulator) JavaVM() uint64 {
	if e.javaVM == 0 {
		e.SetupJNI()
	}
	return e.javaVM
}

// JNIEnv returns the guest JNIEnv* (a pointer to the function table), building
// the JNI tables on first use. Pass it to native functions that take a JNIEnv*.
func (e *Emulator) JNIEnv() uint64 {
	if e.jniEnv == 0 {
		e.SetupJNI()
	}
	return e.jniEnv
}

// Sym returns a resolved global symbol address.
func (e *Emulator) Sym(name string) (uint64, bool) {
	a, ok := e.dl.LookupGlobal(name)
	return uint64(a), ok
}

// trapStubAddr maps the engine-reported trap PC back to the trapping
// instruction's address — for a stub trap, the stub's entry — through the
// Target's StubEncoder (P5a.5: the emulator holds no per-arch trap-offset
// constant like the old hardcoded pc-4).
func (e *Emulator) trapStubAddr(b emu.Backend) emu.GuestAddr {
	pc, _ := b.RegRead(e.pcReg)
	return e.target.Stubs.TrapStubAddr(emu.GuestAddr(pc))
}

// onStubTrap handles TrapHostCall: a guest→host trampoline trap — the JNI
// table slots, Go-implemented libc functions / ReplaceFns import overrides,
// or an unresolved-import placeholder. Classification is by trap-source
// ADDRESS (the StubManager's descriptor table), never by the trap bytes.
//
// A trap whose source is no known stub is NOT consumed here: on ARM64 the
// engine's single interrupt hook also delivers real guest syscalls to this
// handler — those fall through to onSyscallTrap (registered alongside).
func (e *Emulator) onStubTrap(b emu.Backend, _ emu.TrapKind) {
	stub := e.trapStubAddr(b)
	if stub == emu.GuestAddr(e.getEnvStub) { // JavaVM->GetEnv(vm, void** env, version)
		args, err := e.callABI.ReadArgs(b, 2)
		if err != nil {
			if e.cfg.Verbose {
				fmt.Printf("[GetEnv] ReadArgs: %v\n", err)
			}
			return
		}
		_ = putU64(b, args[1], e.jniEnv)
		_ = e.callABI.WriteResult(b, arch.CallResult{Value: 0}) // JNI_OK
		return
	}
	if idx, ok := e.jniDispatch[uint64(stub)]; ok { // JNIEnv->function(...)
		e.handleJNI(idx, b)
		return
	}
	// Go-implemented libc function / ReplaceFns import override (P3.5): the
	// stub was materialized by the HostResolver under the name
	// "host:<symbol>"; recover the bound HostFunc from the InterposeTable.
	// The hostFn contract is self-written result register, so the HostFunc's
	// return value is intentionally ignored here.
	if desc, ok := e.stubMgr.Lookup(stub); ok && desc.Kind == arch.StubHostCall {
		if name, cut := strings.CutPrefix(desc.Name, "host:"); cut {
			if hf, ok := e.itab.LookupSymbol(name); ok {
				hf(&Hook{e})
				return
			}
		}
	}
	// Unresolved-import placeholder / unbound trampoline: count the hit by
	// name (the pre-P2.5d stubHits semantics) and return an optimistic 0.
	if desc, ok := e.stubMgr.Hit(stub); ok {
		if e.cfg.Verbose {
			fmt.Printf("[stub] %s() -> 0\n", desc.Name)
		}
		_ = e.callABI.WriteResult(b, arch.CallResult{Value: 0}) // optimistic default
		return
	}
	// Not a stub: decline. On ARM64 this trap may be a real guest syscall
	// sharing the interrupt hook; onSyscallTrap services it.
}

// onSyscallTrap handles TrapSyscall: a real guest syscall. The frame is
// decoded ONCE via the injected platform transport (no register identities in
// the emulator), the scheduler intercepts futex/nanosleep to drive
// cooperative switching, and the kernel dispatcher services the rest.
//
// Stub-exclusion check: on ARM64 the interrupt hook delivers EVERY trap
// (stubs included) to every InstallTrap handler, so a stub trap arrives here
// too — anything the StubManager knows was already serviced by onStubTrap.
// The address arithmetic (TrapStubAddr) is stub-trap-shaped, but the check is
// a pure exclusion: a syscall instruction never executes from the stub
// region, so its neighborhood can never collide with a stub entry. On AMD64
// the syscall-instruction channel carries only real syscalls and the check
// never matches.
func (e *Emulator) onSyscallTrap(b emu.Backend, _ emu.TrapKind) {
	if _, ok := e.stubMgr.Lookup(e.trapStubAddr(b)); ok {
		return // a stub trap, already handled by onStubTrap
	}
	frame, err := e.kctx.Transport.Decode(b)
	if err != nil {
		if e.cfg.Verbose {
			fmt.Printf("[syscall] decode failed: %v\n", err)
		}
		return
	}
	// Scheduler hooks (futex / nanosleep) drive cooperative switching — futex
	// WAKE wakes parked fibers regardless of caller; WAIT/sleep yield a fiber.
	if e.handleSchedSyscall(b, &frame) {
		return
	}
	e.scCount++
	if e.scCount > 200000 {
		fmt.Println("[guard] runaway syscalls — stopping emulation")
		_ = b.Stop()
		return
	}
	e.kctx.DispatchFrame(&frame)
	// Preempt the running fiber after a serviced syscall (a clean instruction
	// boundary, so its full context snapshots correctly) when its slice is spent.
	if e.threadCap > 0 {
		e.threadOps++
		if e.threadOps > e.threadCap {
			e.yieldReason = yieldPreempt
			_ = b.Stop()
		}
	}
}

// CallFunc invokes guest code at addr with any number of integer args,
// returning the call's result. The CallABI establishes the frame
// (PrepareCall: register args + stack spill + return address) with the
// sentinel as the return address, so emulation stops when the callee returns.
func (e *Emulator) CallFunc(addr uint64, args ...uint64) (uint64, error) {
	if e.poisonErr != nil {
		return 0, fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	// Snapshot SP so the call frame PrepareCall built (spill slots on ARM64,
	// the pushed return address on AMD64) is unwound after the run — a
	// well-formed callee returns with SP intact per the ABI, so any residual
	// difference is our frame.
	origSP, err := e.be.RegRead(e.spReg)
	if err != nil {
		return 0, err
	}
	if err := e.callABI.PrepareCall(e.be, arch.CallRequest{
		Entry:  emu.GuestAddr(addr),
		Return: sentinel,
		Args:   args,
	}); err != nil {
		return 0, fmt.Errorf("CallFunc: %w", err)
	}
	e.scCount = 0
	runErr := e.be.Start(emu.GuestAddr(addr), emu.GuestAddr(sentinel))
	_ = e.be.RegWrite(e.spReg, origSP) // unwind the call frame
	if runErr != nil {
		return 0, fmt.Errorf("emu_start @0x%x: %w", addr, runErr)
	}
	// A panic inside a guest up-call was recovered at the trampoline boundary
	// (guard.go); surface it here — the run's caller — instead of across C.
	if err := e.checkGuestPanic(); err != nil {
		return 0, err
	}
	res, err := e.callABI.ReadResult(e.be)
	if err != nil {
		return 0, fmt.Errorf("CallFunc: read result: %w", err)
	}
	return res.Value, nil
}

// CallSymbol calls an exported function by name with integer args.
func (e *Emulator) CallSymbol(name string, args ...uint64) (uint64, error) {
	addr, ok := e.Sym(name)
	if !ok {
		return 0, fmt.Errorf("symbol %q not found", name)
	}
	return e.CallFunc(addr, args...)
}

// CallOffset calls a function at module base + offset — for non-exported entry
// points located by reverse engineering (unidbg's module.callFunction(offset)).
// A nil module means the main module (Config.SOPath).
func (e *Emulator) CallOffset(m *Module, offset uint64, args ...uint64) (uint64, error) {
	if m == nil {
		m = e.main
	}
	if m == nil {
		return 0, fmt.Errorf("CallOffset: no module (set Config.SOPath or pass a module)")
	}
	return e.CallFunc(m.Base+offset, args...)
}

// RunThreads (the cooperative scheduler) and PendingThreads live in scheduler.go.

// NearestSym maps a guest address to "module!symbol+0xNN" for diagnostics.
func (e *Emulator) NearestSym(addr uint64) string {
	for _, m := range e.modules {
		if addr < m.Base || addr >= m.Base+m.Img.LoadSpan {
			continue
		}
		rel := addr - m.Base
		bestName, bestOff := "", uint64(0)
		for n, off := range m.Img.Exports {
			if off <= rel && off >= bestOff {
				bestName, bestOff = n, off
			}
		}
		if bestName == "" {
			return fmt.Sprintf("%s+0x%x", m.Name, rel)
		}
		return fmt.Sprintf("%s!%s+0x%x", m.Name, bestName, rel-bestOff)
	}
	return fmt.Sprintf("0x%x", addr)
}

// RunInit runs a module's DT_INIT then its init_array (in order), like the
// dynamic linker. Stops at the first failure.
func (e *Emulator) RunInit(m *Module) error {
	if m.Img.Init != 0 {
		if _, err := e.CallFunc(m.Base + m.Img.Init); err != nil {
			return fmt.Errorf("%s DT_INIT: %w", m.Name, err)
		}
	}
	ptrs, err := e.InitArrayPtrs(m)
	if err != nil {
		return err
	}
	for i, addr := range ptrs {
		if _, err := e.CallFunc(addr); err != nil {
			return fmt.Errorf("%s init_array[%d] @0x%x: %w", m.Name, i, addr, err)
		}
	}
	return nil
}

func putU64(be emu.Backend, addr, val uint64) error {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], val)
	return be.MemWrite(emu.GuestAddr(addr), b[:])
}

// InitArrayPtrs reads the module's init_array function pointers from guest
// memory AFTER relocation (on AArch64 the file section is zeros; RELATIVE
// addends written by the linker hold the real, base-relative pointers).
func (e *Emulator) InitArrayPtrs(m *Module) ([]uint64, error) {
	var ptrs []uint64
	for i := 0; i < m.Img.InitArrayLen; i++ {
		b, err := e.be.MemRead(emu.GuestAddr(m.Base+m.Img.InitArrayAddr+uint64(i)*8), 8)
		if err != nil {
			return nil, err
		}
		v := binary.LittleEndian.Uint64(b)
		if v == 0 {
			continue // lld 对齐填充槽（无重定位覆盖，文件值为 0）：真机 bionic 同样跳过
		}
		ptrs = append(ptrs, v)
	}
	return ptrs, nil
}

// poison records that a failed internal transition left the emulator in an
// unusable state. The FIRST poison wins; every subsequent public entry point
// returns it instead of operating on inconsistent state. Use for failures
// whose rollback cannot be verified (e.g. an address-space remap that failed
// mid-way), never for ordinary errors a caller can handle.
func (e *Emulator) poison(what string, err error) error {
	pErr := fmt.Errorf("emulator poisoned (%s): %w", what, err)
	if e.poisonErr == nil {
		e.poisonErr = pErr
	}
	return e.poisonErr
}

// Close releases the backend.
func (e *Emulator) Close() error {
	if e.be != nil {
		return e.be.Close()
	}
	return nil
}
