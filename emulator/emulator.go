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
	"time"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/profile"
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
	// read-only pages into physical RAM exactly once. Writes that would touch
	// a shared range (Replace/HookAddr patching) transparently privatize the
	// module's pages in that engine first. Set true to disable (fresh
	// anonymous memory per engine, pre-Phase-B behavior).
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
	// handler, dex metadata, symbol replacements, system properties). A
	// future iOS personality would be a sibling of this field and mutually
	// exclusive with it.
	Android AndroidConfig
}

// AndroidConfig is the Android personality of an emulated process: the pieces
// that only make sense for an Android-flavoured guest, grouped so that a
// future iOS personality can sit next to them without polluting the
// platform-agnostic top-level Config.
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
	// modules EXPORT are entry-patched (Replace) after boot completes. Model
	// NDK/libc functions the guest calls here (e.g. the AAssetManager family).
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

// legacyARM64Layout is the guest memory layout, made explicit as data in P1
// (memory.Layout). The numbers are exactly the pre-P1 package constants, kept
// clear of each other and of the mmap arena. Layout POLICY (who picks these
// numbers — platform.LayoutPolicy over arch caps + user overrides) arrives in
// P4/P5; this is the Android/ARM64 legacy default until then.
var legacyARM64Layout = memory.Layout{
	ModuleBase: 0x12000000, // modules loaded from here, upward
	ModuleSize: 0x4E000000, // arena up to the stub region
	StubBase:   0x60000000, // svc trampolines for unresolved imports
	StubSize:   0x00100000,
	StackBase:  0xC0000000, // 8 MiB stack
	StackSize:  0x00800000,
	TLSBase:    0xD0000000, // thread-local storage block
	TLSSize:    0x00010000,
}

const sentinel = 0xFFFFFF00 // LR for top-level calls; emu stops when PC hits it

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

	arch    arch.Arch            // CPU properties, resolved once in New (P2.5b; always ARM64 until P4)
	callABI arch.CallABI         // function calling convention (AAPCS64) — args/results/return flow
	stubEnc arch.StubEncoder     // trampoline encoder; an independent capability, not part of Arch/CallABI
	layout  memory.Layout        // guest address-space layout in use
	as      *memory.AddressSpace // single guest VA allocation entry (P2.5c, invariant 12)

	// Boot-cached role registers (P1, DESIGN.md §8: no interface walks on hot
	// paths). Ownership after the P2.5b split (invariant 13): argRegs/retReg/
	// lrReg are the CallABI's role registers; pcReg/spReg are the Arch's.
	// Callers that build an Emulator literal directly (tests) must call
	// cacheRoleRegs after setting arch/callABI.
	argRegs [8]emu.Reg // callABI.Arg(0..7)
	retReg  emu.Reg    // callABI.Ret()
	lrReg   emu.Reg    // callABI.LR()
	pcReg   emu.Reg    // arch.PC()
	spReg   emu.Reg    // arch.SP()

	modules  []*Module
	main     *Module           // the Config.SOPath module, if any
	syms     map[string]uint64 // global export table
	stubs    map[uint64]string
	aForm    bool // 当前 JNI 调用为 Call*MethodA（jvalue 数组）形式 // svc addr -> import/JNI name
	stubHits map[string]int
	scCount  int // syscalls in current CallFunc (runaway guard)

	jniEnv       uint64         // guest JNIEnv* (points to a stub function table)
	javaVM       uint64         // guest JavaVM*
	getEnvStub   uint64         // JavaVM->GetEnv svc stub (special-cased)
	jniDispatch  map[uint64]int // JNIEnv stub addr -> JNINativeInterface index
	classRefs    map[string]dvm.Ref
	shared       []sharedRange          // guest ranges mapped via MemMapPtr (privatize-on-write)
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

	hostByName map[string]hostFn // libc funcs we implement in Go (override bionic)
	hostImpl   map[uint64]hostFn // svc addr -> host impl
	replaced   map[uint64]hostFn // user Replace()d functions (svc addr -> Go impl)
	atRandom   uint64            // guest ptr to 16 "random" bytes (AT_RANDOM)

	// cooperative scheduler state (see scheduler.go)
	fibers      []*fiber // pthread_create'd threads
	curFiber    *fiber   // fiber currently in a slice (nil = main thread)
	nextFiberID int
	threadCap   int    // per-slice syscall budget for the running fiber (0 = main)
	threadOps   int    // syscalls serviced in the current slice
	yieldReason int    // why the current slice stopped (yield*)
	yieldAddr   uint64 // futex uaddr the fiber parked on
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
func New(cfg Config) (e *Emulator, err error) {
	engine, err := emu.Resolve(cfg.Engine)
	if err != nil {
		return nil, fmt.Errorf("backend: %w", err)
	}
	// TODO(P4): 由 Config.Arch/Sniff 决定 — until then everything is ARM64.
	cpuArch, callABI, stubEnc, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		return nil, err
	}
	be, err := emu.NewNamed(engine, cpuArch.EngineArch())
	if err != nil {
		return nil, fmt.Errorf("backend(%s): %w", engine, err)
	}
	// TCG buffer sizing must land before the first uc_emu_start (boot runs
	// guest code), and this point precedes the half-booted cleanup defer below
	// (it only fires once e is assigned) — so failures here close the fresh
	// backend by hand. A non-unicorn engine reports the setting as an error
	// via SetTCGBufferSize rather than silently ignoring it.
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
	e = &Emulator{
		cfg:         cfg,
		engine:      engine,
		be:          be,
		arch:        cpuArch,
		callABI:     callABI,
		stubEnc:     stubEnc,
		layout:      legacyARM64Layout,
		as:          memory.NewAddressSpace(legacyARM64Layout),
		mem:         memory.NewSpace(),
		vm:          dvm.NewVM(),
		fs:          vfs.New(cfg.AssetRoot, pid, cfg.ProcessName),
		syms:        map[string]uint64{},
		stubs:       map[uint64]string{},
		stubHits:    map[string]int{},
		hostByName:  map[string]hostFn{},
		hostImpl:    map[uint64]hostFn{},
		replaced:    map[uint64]hostFn{},
		jniDispatch: map[uint64]int{},
		classRefs:   map[string]dvm.Ref{},
		shared:      []sharedRange{},
		natives:     map[string]uint64{},
		methods:     map[dvm.Ref]*methodRef{},
		fields:      map[dvm.Ref]*fieldRef{},
		arrayPins:   map[uint64]pinEntry{},
	}
	e.cacheRoleRegs()
	// On any construction failure the half-booted engine must be torn down:
	// it already holds unicorn mappings, and repeated failed New calls would
	// otherwise leak engines. The post-boot ReplaceFns pass may PANIC (a
	// Replace that cannot patch is fatal), so the cleanup must catch panics
	// too — close the backend, then re-panic to preserve the original signal.
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
	if cfg.FileResolver != nil {
		e.fs.SetFallback(cfg.FileResolver)
	}
	e.classMeta = e.vm.ResolveClass("java/lang/Class")
	jni := cfg.Android.JNI
	if jni == nil {
		jni = dvm.AbstractJni{}
	}
	// The four JNI time getters are always modeled from the kernel clock (see
	// clockJni) — returning 0 for currentTimeMillis is a louder emulator tell
	// than answering them, and Epoch mode keeps them deterministic.
	e.vm.SetJni(&clockJni{Jni: jni, e: e, prof: cfg.Android.Profile})
	if cfg.Android.DexPath != "" {
		nc, derr := e.vm.LoadDexFile(cfg.Android.DexPath)
		if derr != nil {
			return nil, fmt.Errorf("load dex: %w", derr)
		}
		if cfg.Verbose {
			fmt.Printf("[dex] %s -> %d classes\n", cfg.Android.DexPath, nc)
		}
	}
	registerHostFns(e)
	for name, fn := range cfg.Android.ReplaceFns {
		f := fn
		if addr, ok := e.syms[name]; ok {
			e.Replace(addr, f)
		} else {
			e.hostByName[name] = e.guardHostFn(func(em *Emulator, b emu.Backend) {
				ret := f(&Hook{em})
				_ = b.RegWrite(em.retReg, ret)
			})
		}
	} // libc functions we implement in Go (need no libc init)
	e.kctx = &kernel.Context{
		B: be, Mem: e.mem, VFS: e.fs, Pid: pid, Verbose: cfg.Verbose, Epoch: cfg.Epoch,
		// P2: the syscall transport ABI, dispatch table and guest struct
		// codecs are injected platform personality (Android / AArch64 Linux
		// today), not hardcoded in the kernel. TODO(P4): resolve from
		// Config.Platform once functional options land.
		Transport: android.LinuxARM64Transport{},
		Table:     android.NewSyscallTable(),
		Codecs:    android.AsmGenericLP64Codecs{},
	}
	// A device profile anchors the monotonic clock at the persona's boot time
	// and serves live battery sysfs. Epoch keeps winning (kernel.clock checks
	// it first), so deterministic signing runs are unaffected.
	if cfg.Android.Profile != nil {
		e.kctx.Clock = profileClock{prof: cfg.Android.Profile}
		prof := cfg.Android.Profile
		e.fs.MountBattery(func() (int, bool) { return prof.Battery(time.Now()) })
	}

	// Reserve fixed regions. Every guest VA range is registered with the
	// AddressSpace first (P2.5c, invariant 12: the single VA allocation entry);
	// the backend MemMap calls below only back ranges the AddressSpace owns.
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
	// never drift into them. Both live inside the Layout's module arena:
	// heap = [BrkBase, MmapBase), mmap = [MmapBase, module arena top).
	if err := e.as.Reserve(emu.GuestAddr(kernel.BrkBase), memory.MmapBase-kernel.BrkBase, memory.PurposeHeap); err != nil {
		return nil, fmt.Errorf("reserve heap: %w", err)
	}
	if err := e.as.Reserve(emu.GuestAddr(memory.MmapBase), l.ModuleBase+l.ModuleSize-memory.MmapBase, memory.PurposeMmap); err != nil {
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
	// SP near top of stack (16-aligned).
	_ = be.RegWrite(e.spReg, l.StackBase+l.StackSize-0x200)

	// bionic TLS: TPIDR_EL0 -> slot array; slot[TLS_SLOT_THREAD_ID] -> a mapped
	// pthread_internal_t (zeroed). Without this, libc reads a NULL thread ptr
	// and faults writing thread-local fields. The struct lives inside the TLS
	// region so its fields are always mapped.
	const (
		tlsSlotSelf     = 0 // __get_tls()[0] = tls base
		tlsSlotThreadID = 1 // -> pthread_internal_t*
	)
	pthreadStruct := l.TLSBase + 0x1000
	if err := cpuArch.SetTLSBase(be, emu.GuestAddr(l.TLSBase)); err != nil {
		return nil, fmt.Errorf("set TLS base: %w", err)
	}
	_ = putU64(be, l.TLSBase+tlsSlotSelf*8, l.TLSBase)
	_ = putU64(be, l.TLSBase+tlsSlotThreadID*8, pthreadStruct)

	// Route SVC: distinguish import-stub calls (by PC) from real syscalls.
	// Every Go callback handed to the backend goes through the panic guard
	// (guard.go): a panic must never escape across the purego trampoline.
	// InterruptHooker/InvalidMemHooker are capability probes (P2.5a): an
	// engine without them fails New with ErrUnsupported, matching the old
	// unconditional-method error path.
	intr, ok := be.(emu.InterruptHooker)
	if !ok {
		return nil, fmt.Errorf("hook interrupt: %w (engine %q)", emu.ErrUnsupported, e.engine)
	}
	if _, err := intr.HookInterrupt(e.guardInterrupt(e.onInterrupt)); err != nil {
		return nil, err
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

	if err := e.boot(); err != nil {
		return nil, err // cleanup via the deferred Close above
	}
	// ReplaceFns second pass: exports of the freshly loaded modules are only
	// in e.syms now. Names bound as import overrides during linking are not
	// in e.syms (they resolved to stubs) and are naturally skipped; exported
	// symbols get their entry patched.
	for name, fn := range cfg.Android.ReplaceFns {
		if addr, ok := e.syms[name]; ok {
			if err := e.ReplaceE(addr, fn); err != nil {
				return nil, fmt.Errorf("ReplaceFns %s: %w", name, err)
			}
		}
	}
	return e, nil
}

// cacheRoleRegs snapshots the Arch's and CallABI's role registers into plain
// fields/slices at boot, so hot paths never walk the interface per call.
// Callers that build an Emulator literal directly (tests) must call this
// after setting arch/callABI.
func (e *Emulator) cacheRoleRegs() {
	for i := range e.argRegs {
		e.argRegs[i] = e.callABI.Arg(i)
	}
	e.retReg = e.callABI.Ret()
	e.lrReg = e.callABI.LR()
	e.pcReg = e.arch.PC()
	e.spReg = e.arch.SP()
}

// boot maps bionic, then (if configured) loads + initializes the main library.
func (e *Emulator) boot() error {
	lib := e.cfg.AssetRoot + "/android/sdk23/lib64/"
	for _, l := range []string{"libc.so", "libm.so", "libdl.so"} {
		if _, err := e.LoadModule(lib+l, l); err != nil {
			return fmt.Errorf("load %s: %w", l, err)
		}
	}
	if e.cfg.SOPath == "" {
		return nil // bionic only; caller will LoadLibrary explicitly
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
	if err := e.applyPlan(plan, base, e.resolveSymbol); err != nil {
		return nil, fmt.Errorf("link %s: %w", name, err)
	}
	for n, off := range img.Exports {
		if _, exists := e.syms[n]; !exists {
			e.syms[n] = base + off
		}
	}
	m := &Module{Name: name, Base: base, Img: img}
	e.modules = append(e.modules, m)
	if e.cfg.Verbose {
		fmt.Printf("[load] %-20s base=0x%x span=0x%x exports=%d\n", name, base, span, len(img.Exports))
	}
	return m, nil
}

// resolveSymbol satisfies loader.Resolver: global export, else a svc stub.
func (e *Emulator) resolveSymbol(name string) (uint64, bool) {
	if fn, ok := e.hostByName[name]; ok { // Go override for libc funcs needing init
		a := e.makeStub("host:"+name, arch.StubHostCall)
		e.hostImpl[a] = fn
		return a, true
	}
	if a, ok := e.syms[name]; ok {
		return a, true
	}
	return e.makeStub(name, arch.StubUnresolved), true
}

// makeStub emits a trampoline at a fresh stub address via the architecture's
// StubEncoder (arm64: `svc #0 ; ret`, which traps to onInterrupt, which
// returns to the caller). Used for unresolved imports, host functions and JNI
// table slots. Trap identity is decided by ADDRESS (the stubs map below), not
// by anything in the emitted bytes — see arch.StubEncoder.
func (e *Emulator) makeStub(name string, kind arch.StubKind) uint64 {
	// Stub slots come from the AddressSpace's stub region (8 bytes each, the
	// pre-P2.5c stub-cursor stride). No error channel exists on the resolution
	// path, so region exhaustion panics like an encoder failure below.
	a64, err := e.as.Alloc(memory.PurposeStub, 8)
	if err != nil {
		panic(fmt.Sprintf("makeStub %s: %v", name, err))
	}
	a := uint64(a64)
	code, err := e.stubEnc.EmitStub(kind)
	if err != nil {
		panic(fmt.Sprintf("makeStub %s: %v", name, err))
	}
	_ = e.be.MemWrite(emu.GuestAddr(a), code)
	e.stubs[a] = name
	return a
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
		e.jniDispatch[stub] = i // dispatched in onInterrupt -> handleJNI
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
func (e *Emulator) Sym(name string) (uint64, bool) { a, ok := e.syms[name]; return a, ok }

// onInterrupt handles SVC: a stub call (unresolved import) or a real syscall.
func (e *Emulator) onInterrupt(b emu.Backend, intno uint32) {
	pc, _ := b.RegRead(e.pcReg)
	svc := pc - 4            // unicorn advances PC past the svc
	if svc == e.getEnvStub { // JavaVM->GetEnv(vm, void** env, version)
		envpp, _ := b.RegRead(e.argRegs[1])
		_ = putU64(b, envpp, e.jniEnv)
		_ = b.RegWrite(e.retReg, 0) // JNI_OK
		return
	}
	if fn, ok := e.replaced[svc]; ok { // user Replace()d function
		fn(e, b)
		return
	}
	if idx, ok := e.jniDispatch[svc]; ok { // JNIEnv->function(...)
		e.handleJNI(idx, b)
		return
	}
	if fn, ok := e.hostImpl[svc]; ok { // Go-implemented libc function
		fn(e, b)
		return
	}
	if name, ok := e.stubs[svc]; ok {
		e.stubHits[name]++
		if e.cfg.Verbose {
			fmt.Printf("[stub] %s() -> 0\n", name)
		}
		_ = b.RegWrite(e.retReg, 0) // optimistic default
		return
	}
	// Real guest syscall: decode the frame ONCE via the injected platform
	// transport (no register identities in the emulator), let the scheduler
	// intercept futex/nanosleep to drive cooperative switching, then hand the
	// frame to the kernel dispatcher.
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

// CallFunc invokes guest code at addr with up to 8 integer args (arg
// registers 0..7 per the CallABI), returning the return register. LR is
// set to a sentinel so emulation stops on return.
func (e *Emulator) CallFunc(addr uint64, args ...uint64) (uint64, error) {
	if e.poisonErr != nil {
		return 0, fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	regs := e.argRegs[:] // boot-cached callABI.Arg(0..7)
	if len(args) > len(regs) {
		return 0, fmt.Errorf("CallFunc: >8 args not supported")
	}
	for i, a := range args {
		if err := e.be.RegWrite(regs[i], a); err != nil {
			return 0, err
		}
	}
	if err := e.be.RegWrite(e.lrReg, sentinel); err != nil {
		return 0, err
	}
	e.scCount = 0
	if err := e.be.Start(emu.GuestAddr(addr), emu.GuestAddr(sentinel)); err != nil {
		return 0, fmt.Errorf("emu_start @0x%x: %w", addr, err)
	}
	// A panic inside a guest up-call was recovered at the trampoline boundary
	// (guard.go); surface it here — the run's caller — instead of across C.
	if err := e.checkGuestPanic(); err != nil {
		return 0, err
	}
	return e.be.RegRead(e.retReg)
}

// CallSymbol calls an exported function by name with up to 8 integer args.
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
