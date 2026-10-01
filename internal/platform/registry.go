package platform

import (
	"fmt"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/profile"
)

// Factory builds one platform's complete Runtime from a minimal BindContext
// (DESIGN.md §3.4/§4). The composition root (emulator.New) resolves
// the factory registered under the probed Target.Platform and binds it; the
// emulator itself holds NO per-platform selection logic (no switch on
// platform.ID), so a new platform personality is added by registering a new
// factory here — without touching the emulator.
//
// Per-architecture knowledge stays INSIDE the factory: a factory may switch
// on BindContext.ArchID to pick its per-arch implementations (syscall
// transport/table/codecs), exactly as SyscallPersonalityFor always has. The
// arch-keyed selection is platform business; the platform-keyed selection is
// the registry's.
type Factory interface {
	Bind(ctx BindContext) (*Runtime, error)
}

// BindContext is everything a Factory needs to produce its Runtime — and
// nothing more (DESIGN.md invariant 2 style: no component ever receives a
// half-built Emulator). It deliberately carries the arch.ID, not the
// target.Target: target aggregates platform (Target.Platform), so platform
// importing target back would close a dependency cycle.
//
// Config is the platform.Config the composition root normalized against the
// probed platform (nil = platform defaults). The factory asserts its own
// concrete config type; a mismatch is a configuration error, surfaced from
// Bind — the composition root routes configs by PlatformID(), never by
// type-switch.
type BindContext struct {
	ArchID arch.ID
	Config Config
}

// Runtime is the composition product of a platform Factory the
// complete platform personality, produced ONCE at boot and consumed as pure
// data by the emulator. It is deliberately a struct of data, not a fat
// interface and not three separate registries: every field is either a value
// the emulator injects into the kernel/scheduler/linker machinery or a
// presence flag it feature-tests (nil Interop = no Java runtime, nil
// AuxvLookup = no auxv, nil InitGuest = no platform TLS layout) — never a
// platform identity the emulator dispatches on.
type Runtime struct {
	// Startup builds the guest process initial state once per emulator
	// (invariant 10): the auxv data block on Linux-flavoured
	// platforms, an exec-style initial stack frame on Darwin.
	Startup StartupABI
	// AuxvLookup serves getauxval(type) from Startup's built vector —
	// typically Startup's own Lookup method bound at Bind time, so the
	// interposed getauxval and the data block can never drift apart (the
	// single-source invariant, without the emulator type-asserting the
	// StartupABI). nil = the platform has no auxv; the emulator then binds
	// no getauxval host function at all.
	AuxvLookup func(typ uint64) uint64
	// StackTopReserve is the SP-headroom constant the boot sets the initial
	// SP from and Startup builds against it travels with the
	// platform so the two never drift.
	StackTopReserve uint64

	// Layout plans the initial guest address space from arch capabilities
	// plus user overrides — pure data, no Map/Alloc/Reserve.
	Layout LayoutPolicy

	// Syscall personality (shape): the register transport, the
	// number→handler dispatch table and the guest struct codecs the
	// emulator injects into kernel.Context, plus the syscall numbers the
	// cooperative scheduler intercepts before the kernel table sees them.
	Transport      kernel.SyscallTransport
	Table          *kernel.Table
	Codecs         kernel.StructCodecs
	Futex          uint64
	Nanosleep      uint64
	ClockNanosleep uint64

	// RuntimeLibs are the platform runtime libraries the boot loads, as
	// AssetRoot-relative paths in load order (e.g. bionic's
	// "android/sdk23/lib64/libc.so"). nil = the platform ships no runtime
	// libraries; the guest then links against its own image plus host
	// stubs only.
	RuntimeLibs []string
	// Uname is the guest-visible utsname identity, per-arch data
	// selected at Bind time (Android: aarch64 / armv7l / x86_64). The
	// kernel's uname handler encodes exactly this — the identity is
	// platform business, never a kernel-side constant. nil = the platform
	// binds no uname number into its table (e.g. Darwin); a table that
	// binds uname without an identity makes the handler fail loudly.
	Uname *kernel.UnameInfo
	// InitGuest materializes platform-specific initial address-space state
	// after the layout is mapped (e.g. bionic's TLS slot array: slot[0] =
	// TLS base, slot[1] = a pthread_internal_t inside the TLS region).
	// nil = no platform-specific initial state.
	InitGuest func(mem MemWriter, l memory.Layout) error

	// ReplaceFns installs Go implementations by symbol name (both binding
	// paths terminate in interpose.InterposeTable): unresolved imports bind
	// to host stubs at link time, exports get an interposition entry hook
	// after boot. Sourced from the platform config at Bind time.
	ReplaceFns map[string]interpose.HostFunc
	// PthreadStubs asks the emulator to bind pthread_create/pthread_join/
	// pthread_detach host functions that model guest threads as cooperative
	// scheduler fibers (the guest's real pthread implementation would need
	// a fully bootstrapped libc). false = leave pthread symbols alone.
	PthreadStubs bool

	// Interop is the Java/device interop surface; nil = the platform has
	// none (no JNI dispatch, no dex metadata, no system properties, no
	// device profile — e.g. a Darwin guest).
	Interop *Interop
}

// Interop is the optional Java-runtime and device-personality surface of a
// platform Runtime (Android today). The emulator consumes it as feature
// tests: a non-nil Interop wires the JNI handler and dex metadata; a non-nil
// PropertyProvider binds __system_property_get; a non-nil Profile anchors
// the kernel clock at the persona's boot time and serves live battery sysfs.
type Interop struct {
	// Jni is the Java callback handler the guest's JNIEnv calls dispatch
	// to. nil = the emulator's default everything-answers-null handler.
	Jni dvm.Jni
	// DexPath optionally loads a classes.dex at boot so FindClass/
	// GetMethodID/GetFieldID resolve against real metadata. Empty = none.
	DexPath string
	// PropertyProvider answers the guest's __system_property_get(key):
	// (value, true) to supply a value, ("", false) for "unset". nil = the
	// emulator binds no property host function.
	PropertyProvider func(key string) (string, bool)
	// Profile, if non-nil, installs the deterministic device-liveness model
	// (persona boot-time clock anchor + battery sysfs).
	Profile *profile.Profile
}

// Registry is one factory table. The package-level default registry backs
// Register/Resolve — the init()-time registration path and the composition
// root; tests that exercise registration semantics build their own instance
// (NewRegistry) so they stay hermetic regardless of test order or -count
// runs, instead of trying to un-register global state.
type Registry struct {
	factories map[ID]Factory
}

// NewRegistry returns an empty, isolated factory table.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[ID]Factory)}
}

// Register makes a Factory available under id. As in loader.RegisterParser, a
// duplicate key overwrites — registration happens at init time, so the last
// linked implementation wins — and a nil factory is ignored (it does NOT
// remove an existing registration).
func (r *Registry) Register(id ID, f Factory) {
	if f == nil {
		return
	}
	r.factories[id] = f
}

// Resolve returns the Factory registered under id, or an error naming the
// missing registration (with the standard "import the subpackage" hint, the
// same shape as the loader's parser dispatch). The registry consumes the
// probed Target.Platform as-is; Probe→Target resolution stays upstream and
// is never re-decided here.
func (r *Registry) Resolve(id ID) (Factory, error) {
	f, ok := r.factories[id]
	if !ok {
		return nil, fmt.Errorf("platform: no factory registered for platform %s (import the platform/%s package for its init())", id, id)
	}
	return f, nil
}

// defaultRegistry is the process-wide table the platform subpackages'
// init() functions register into and the composition root resolves from.
var defaultRegistry = NewRegistry()

// Register makes a Factory available under id on the default registry;
// called from a platform subpackage's init().
func Register(id ID, f Factory) { defaultRegistry.Register(id, f) }

// Resolve returns the Factory registered under id on the default registry.
func Resolve(id ID) (Factory, error) { return defaultRegistry.Resolve(id) }
