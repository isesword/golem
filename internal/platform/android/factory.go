package android

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// The Android personality registers its factory at link time the
// composition root resolves platform.Android -> this factory and binds the
// complete Runtime below. emulator holds no Android-specific selection
// logic beyond this registration.
func init() { platform.Register(platform.Android, factory{}) }

// factory assembles the Android Runtime from a BindContext. The per-arch
// selection (syscall transport/table/codecs, scheduler interception
// numbers) lives HERE — it has always been platform business
// (SyscallPersonalityFor); the platform-keyed selection is the registry's.
type factory struct{}

func (factory) Bind(ctx platform.BindContext) (*platform.Runtime, error) {
	// nil Config = platform defaults; a non-nil Config must be this
	// platform's own concrete type — anything else is a configuration
	// error, not a silent re-interpretation.
	cfg := NewConfig()
	if ctx.Config != nil {
		c, ok := ctx.Config.(*Config)
		if !ok {
			return nil, fmt.Errorf("android: platform config is %T (platform %s), want *android.Config", ctx.Config, ctx.Config.PlatformID())
		}
		cfg = c
	}
	pers, err := SyscallPersonalityFor(ctx.ArchID)
	if err != nil {
		return nil, err
	}
	// Startup and AuxvLookup are bound to the SAME StartupABI instance, so
	// the interposed getauxval serves exactly the vector BuildInitialState
	// materialized — the single-source invariant, with no emulator-side
	// type assertion. The pointer WIDTH of the auxv wire format is
	// arch-dependent ARM32 gets the 8-byte-pair Elf32_auxv_t builder.
	var startup platform.StartupABI
	var auxvLookup func(typ uint64) uint64
	switch ctx.ArchID {
	case arch.IDARM:
		s := &StartupABI32{}
		startup, auxvLookup = s, s.Lookup
	default:
		s := &StartupABI{}
		startup, auxvLookup = s, s.Lookup
	}
	// Bionic runtime libraries and the TLS slot init are arch-keyed. The
	// asset tree ships BOTH widths: AArch64 under lib64/, ARM32 (real
	// API-23 armeabi-v7a bionic) under lib/. On ARM64 the lib64 set loads
	// for real; on any other target the boot's machine-mismatch skip (the
	// .5 convention) drops whatever does not match — AMD64 therefore
	// still boots libc-less, while ARM32 gets its real libc/libm/libdl
	// (naming note: the ARM32 tree keeps the image's original libc++.so /
	// libstdc++.so names, unlike lib64's libcpp/libstdcpp). The TLS slot
	// array holds guest pointers (4 bytes on ARM32).
	runtimeLibs := []string{
		"android/sdk23/lib64/libc.so",
		"android/sdk23/lib64/libm.so",
		"android/sdk23/lib64/libdl.so",
	}
	initGuest := initBionicTLS
	if ctx.ArchID == arch.IDARM {
		// liblog too: the NDK-built fixtures DT_NEEDED it (real
		// __android_log_print — usually interposed by the caller). The
		// ARM64 list deliberately stays three-library (boot red line).
		runtimeLibs = []string{
			"android/sdk23/lib/libc.so",
			"android/sdk23/lib/libm.so",
			"android/sdk23/lib/libdl.so",
			"android/sdk23/lib/liblog.so",
		}
		initGuest = initBionicTLS32
	}
	// The guest-visible utsname identity is per-arch personality data
	// : bionic's uname()-based checks read `machine` to pick library
	// directories, so it must match the target (aarch64 / armv7l /
	// x86_64). The kernel handler only encodes it.
	uname := &kernel.UnameInfo{
		Sysname:    "Linux",
		Nodename:   "localhost",
		Release:    "4.14.117-golem",
		Version:    "#1 SMP PREEMPT",
		Domainname: "localdomain",
	}
	switch ctx.ArchID {
	case arch.IDARM:
		uname.Machine = "armv7l"
	case arch.IDAMD64:
		uname.Machine = "x86_64"
	default:
		uname.Machine = "aarch64"
	}
	return &platform.Runtime{
		Startup:         startup,
		AuxvLookup:      auxvLookup,
		StackTopReserve: StackTopReserve,
		Layout:          LayoutPolicy{},
		Transport:       pers.Transport,
		Table:           pers.Table,
		Codecs:          pers.Codecs,
		Futex:           pers.Futex,
		Nanosleep:       pers.Nanosleep,
		ClockNanosleep:  pers.ClockNanosleep,
		// Bionic from the asset tree, in load order.
		RuntimeLibs:  runtimeLibs,
		Uname:        uname,
		InitGuest:    initGuest,
		ReplaceFns:   cfg.ReplaceFns,
		PthreadStubs: true,
		// Android always has the Java/device interop surface — an all-zero
		// config still wires the default JNI handler and the clock-
		// consistent time getters.
		Interop: &platform.Interop{
			Jni:              cfg.JNI,
			DexPath:          cfg.DexPath,
			PropertyProvider: cfg.PropertyProvider,
			Profile:          cfg.Profile,
		},
	}, nil
}

// initBionicTLS materializes bionic's TLS slot layout: TPIDR_EL0 points at a
// slot array; slot[0] (__get_tls self) = the TLS base, slot[1]
// (TLS_SLOT_THREAD_ID) = a zeroed pthread_internal_t that lives inside the
// TLS region, so its fields are always mapped. Without this, libc reads a
// NULL thread pointer and faults writing thread-local fields.
func initBionicTLS(mem platform.MemWriter, l memory.Layout) error {
	const (
		tlsSlotSelf     = 0 // __get_tls()[0] = tls base
		tlsSlotThreadID = 1 // -> pthread_internal_t*
	)
	put := func(addr, v uint64) error {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		return mem.MemWrite(emu.GuestAddr(addr), b[:])
	}
	pthreadStruct := uint64(l.TLSBase) + 0x1000
	if err := put(uint64(l.TLSBase)+tlsSlotSelf*8, uint64(l.TLSBase)); err != nil {
		return err
	}
	return put(uint64(l.TLSBase)+tlsSlotThreadID*8, pthreadStruct)
}

// initBionicTLS32 is the ARM32 variant of initBionicTLS: identical slot
// layout, but the slots hold 32-bit guest pointers (4-byte writes).
func initBionicTLS32(mem platform.MemWriter, l memory.Layout) error {
	const (
		tlsSlotSelf     = 0 // __get_tls()[0] = tls base
		tlsSlotThreadID = 1 // -> pthread_internal_t*
	)
	put := func(addr, v uint64) error {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(v))
		return mem.MemWrite(emu.GuestAddr(addr), b[:])
	}
	pthreadStruct := uint64(l.TLSBase) + 0x1000
	if err := put(uint64(l.TLSBase)+tlsSlotSelf*4, uint64(l.TLSBase)); err != nil {
		return err
	}
	return put(uint64(l.TLSBase)+tlsSlotThreadID*4, pthreadStruct)
}
