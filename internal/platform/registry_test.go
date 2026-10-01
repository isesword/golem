package platform

import (
	"strings"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/kernel"
)

// This file is the synthetic-platform proof: a brand-new platform
// personality — never linked into emulator's wiring — is registered,
// resolved and bound through exactly the Register/Resolve/Bind contract the
// composition root uses. Nothing outside this package changes for the
// synthetic platform to exist; that is the property that lets a real third
// platform land without touching the emulator.

const (
	synthID  = ID(240) // registered in the tests below
	unusedID = ID(241) // never registered
)

// synthConfig is the synthetic platform's typed boot configuration.
type synthConfig struct {
	greeting string
}

func (synthConfig) PlatformID() ID { return synthID }

// synthStartup is a trivial StartupABI (the synthetic platform builds no
// initial state).
type synthStartup struct {
	built int
}

func (s *synthStartup) BuildInitialState(ctx *StartupContext) error {
	s.built++
	return nil
}

// synthFactory mimics the real personalities' Bind shape: it asserts its
// concrete config type (a mismatch is a configuration error), selects
// per-arch pieces by BindContext.ArchID (an unknown arch is an error naming
// the missing support), and produces the complete Runtime as data in one
// pass.
type synthFactory struct {
	sawCtx  BindContext
	bindErr error
}

func (f *synthFactory) Bind(ctx BindContext) (*Runtime, error) {
	f.sawCtx = ctx
	if f.bindErr != nil {
		return nil, f.bindErr
	}
	cfg := synthConfig{greeting: "default"}
	if ctx.Config != nil {
		c, ok := ctx.Config.(synthConfig)
		if !ok {
			return nil, errSynthConfig
		}
		cfg = c
	}
	if ctx.ArchID != arch.IDARM64 {
		return nil, errSynthArch
	}
	startup := &synthStartup{}
	return &Runtime{
		Startup:         startup,
		StackTopReserve: 0x300,
		Table:           &kernel.Table{},
		Futex:           98, // asm-generic __NR_futex, as arbitrary data
		Interop:         &Interop{DexPath: cfg.greeting},
	}, nil
}

var (
	errSynthConfig = errorString("synth: platform config of the wrong type")
	errSynthArch   = errorString("synth: no syscall personality for this arch")
)

type errorString string

func (e errorString) Error() string { return string(e) }

// TestSyntheticPlatformRegistersAndBinds is the core proof: register a
// factory under a fresh platform ID, resolve it back, and bind a complete
// Runtime — config flowing in, personality data flowing out.
func TestSyntheticPlatformRegistersAndBinds(t *testing.T) {
	f := &synthFactory{}
	Register(synthID, f)

	got, err := Resolve(synthID)
	if err != nil {
		t.Fatalf("Resolve(synthID): %v", err)
	}
	if got != Factory(f) {
		t.Fatalf("Resolve(synthID) = %T, want the registered *synthFactory", got)
	}

	rt, err := got.Bind(BindContext{ArchID: arch.IDARM64, Config: synthConfig{greeting: "hello"}})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// The factory saw the exact BindContext the caller passed.
	if f.sawCtx.ArchID != arch.IDARM64 {
		t.Fatalf("factory saw ArchID %v, want %v", f.sawCtx.ArchID, arch.IDARM64)
	}
	if cfg, ok := f.sawCtx.Config.(synthConfig); !ok || cfg.greeting != "hello" {
		t.Fatalf("factory saw Config %#v, want synthConfig{hello}", f.sawCtx.Config)
	}
	// The Runtime carries the factory's composition product as data.
	if rt.Startup == nil || rt.Table == nil {
		t.Fatal("Runtime must carry the factory's Startup and syscall Table")
	}
	if rt.StackTopReserve != 0x300 || rt.Futex != 98 {
		t.Fatalf("Runtime data = reserve %#x futex %d, want 0x300/98", rt.StackTopReserve, rt.Futex)
	}
	if rt.Interop == nil || rt.Interop.DexPath != "hello" {
		t.Fatalf("Runtime.Interop = %#v, want config-derived DexPath", rt.Interop)
	}
	if rt.AuxvLookup != nil || rt.InitGuest != nil || rt.PthreadStubs {
		t.Fatal("features the synthetic platform did not opt into must stay absent")
	}
}

// TestSyntheticPlatformBindDefaults: a nil Config means "platform defaults" —
// the factory, not the composition root, decides what those are.
func TestSyntheticPlatformBindDefaults(t *testing.T) {
	rt, err := (&synthFactory{}).Bind(BindContext{ArchID: arch.IDARM64})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if rt.Interop == nil || rt.Interop.DexPath != "default" {
		t.Fatalf("nil Config must yield platform defaults, got %#v", rt.Interop)
	}
}

// TestSyntheticPlatformBindErrors: the factory owns its configuration and
// per-arch errors — a wrong config type or an unsupported arch surfaces from
// Bind, not from any composition-root type-switch.
func TestSyntheticPlatformBindErrors(t *testing.T) {
	f := &synthFactory{}
	if _, err := f.Bind(BindContext{ArchID: arch.IDARM64, Config: synthOtherConfig{}}); err != errSynthConfig {
		t.Fatalf("wrong config type: err = %v, want errSynthConfig", err)
	}
	if _, err := f.Bind(BindContext{ArchID: arch.IDAMD64, Config: synthConfig{}}); err != errSynthArch {
		t.Fatalf("unsupported arch: err = %v, want errSynthArch", err)
	}
}

// synthOtherConfig is a Config implementation for a DIFFERENT platform — the
// wrong-type assertion case.
type synthOtherConfig struct{}

func (synthOtherConfig) PlatformID() ID { return ID(242) }

// TestResolveUnregistered: an unknown platform ID is a resolution error that
// names the platform and the fix (import the subpackage).
func TestResolveUnregistered(t *testing.T) {
	if _, err := Resolve(unusedID); err == nil {
		t.Fatal("Resolve(unregistered) must fail")
	} else if !strings.Contains(err.Error(), "no factory registered") {
		t.Fatalf("Resolve error = %q, want the missing-registration message", err)
	}
}

// TestRegisterSemantics match the loader's registry contract: a nil factory
// is ignored; a duplicate key overwrites (init-time registration, last
// linked wins). It runs on an isolated Registry instance — the global
// default table is init()-time territory, and "clean up" of global state
// would be exactly the kind of order-dependent hermeticity leak that breaks
// -count=2.
func TestRegisterSemantics(t *testing.T) {
	const id = ID(243)
	r := NewRegistry()
	r.Register(id, nil)
	if _, err := r.Resolve(id); err == nil {
		t.Fatal("Register(id, nil) must leave the id unregistered")
	}
	first, second := &synthFactory{}, &synthFactory{}
	r.Register(id, first)
	r.Register(id, second)
	if got, err := r.Resolve(id); err != nil || got != Factory(second) {
		t.Fatalf("duplicate Register must overwrite: got %v, %v", got, err)
	}
}
