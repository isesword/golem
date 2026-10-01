package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
)

// TestFactoryRegistered: init() must have registered the Darwin factory
// under platform.Darwin — this is the only way the composition root ever
// reaches it.
func TestFactoryRegistered(t *testing.T) {
	f, err := platform.Resolve(platform.Darwin)
	if err != nil {
		t.Fatalf("Resolve(platform.Darwin): %v", err)
	}
	if _, ok := f.(factory); !ok {
		t.Fatalf("registered factory = %T, want darwin.factory", f)
	}
}

// TestFactoryBindARM64 pins the Runtime the factory produces: the thin
// Darwin personality as data — syscall pieces and layout present, every
// Android-only surface provably absent.
func TestFactoryBindARM64(t *testing.T) {
	replaceFns := map[string]interpose.HostFunc{"bar": nil}
	rt, err := (factory{}).Bind(platform.BindContext{
		ArchID: arch.IDARM64,
		Config: NewConfig(WithReplaceFns(replaceFns)),
	})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, ok := rt.Startup.(*StartupABI); !ok {
		t.Fatalf("Runtime.Startup = %T, want *darwin.StartupABI", rt.Startup)
	}
	if rt.StackTopReserve != StackTopReserve {
		t.Fatalf("StackTopReserve = %#x, want %#x", rt.StackTopReserve, StackTopReserve)
	}
	if rt.Layout == nil || rt.Transport == nil || rt.Table == nil || rt.Codecs == nil {
		t.Fatal("Runtime must carry layout + syscall personality")
	}
	if len(rt.ReplaceFns) != 1 {
		t.Fatalf("ReplaceFns = %v, want the config's map", rt.ReplaceFns)
	}
	// The absent surfaces are the contract: no auxv, no runtime
	// libraries, no TLS init, no pthread stubs, no scheduler interception,
	// no Java/device interop.
	if rt.AuxvLookup != nil {
		t.Fatal("Darwin has no auxv — AuxvLookup must be nil")
	}
	if rt.RuntimeLibs != nil || rt.InitGuest != nil || rt.PthreadStubs || rt.Interop != nil {
		t.Fatal("Darwin must carry no runtime libs, TLS init, pthread stubs or interop surface")
	}
	if rt.Futex != 0 || rt.Nanosleep != 0 || rt.ClockNanosleep != 0 {
		t.Fatal("P5b does no fiber scheduling for Darwin — interception numbers stay 0")
	}
}

// TestFactoryBindDefaultsAndErrors: nil Config yields platform defaults; a
// foreign config type and an unsupported arch are Bind errors.
func TestFactoryBindDefaultsAndErrors(t *testing.T) {
	rt, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDARM64})
	if err != nil {
		t.Fatalf("Bind(nil config): %v", err)
	}
	if len(rt.ReplaceFns) != 0 {
		t.Fatalf("nil Config must yield zero-value defaults, got %v", rt.ReplaceFns)
	}
	if _, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDARM64, Config: foreignConfig{}}); err == nil {
		t.Fatal("a foreign platform config must be a Bind error")
	}
	if _, err := (factory{}).Bind(platform.BindContext{ArchID: arch.IDAMD64}); err == nil {
		t.Fatal("Darwin/AMD64 is unsupported and must be a Bind error")
	}
}

// foreignConfig is a platform.Config that is not *darwin.Config.
type foreignConfig struct{}

func (foreignConfig) PlatformID() platform.ID { return platform.Android }
