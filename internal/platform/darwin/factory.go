package darwin

import (
	"fmt"

	"github.com/isesword/golem/internal/platform"
)

// The Darwin personality registers its factory at link time (P5b.5): the
// composition root resolves platform.Darwin -> this factory and binds the
// complete Runtime below. emulator holds no Darwin-specific selection
// logic beyond this registration.
func init() { platform.Register(platform.Darwin, factory{}) }

// factory assembles the Darwin Runtime from a BindContext. The per-arch
// selection (syscall transport/table/codecs) lives HERE — platform
// business, as SyscallPersonalityFor has always had it.
type factory struct{}

func (factory) Bind(ctx platform.BindContext) (*platform.Runtime, error) {
	// nil Config = platform defaults; a non-nil Config must be this
	// platform's own concrete type — anything else is a configuration
	// error, not a silent re-interpretation.
	cfg := NewConfig()
	if ctx.Config != nil {
		c, ok := ctx.Config.(*Config)
		if !ok {
			return nil, fmt.Errorf("darwin: platform config is %T (platform %s), want *darwin.Config", ctx.Config, ctx.Config.PlatformID())
		}
		cfg = c
	}
	pers, err := SyscallPersonalityFor(ctx.ArchID)
	if err != nil {
		return nil, err
	}
	return &platform.Runtime{
		Startup:         &StartupABI{},
		StackTopReserve: StackTopReserve,
		Layout:          LayoutPolicy{},
		Transport:       pers.Transport,
		Table:           pers.Table,
		Codecs:          pers.Codecs,
		Futex:           pers.Futex,
		Nanosleep:       pers.Nanosleep,
		ClockNanosleep:  pers.ClockNanosleep,
		ReplaceFns:      cfg.ReplaceFns,
		// Everything else stays absent by construction: no AuxvLookup (XNU
		// has no auxv — the StartupABI builds an exec-style initial stack
		// frame instead), no RuntimeLibs (P5b ships no dyld/libSystem), no
		// InitGuest (Darwin's TLS layout is dyld's business and P5b models
		// none of it), no PthreadStubs (no fiber scheduling — the psynch
		// primitives are not modelled), no Interop (a Darwin guest has no
		// Java runtime).
	}, nil
}
