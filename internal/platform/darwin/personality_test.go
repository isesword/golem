package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
)

// TestPersonalityForARM64: the only supported combination — transport, table
// and codecs all present, scheduler interception numbers all zero (P5b does
// no Darwin fiber scheduling).
func TestPersonalityForARM64(t *testing.T) {
	p, err := SyscallPersonalityFor(arch.IDARM64)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport == nil || p.Table == nil || p.Codecs == nil {
		t.Fatalf("incomplete personality: %+v", p)
	}
	if p.Futex != 0 || p.Nanosleep != 0 || p.ClockNanosleep != 0 {
		t.Fatalf("Darwin scheduler interception must be inert in P5b, got futex=%d nanosleep=%d clock_nanosleep=%d",
			p.Futex, p.Nanosleep, p.ClockNanosleep)
	}
}

// TestPersonalityForUnsupported: AMD64 (and anything else) errors loudly —
// the error names the missing support.
func TestPersonalityForUnsupported(t *testing.T) {
	if _, err := SyscallPersonalityFor(arch.IDAMD64); err == nil {
		t.Fatal("Darwin/AMD64 must error (P5b supports ARM64 only)")
	}
}
