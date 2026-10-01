package emu

import (
	"errors"
	"fmt"
	"testing"
)

// stubBackend is a minimal Backend for registry tests: the registry only
// exercises the factory plumbing, never a backend method, so the nil embedded
// interface (which panics if a method IS called — failing the test loudly) is
// exactly right.
type stubBackend struct{ Backend }

// TestFactoryReceivesArch pins the contract: the Arch given to NewNamed is
// handed to the backend's Factory unchanged.
func TestFactoryReceivesArch(t *testing.T) {
	var got Arch
	Register("test-arch-probe", func(a Arch) (Backend, error) {
		got = a
		return stubBackend{}, nil
	})
	for _, a := range []Arch{ArchARM64, ArchARM, ArchAMD64} {
		got = 0
		if _, err := NewNamed("test-arch-probe", a); err != nil {
			t.Fatalf("NewNamed(_, %v): %v", a, err)
		}
		if got != a {
			t.Fatalf("factory received arch %d, want %d", got, a)
		}
	}
}

// TestFactoryUnsupportedArch mirrors the unicorn backend's behavior with a
// stub factory: a non-ARM64 request must come back as an error that
// errors.Is(ErrUnsupported) recognizes, and ARM64 must succeed.
func TestFactoryUnsupportedArch(t *testing.T) {
	Register("test-arm64-only", func(a Arch) (Backend, error) {
		if a != ArchARM64 {
			return nil, fmt.Errorf("emu: stub backend: arch %s: %w", a, ErrUnsupported)
		}
		return stubBackend{}, nil
	})
	if _, err := NewNamed("test-arm64-only", ArchARM); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ArchARM: err = %v, want errors.Is(ErrUnsupported)", err)
	}
	if _, err := NewNamed("test-arm64-only", ArchAMD64); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ArchAMD64: err = %v, want errors.Is(ErrUnsupported)", err)
	}
	if _, err := NewNamed("test-arm64-only", ArchARM64); err != nil {
		t.Fatalf("ArchARM64: %v", err)
	}
}
