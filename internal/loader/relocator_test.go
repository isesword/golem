package loader

import (
	"strings"
	"testing"

	"github.com/isesword/golem/internal/emu"
)

type fakeRelocator struct{ calls int }

func (f *fakeRelocator) Apply(emu.Backend, *Image, Reloc, uint64, SymbolResolver) error {
	f.calls++
	return nil
}

// TestRelocatorRegistry: register under a (Format, Arch) key, resolve the
// same instance back, and get an explicit error for an unregistered pair.
// Uses keys no real implementation occupies, so the test cannot clobber the
// genuine (FormatELF, ArchARM64) registration.
func TestRelocatorRegistry(t *testing.T) {
	fake := &fakeRelocator{}
	RegisterRelocator(FormatMachO, emu.ArchAMD64, fake)

	got, err := ResolveRelocator(FormatMachO, emu.ArchAMD64)
	if err != nil {
		t.Fatal(err)
	}
	if got != fake {
		t.Fatalf("resolved %T, want the registered instance", got)
	}

	if _, err := ResolveRelocator(FormatMachO, emu.ArchARM64); err == nil {
		t.Fatal("expected error for unregistered (FormatMachO, ArchARM64)")
	} else if !strings.Contains(err.Error(), "no relocator registered") {
		t.Fatalf("error should name the missing registration: %v", err)
	}

	// nil registrations are ignored, not stored.
	RegisterRelocator(FormatMachO, emu.ArchARM, nil)
	if _, err := ResolveRelocator(FormatMachO, emu.ArchARM); err == nil {
		t.Fatal("nil relocator must not become resolvable")
	}
}

// TestParserRegistry mirrors the relocator registry for format parsers.
func TestParserRegistry(t *testing.T) {
	called := false
	RegisterParser(FormatMachO, func(path string) (*Image, error) {
		called = true
		return &Image{Path: path}, nil
	})
	p, ok := parsers[FormatMachO]
	if !ok {
		t.Fatal("parser not registered")
	}
	img, err := p("/tmp/x")
	if err != nil || !called || img.Path != "/tmp/x" {
		t.Fatalf("parser dispatch broken: img=%v err=%v called=%v", img, err, called)
	}
	if _, ok := parsers[Format(0xfe)]; ok {
		t.Fatal("phantom parser present")
	}
}
