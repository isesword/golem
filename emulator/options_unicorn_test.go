//go:build unicorn

package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/platform/android"
)

// End-to-end equivalence (P4a): booting through the functional-options path
// (WithPlatformConfig + android.NewConfig) must produce the same observable
// behavior as the deprecated Config.Android legacy path — here the
// ReplaceFns export interposition. The legacy twin is
// TestReplaceFnsPostBootExportPatch in shared_test.go.
func TestWithPlatformConfigBootEquivalence(t *testing.T) {
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"add": func(ctx interpose.CallContext) uint64 {
				h := ctx.(*Hook)
				return mustArg(h, 0)*10 + mustArg(h, 1)
			},
		}),
	)))
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	defer e.Close()

	if e.target == nil || e.target.Platform != platform.Android {
		t.Fatalf("target not resolved: %+v", e.target)
	}
	r, err := e.CallSymbol("add", 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	if r != 23 {
		t.Fatalf("options-path ReplaceFns interposition inactive: add(2,3)=%d, want 23", r)
	}
}
