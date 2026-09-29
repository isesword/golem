package android

import (
	"testing"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
	"github.com/isesword/golem/internal/profile"
)

// testJni is a distinguishable dvm.Jni implementation (AbstractJni answers
// everything with null/0).
type testJni struct{ dvm.AbstractJni }

func TestNewConfigOptions(t *testing.T) {
	jni := testJni{}
	fns := map[string]interpose.HostFunc{
		"clock": func(ctx interpose.CallContext) uint64 { return 7 },
	}
	provider := func(key string) (string, bool) { return "v-" + key, true }
	prof := &profile.Profile{}

	c := NewConfig(
		WithJNI(jni),
		WithDexPath("/data/classes.dex"),
		WithReplaceFns(fns),
		WithPropertyProvider(provider),
		WithProfile(prof),
		nil, // nil options are skipped
	)

	if c.JNI != jni {
		t.Fatalf("WithJNI not applied: got %T", c.JNI)
	}
	if c.DexPath != "/data/classes.dex" {
		t.Fatalf("WithDexPath not applied: got %q", c.DexPath)
	}
	if len(c.ReplaceFns) != 1 {
		t.Fatalf("WithReplaceFns not applied: got %d entries", len(c.ReplaceFns))
	}
	if got := c.ReplaceFns["clock"](nil); got != 7 {
		t.Fatalf("ReplaceFns entry: got %d, want 7", got)
	}
	if v, ok := c.PropertyProvider("ro.x"); !ok || v != "v-ro.x" {
		t.Fatalf("WithPropertyProvider not applied: got (%q, %v)", v, ok)
	}
	if c.Profile != prof {
		t.Fatal("WithProfile not applied")
	}
	if c.PlatformID() != platform.Android {
		t.Fatalf("PlatformID = %v, want android", c.PlatformID())
	}
}

func TestNewConfigZero(t *testing.T) {
	c := NewConfig()
	if c.JNI != nil || c.DexPath != "" || len(c.ReplaceFns) != 0 ||
		c.PropertyProvider != nil || c.Profile != nil {
		t.Fatalf("zero config not zero: %+v", c)
	}
	var _ platform.Config = c // compile-time contract
}
