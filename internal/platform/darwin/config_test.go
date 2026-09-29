package darwin

import (
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform"
)

func TestConfigPlatformID(t *testing.T) {
	c := NewConfig()
	if c.PlatformID() != platform.Darwin {
		t.Fatalf("PlatformID = %s, want darwin", c.PlatformID())
	}
	var _ platform.Config = c // the composition root carries it platform-agnostically
}

func TestConfigWithReplaceFns(t *testing.T) {
	fn := interpose.HostFunc(nil)
	c := NewConfig(WithReplaceFns(map[string]interpose.HostFunc{"host_magic": fn}))
	if _, ok := c.ReplaceFns["host_magic"]; !ok {
		t.Fatalf("ReplaceFns not installed: %v", c.ReplaceFns)
	}
	// nil option is tolerated, like the Android options.
	c2 := NewConfig(nil)
	if c2.ReplaceFns != nil {
		t.Fatal("zero-value Config must carry no ReplaceFns")
	}
}
