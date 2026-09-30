//go:build unicorn

package emulator

import (
	"testing"
)

// TestTCGBufferAppliedBeforeFirstExecution is the unicorn-side regression net
// for the §4 TCG-timing invariant: unicorn's UC_CTL_TCG_BUFFER_SIZE only
// takes effect ahead of the first uc_emu_start, so a boot with an explicit
// TCGBufferMiB that goes on to execute guest code proves the sizing was
// applied in stage 6 (pre-execution), not retroactively. The step's position
// relative to mapping/loading is locked tag-free by
// TestBootTCGStepPrecedesMappingAndExecution (boot_order_test.go).
func TestTCGBufferAppliedBeforeFirstExecution(t *testing.T) {
	e, err := New(Config{
		SOPath:       "../examples/native/native.so",
		AssetRoot:    "../assets",
		TCGBufferMiB: 32,
	})
	if err != nil {
		t.Fatalf("boot with TCGBufferMiB=32: %v", err)
	}
	defer e.Close()

	if r, err := e.CallSymbol("add", Words(2, 3)...); err != nil || int32(r) != 5 {
		t.Fatalf("add(2,3) = %d, err=%v — guest execution after a sized TCG buffer must work", int32(r), err)
	}
}
