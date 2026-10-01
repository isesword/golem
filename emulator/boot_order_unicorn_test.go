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
	// The 32 MiB sizing is a hint, not a contract: distro-packaged unicorn
	// builds (ubuntu-24.04-arm's libunicorn) reject it outright with
	// UC_ERR_ARG. The invariant under test is the TIMING of the sizing
	// (pre-execution, locked tag-free by TestBootTCGStepPrecedes...), so on
	// engines that refuse the hint, verify the largest accepted size instead
	// of pretending 32 is universal.
	const wantMiB = 32
	accepted := 0
	var lastErr error
	for _, mib := range []int{wantMiB, 16, 8, 4} {
		e, err := New(Config{
			SOPath:       "../examples/native/native.so",
			AssetRoot:    "../assets",
			TCGBufferMiB: mib,
		})
		if err != nil {
			lastErr = err
			continue
		}
		accepted = mib
		if mib != wantMiB {
			t.Logf("engine rejected TCGBufferMiB=%d (%v); verifying with the accepted %d MiB", wantMiB, lastErr, mib)
		}
		defer e.Close()

		if r, err := e.CallSymbol("add", Words(2, 3)...); err != nil || int32(r) != 5 {
			t.Fatalf("add(2,3) = %d, err=%v — guest execution after a sized TCG buffer must work", int32(r), err)
		}
		break
	}
	if accepted == 0 {
		// Distro builds (ubuntu's apt libunicorn) reject EVERY size — the
		// sizing-timing invariant is unverifiable on an engine that cannot
		// size; the stage position stays locked tag-free by
		// TestBootTCGStepPrecedesMappingAndExecution.
		t.Skipf("engine accepts no TCG sizing via UC_CTL_TCG_BUFFER_SIZE (last: %v)", lastErr)
	}
}
