package emulator

import (
	"testing"
	"time"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/profile"
)

// clockJni answers the four Java time getters from the kernel clock, so JNI
// and syscall time can never disagree; everything else delegates.
func TestClockJniTimeGetters(t *testing.T) {
	prof := profile.New(42, time.Now())
	e := &Emulator{kctx: &kernel.Context{Clock: profileClock{prof: prof}}}
	j := &clockJni{Jni: dvm.AbstractJni{}, e: e, prof: prof}

	ctm := j.CallStaticLongMethodV(nil, nil, "java/lang/System->currentTimeMillis()J", nil)
	if d := time.Now().UnixMilli() - ctm; d < 0 || d > 5000 {
		t.Errorf("currentTimeMillis off by %d ms", d)
	}
	elapsed := j.CallStaticLongMethodV(nil, nil, "android/os/SystemClock->elapsedRealtime()J", nil)
	wantElapsed := time.Since(prof.BootTime).Milliseconds()
	if d := wantElapsed - elapsed; d < 0 || d > 5000 {
		t.Errorf("elapsedRealtime = %d ms, want ~%d (time since persona boot)", elapsed, wantElapsed)
	}
	nano := j.CallStaticLongMethodV(nil, nil, "java/lang/System->nanoTime()J", nil)
	if d := nano - elapsed*1e6; d < 0 || d > 5e9 {
		t.Errorf("nanoTime %d vs elapsedRealtime %d ms: origins differ", nano, elapsed)
	}
	uptime := j.CallStaticLongMethodV(nil, nil, "android/os/SystemClock->uptimeMillis()J", nil)
	if uptime > elapsed {
		t.Errorf("uptimeMillis %d > elapsedRealtime %d (uptime must exclude deep sleep)", uptime, elapsed)
	}
	if elapsed-uptime < elapsed/10 {
		t.Errorf("uptimeMillis %d barely below elapsed %d — no deep sleep subtracted", uptime, elapsed)
	}

	// unknown sigs fall through to the delegate (AbstractJni -> 0)
	if got := j.CallStaticLongMethodV(nil, nil, "com/foo/Bar->baz()J", nil); got != 0 {
		t.Errorf("delegate fallthrough = %d, want 0", got)
	}
}

// Epoch pins everything for signing determinism, even with a profile set:
// wall clock = epoch, monotonic/uptime zero-based, profile uptime bypassed.
func TestClockJniEpochWins(t *testing.T) {
	const epoch = 1700000000
	prof := profile.New(42, time.Now())
	e := &Emulator{
		cfg:  Config{Epoch: epoch},
		kctx: &kernel.Context{Epoch: epoch, Clock: profileClock{prof: prof}},
	}
	j := &clockJni{Jni: dvm.AbstractJni{}, e: e, prof: prof}

	if got := j.CallStaticLongMethodV(nil, nil, "java/lang/System->currentTimeMillis()J", nil); got != epoch*1000 {
		t.Errorf("currentTimeMillis = %d, want %d (pinned)", got, epoch*1000)
	}
	for _, sig := range []string{
		"java/lang/System->nanoTime()J",
		"android/os/SystemClock->elapsedRealtime()J",
		"android/os/SystemClock->uptimeMillis()J",
	} {
		if got := j.CallStaticLongMethodV(nil, nil, sig, nil); got != 0 {
			t.Errorf("%s = %d, want 0 (pinned: boot == epoch)", sig, got)
		}
	}
}
