package emulator

import (
	"time"

	"github.com/isesword/golem/dvm"
	"github.com/isesword/golem/internal/profile"
)

// profileClock adapts a device profile to kernel.Clock: the wall clock is the
// host's, but the monotonic origin (boot time) is the persona's — so uptime
// and elapsedRealtime describe a device that has been alive for days, not a
// process that started seconds ago.
type profileClock struct{ prof *profile.Profile }

func (c profileClock) Now() time.Time      { return time.Now() }
func (c profileClock) BootTime() time.Time { return c.prof.BootTime }

// clockJni wraps the configured Jni handler and answers the four Java time
// getters from the SAME clock the syscall layer uses — a risk-control probe
// comparing System.currentTimeMillis against gettimeofday (or uptimeMillis
// against CLOCK_BOOTTIME) must find them consistent, and AbstractJni's
// default 0 (Jan 1970) is an instant emulator tell. Every other method
// delegates to the wrapped handler.
type clockJni struct {
	dvm.Jni                  // delegate for everything but the time getters
	e       *Emulator        // kernel clock access (effective Clock/Epoch/host)
	prof    *profile.Profile // nil = uptimeMillis == elapsedRealtime
}

func (j *clockJni) CallStaticLongMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) int64 {
	switch sig {
	case "java/lang/System->currentTimeMillis()J":
		return j.e.kctx.Now().UnixMilli()
	case "java/lang/System->nanoTime()J":
		// Android implements nanoTime on CLOCK_MONOTONIC; any monotonic origin
		// is spec-legal, so time-since-boot works.
		return int64(j.e.kctx.SinceBoot())
	case "android/os/SystemClock->elapsedRealtime()J":
		return int64(j.e.kctx.SinceBoot() / time.Millisecond)
	case "android/os/SystemClock->uptimeMillis()J":
		// With a profile, uptime excludes deep sleep (real Android semantics);
		// without one (or in pinned-Epoch mode) it equals elapsedRealtime.
		if j.prof != nil && j.e.cfg.Epoch == 0 {
			return int64(j.prof.UptimeMillis(j.e.kctx.Now()) / time.Millisecond)
		}
		return int64(j.e.kctx.SinceBoot() / time.Millisecond)
	}
	return j.Jni.CallStaticLongMethodV(vm, cls, sig, va)
}
