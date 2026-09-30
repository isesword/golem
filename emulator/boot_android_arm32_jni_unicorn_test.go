//go:build unicorn && (darwin || linux)

// P7 acceptance: the REAL-WORLD Android/ARM32 runtime — a full boot with
// the API-23 armeabi-v7a bionic (real libc/libm/libdl/liblog mapped and
// relocated from the asset tree) under an NDK-built JNI library whose
// DT_NEEDED chain resolves through the loaded modules. This is the
// product-level step past P6e's architecture proof:
//
//	boot (4 bionic libs + fixture) -> JNI_OnLoad runs (the emulator's
//	JavaVM contract) -> native calls -> REAL libc work (malloc/snprintf/
//	strlen/memcpy/free inside bionic) -> REAL syscall through the libc
//	wrapper (getpid) -> real liblog call (host-interposed) -> return.
package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform/android"
)

func TestBootAndroidARM32RealBionicJNI(t *testing.T) {
	const so = "../examples/native/hello_jni_arm32.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	// The 32-bit bionic assets are NOT tracked in git (public repo — see
	// .gitignore); fetch them with scripts/fetch_bionic_arm32.sh.
	const bionic = "../assets/android/sdk23/lib/libc.so"
	if _, err := os.Stat(bionic); err != nil {
		t.Skipf("ARM32 bionic assets not fetched: %v (run scripts/fetch_bionic_arm32.sh)", err)
	}

	type logCall struct{ prio, tag uint64 }
	var logCalls []logCall
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			// __android_log_write/__android_log_print: the liblog surface
			// the fixture uses. Record (prio, tag-ptr), return 0 — the
			// real /dev/log socket is out of scope.
			"__android_log_print": func(ctx interpose.CallContext) uint64 {
				h := ctx.(*Hook)
				logCalls = append(logCalls, logCall{prio: h.Arg(0), tag: h.Arg(1)})
				return 0
			},
		}),
	)))
	if err != nil {
		t.Fatalf("New (ARM32 + real bionic boot): %v", err)
	}
	defer e.Close()

	// JNI_OnLoad ran during LoadLibrary (boot): it logs exactly once.
	if len(logCalls) != 1 {
		t.Fatalf("log calls after boot = %d, want exactly 1 (JNI_OnLoad)", len(logCalls))
	}
	if logCalls[0].prio != 4 { // ANDROID_LOG_INFO
		t.Fatalf("JNI_OnLoad log priority = %d, want 4 (INFO)", logCalls[0].prio)
	}

	call := func(name string, args ...uint64) uint64 {
		t.Helper()
		v, err := e.CallSymbol(name, args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return v
	}
	env := e.JavaVM() // the functions ignore env/cls; pass the vm pointer honestly

	// Real libc heap/string work inside the loaded bionic: malloc(64) ->
	// snprintf("p7-7") -> strlen -> malloc -> memcpy -> strlen -> free.
	// "p7-7" is 4 chars: 4 + 4 + 7 = 15.
	if got := call("Java_golem_p7_Native_heapRoundTrip", env, 0, 7); got != 15 {
		t.Fatalf("heapRoundTrip(7) = %d, want 15 (malloc/snprintf/strlen/memcpy/free in real bionic)", got)
	}
	// Real syscall through the libc wrapper (r7/svc into the P6d table).
	if got := call("Java_golem_p7_Native_getpidViaLibc", env, 0); got != 4242 {
		t.Fatalf("getpidViaLibc() = %d, want 4242", got)
	}
	// Real liblog call, host-interposed.
	if got := call("Java_golem_p7_Native_logLine", env, 0, 3); got != 3 {
		t.Fatalf("logLine(3) = %d, want 3", got)
	}
	if len(logCalls) != 2 || logCalls[1].prio != 3 {
		t.Fatalf("log calls = %v, want a second call with priority 3", logCalls)
	}
}
