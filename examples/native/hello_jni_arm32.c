// Real-bionic ARMv7 JNI fixture (P7) — built with the NDK's
// armv7a-linux-androideabi23-clang against the platform libc/liblog, so the
// whole chain is REAL: DT_NEEDED libc.so/liblog.so resolved from the
// loaded bionic modules, crt init via init_array, libc heap/string calls,
// a liblog call (host-interposed in the tests), and a real syscall through
// the libc wrapper.
//
// Build (committed prebuilt is hello_jni_arm32.so; rebuild with
// build_android_arm32_jni_fixture.sh):
//   armv7a-linux-androideabi23-clang -shared -fPIC -O2 \
//       -o hello_jni_arm32.so hello_jni_arm32.c -llog

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "golem-p7"

// JNI_OnLoad is called by golem's LoadLibrary (the emulator's JavaVM
// contract): logs once and reports JNI 1.6.
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "JNI_OnLoad");
    return JNI_VERSION_1_6;
}

// heapRoundTrip exercises the libc heap and string machinery for real:
// malloc + snprintf + strlen + memcpy + free, all resolved into the loaded
// bionic libc. Returns strlen(buf) + strlen(copy) + n so every step's
// result is observable: with n=7 -> "p7-7" -> 4 + 4 + 7 = 15.
jlong Java_golem_p7_Native_heapRoundTrip(JNIEnv *env, jclass cls, jint n) {
    (void)env; (void)cls;
    char *buf = malloc(64);
    if (!buf) return -1;
    snprintf(buf, 64, "p7-%d", (int)n);
    size_t len = strlen(buf);
    char *copy = malloc(len + 1);
    if (!copy) { free(buf); return -2; }
    memcpy(copy, buf, len + 1);
    jlong out = (jlong)len + (jlong)strlen(copy) + (jlong)n;
    free(copy);
    free(buf);
    return out;
}

// getpidViaLibc calls the libc getpid() wrapper — a REAL syscall (r7/svc)
// through the loaded bionic, returning the emulator's configured pid.
jlong Java_golem_p7_Native_getpidViaLibc(JNIEnv *env, jclass cls) {
    (void)env; (void)cls;
    return (jlong)getpid();
}

// logLine issues one real liblog call (the tests interpose
// __android_log_print and record it). Returns the priority it used.
jlong Java_golem_p7_Native_logLine(JNIEnv *env, jclass cls, jint prio) {
    (void)env; (void)cls;
    __android_log_print((int)prio, LOG_TAG, "native line %d", 42);
    return (jlong)prio;
}
