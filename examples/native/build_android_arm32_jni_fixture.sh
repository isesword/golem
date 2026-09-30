#!/bin/sh
# Rebuilds the committed real-bionic ARMv7 JNI fixture (hello_jni_arm32.so)
# with the Android NDK toolchain. macOS + NDK required (Windows/Linux
# builds never need this — the prebuilt .so is committed, see
# hello_jni_arm32.c for what it carries).
#
# The NDK clang links against the platform libc/liblog: the output carries
# DT_NEEDED libc.so + liblog.so (+ crt init in .init_array), all resolved
# from golem's loaded bionic modules at test time.
set -e
cd "$(dirname "$0")"
NDK_BIN=/opt/homebrew/share/android-ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin
"$NDK_BIN/armv7a-linux-androideabi23-clang" -shared -fPIC -O2 \
    -o hello_jni_arm32.so hello_jni_arm32.c -llog
