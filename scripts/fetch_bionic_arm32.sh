#!/bin/bash
# fetch_bionic_arm32.sh — fetch the real 32-bit ARM bionic runtime libraries
# from the official Android SDK API 23 (Android 6.0) armeabi-v7a system image
# and place them under assets/android/sdk23/lib/.
#
# These binaries are NOT tracked in git (AOSP bionic is BSD-licensed, OpenSSL
# and the GCC runtime have their own attribution terms — redistribution is
# permitted but we follow the emulator-project convention of fetching them
# locally instead of committing device-extracted binaries to a public repo).
#
# Requirements: Java, Android cmdline-tools (sdkmanager), e2fsprogs (debugfs).
#   macOS:  brew install --cask android-commandlinetools temurin
#           brew install e2fsprogs
#
# Usage:  scripts/fetch_bionic_arm32.sh [SDK_ROOT]
#   SDK_ROOT defaults to ~/Library/Android/sdk (macOS default).

set -euo pipefail

SDK_ROOT="${1:-$HOME/Library/Android/sdk}"
API="android-23"
ABI="armeabi-v7a"
PKG="system-images;${API};default;${ABI}"
IMG_DIR="$SDK_ROOT/system-images/${API}/default/${ABI}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/assets/android/sdk23/lib"

SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
if [ ! -x "$SDKMANAGER" ]; then
    for cand in /opt/homebrew/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager \
                /usr/local/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager; do
        [ -x "$cand" ] && SDKMANAGER="$cand" && break
    done
fi
[ -x "$SDKMANAGER" ] || { echo "error: sdkmanager not found (install android-commandlinetools)" >&2; exit 1; }

DEBUGFS="$(command -v debugfs || true)"
if [ -z "$DEBUGFS" ]; then
    for cand in /opt/homebrew/opt/e2fsprogs/sbin/debugfs /usr/local/opt/e2fsprogs/sbin/debugfs; do
        [ -x "$cand" ] && DEBUGFS="$cand" && break
    done
fi
[ -x "$DEBUGFS" ] || { echo "error: debugfs not found (install e2fsprogs)" >&2; exit 1; }

if [ ! -f "$IMG_DIR/system.img" ]; then
    echo ">> accepting licenses"
    yes | "$SDKMANAGER" --sdk_root="$SDK_ROOT" --licenses >/dev/null || true
    echo ">> downloading $PKG"
    "$SDKMANAGER" --sdk_root="$SDK_ROOT" "$PKG"
fi

# The API-23 image is raw ext4 whose filesystem root IS the /system partition,
# so the libraries live at /lib (not /system/lib) inside the image.
LIBS="libc.so libm.so libdl.so liblog.so libz.so libstdc++.so libc++.so libcrypto.so libssl.so libcutils.so"

mkdir -p "$OUT_DIR"
for lib in $LIBS; do
    "$DEBUGFS" -R "dump /lib/$lib $OUT_DIR/$lib" "$IMG_DIR/system.img" >/dev/null 2>&1
    echo "   extracted $lib"
done
"$DEBUGFS" -R "dump /bin/linker $OUT_DIR/linker" "$IMG_DIR/system.img" >/dev/null 2>&1
echo "   extracted linker"

echo ">> done: $OUT_DIR"
ls -la "$OUT_DIR"
