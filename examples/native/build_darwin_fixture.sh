#!/bin/sh
# Rebuilds the committed Mach-O arm64 fixture (hello_darwin_arm64.dylib).
# macOS + Xcode CLT required (Windows/Linux builds never need this — the
# prebuilt dylib is committed, see hello_darwin_arm64.c for what it carries).
#
# -no_fixup_chains keeps classic LC_DYLD_INFO_ONLY rebase/bind opcodes;
# chained fixups are the ARM64e/PAC world (P5c, deliberately unsupported).
# -undefined,dynamic_lookup leaves host_magic undefined at link time — the
# tests bind it through golem's HostResolver at load time.
set -e
cd "$(dirname "$0")"
clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
      -fno-builtin -fno-stack-protector -O2 \
      -Wl,-no_fixup_chains -Wl,-undefined,dynamic_lookup \
      -o hello_darwin_arm64.dylib hello_darwin_arm64.c
