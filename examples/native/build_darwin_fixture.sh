#!/bin/sh
# Rebuilds the committed Mach-O arm64 fixtures (hello_darwin_arm64.dylib
# and hello_darwin_arm64_chained.dylib) from the SAME source. macOS +
# Xcode CLT required (Windows/Linux builds never need this — the prebuilt
# dylibs are committed, see hello_darwin_arm64.c for what they carry).
#
#   hello_darwin_arm64.dylib         — classic LC_DYLD_INFO_ONLY rebase/
#                                      bind opcodes (-no_fixup_chains).
#   hello_darwin_arm64_chained.dylib — LC_DYLD_CHAINED_FIXUPS, pointer
#                                      format DYLD_CHAINED_PTR_64 (2): the
#                                      P5d fixture.
#
# TOOLCHAIN FACT (ld 27037.1): plain arm64 defaults to CLASSIC opcodes —
# even with -target arm64-apple-macos14 — so the chained variant needs an
# explicit -fixup_chains. That flag is also what produces format 2: this
# is the same payload real modern Darwin binaries carry.
#
# -undefined,dynamic_lookup leaves host_magic undefined at link time — the
# tests bind it through golem's HostResolver at load time.
set -e
cd "$(dirname "$0")"
clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
      -fno-builtin -fno-stack-protector -O2 \
      -Wl,-no_fixup_chains -Wl,-undefined,dynamic_lookup \
      -o hello_darwin_arm64.dylib hello_darwin_arm64.c
clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
      -fno-builtin -fno-stack-protector -O2 \
      -Wl,-fixup_chains -Wl,-undefined,dynamic_lookup \
      -o hello_darwin_arm64_chained.dylib hello_darwin_arm64.c
