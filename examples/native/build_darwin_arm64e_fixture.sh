#!/bin/sh
# Rebuilds the committed Mach-O ARM64E fixtures (P5c). macOS + Xcode CLT
# required (Windows/Linux builds never need this — the prebuilt dylibs are
# committed, see the .c files for what they carry).
#
# Two outputs:
#   hello_darwin_arm64e.dylib   — the default arm64e toolchain product:
#                                 LC_DYLD_CHAINED_FIXUPS with all four entry
#                                 kinds (auth/non-auth rebase/bind). Calls
#                                 through loader-materialized pointers use
#                                 explicit `blr` asm, and -fno-ptrauth-
#                                 returns drops the ABI-forced pac-ret pair
#                                 (see the .c header — golem emulates no PAC
#                                 instruction semantics; this unicorn build
#                                 faults on retab).
#   hostdata_darwin_arm64.dylib — plain arm64 classic data exporter; the
#                                 cross-module bind target for host_value.
#
# TOOLCHAIN FACT (ld 27037.1): an arm64e + classic-opcodes variant
# (-Wl,-no_fixup_chains) is UNPRODUCIBLE — ld emits "bind opcodes are no
# longer supported with arm64e, switching to chained fixups" and ignores the
# flag; -ld_classic is gone too. Apple now mandates chained fixups for
# arm64e, so that combination is not a real-world input; the classic opcode
# path stays covered by the arm64 fixtures (hello_darwin_arm64.dylib).
#
# -undefined,dynamic_lookup leaves host_magic/host_value undefined at link
# time — the tests bind them through golem's resolver chain at load time.
set -e
cd "$(dirname "$0")"

clang -arch arm64e -target arm64-apple-macos11 -dynamiclib \
      -fno-builtin -fno-stack-protector -mbranch-protection=none \
      -fno-ptrauth-returns -O2 \
      -Wl,-undefined,dynamic_lookup \
      -o hello_darwin_arm64e.dylib hello_darwin_arm64e.c

clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
      -fno-builtin -fno-stack-protector -O2 \
      -Wl,-no_fixup_chains \
      -o hostdata_darwin_arm64.dylib hostdata_darwin_arm64.c
