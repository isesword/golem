#!/bin/sh
# Rebuilds the committed Android/ARM32 fixture (hello_android_arm32.so) with
# zig cc (the same toolchain family as the x86-64 fixture). macOS/Linux +
# zig required (Windows builds never need this — the prebuilt .so is
# committed, see hello_android_arm32.c for what it carries).
#
#   -target arm-linux-gnueabihf -mcpu=cortex_a7 : armv7-a hard-float EABI
#     (zig names its CPUs; cortex_a7 is the armv7-a baseline. Integer
#     arguments follow the same AAPCS32 core rules under hard- and
#     soft-float — VFP only changes FLOAT argument passing, which this
#     fixture has none of — and EM_ARM + EABI version 5 is what the loader
#     keys on).
#   -shared -nostdlib                          : no libc — the asset tree
#     ships no 32-bit bionic (P6e); the single import (host_magic) is left
#     undefined and bound by the tests through golem's HostResolver.
#   -fno-stack-protector                       : no __stack_chk_guard from
#     libc to resolve.
# thumb_add carries __attribute__((target("thumb"))) — verify the Thumb
# bit0 on its st_value with:  zig objdump --syms hello_android_arm32.so
set -e
cd "$(dirname "$0")"
zig cc -target arm-linux-gnueabihf -mcpu=cortex_a7 -shared -nostdlib \
       -fno-builtin -fno-stack-protector -O2 \
       -o hello_android_arm32.so hello_android_arm32.c
