// Tiny Darwin/ARM64E (Mach-O arm64e) shared library — the P5c touchstone
// fixture for golem's arch x platform x format matrix: same ARM64 CPU and
// Darwin platform as hello_darwin_arm64, but the ARM64E variant with
// CHAINED FIXUPS (LC_DYLD_CHAINED_FIXUPS, DYLD_CHAINED_PTR_ARM64E) instead
// of classic dyld opcodes. It deliberately exercises all four chain-entry
// kinds the loader decodes:
//
//	host_fp      -> AUTH bind      (function pointer to an import)
//	host_val_ptr -> non-auth bind  (data pointer to an import)
//	fptr_table   -> AUTH rebase    (function pointer to a local)
//	local_ptr    -> non-auth rebase(data pointer to a local)
//
// Build (committed prebuilt is hello_darwin_arm64e.dylib; rebuild on macOS
// with build_darwin_arm64e_fixture.sh):
//   clang -arch arm64e -target arm64-apple-macos11 -dynamiclib \
//         -fno-builtin -fno-stack-protector -mbranch-protection=none -O2 \
//         -Wl,-undefined,dynamic_lookup \
//         -o hello_darwin_arm64e.dylib hello_darwin_arm64e.c
//
// CALL-SITE AUTHENTICATION: golem's PACPolicyStrip materializes BARE
// pointers into the auth slots, so no guest code may authenticate a
// loader-materialized pointer (P5c policy). But clang ties call-site
// authentication to signed-storage provenance: ANY call through a value it
// can trace back to the signed globals emits blraaz — neither
// -mbranch-protection=none nor integer casts remove it, and
// -fno-ptrauth-calls would also strip the auth property from the FIXUPS
// (defeating the fixture). The two functions that call through those slots
// therefore issue an explicit `blr` via inline asm — deterministic, and a
// faithful stand-in for foreign/interposed call paths. The arm64e ABI's
// pac-ret prologue pair (pacibsp/retab) cannot be disabled — clang forces
// it — and needs no policy: it is the CPU's own LR signing and round-trips
// inside the CPU backend (verified against unicorn's pauth-capable ARM64
// model).

long add(long a, long b) { return a + b; }

// Imported host function — golem interposes it (HostResolver materializes a
// guest stub; the AUTH bind chain entry on host_fp is decoded and stripped
// to the stub's bare guest address).
extern long host_magic(long x);

// Imported host DATA symbol — exported by hostdata_darwin_arm64.dylib in
// the e2e, producing a NON-auth bind chain entry (data pointers are not
// signed).
extern long host_value;

long (*host_fp)(long) = host_magic;
long *host_val_ptr = &host_value;

// Calls through loader-materialized pointers must NOT authenticate (see the
// file header): load the slot, move it to x8, and `blr x8` in explicit asm
// so clang cannot emit blraaz. The clobber list is the full caller-saved
// set — the call target is opaque to the compiler.
long call_host(long x) {
    register long x0 __asm__("x0") = x;
    register long x8 __asm__("x8") = (long)host_fp;
    __asm__ volatile("blr x8"
                     : "+r"(x0)
                     : "r"(x8)
                     : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                       "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                       "x16", "x17", "x30");
    return x0 + 1;
}
long read_host_value(void) { return *host_val_ptr; }

// Internal-pointer rebase targets: a function pointer (AUTH rebase — code
// pointers in __data are signed on arm64e) and a data pointer (non-auth
// rebase).
static long seven(void) { return 7; }
static long local_val = 55;
long (*fptr_table[2])(void) = { seven, 0 };
long *local_ptr = &local_val;

long via_fptr_table(void) {
    register long x0 __asm__("x0");
    register long x8 __asm__("x8") = (long)fptr_table[0];
    __asm__ volatile("blr x8"
                     : "=r"(x0)
                     : "r"(x8)
                     : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                       "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                       "x16", "x17", "x30");
    return x0 + add(1, 2);
}
long read_local(void) { return *local_ptr; }

// A REAL Darwin syscall: unix syscall 20 (getpid), number in x16, svc #0x80.
// On success the kernel clears carry and returns the value in x0 — the exact
// inverse of the Linux/x8/-errno convention the Android personality uses.
long guest_getpid(void) {
    register long x16 __asm__("x16") = 20; // Darwin arm64 SYS_getpid
    long ret;
    __asm__ volatile("svc #0x80" : "=r"(ret) : "r"(x16) : "memory");
    return ret;
}

// An UNIMPLEMENTED Darwin syscall: number 0x7fff, table miss → ENOSYS. The
// Darwin encoding carries failure as carry-set + errno in x0 (positive); the
// guest observes both and packs them for the test: (carry << 32) | errno.
// NOTE: the condition is hs (C set) — "lo" would be C CLEAR (the inverse).
long guest_bogus_syscall(void) {
    register long x16 __asm__("x16") = 0x7fff;
    long ret, carry;
    __asm__ volatile("svc #0x80\n\tcset %w1, hs"
                     : "=r"(ret), "=r"(carry)
                     : "r"(x16)
                     : "memory");
    return (carry << 32) | (ret & 0xffffffff);
}
