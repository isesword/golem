// Tiny Darwin/ARM64 (Mach-O arm64) shared library — the P5b touchstone
// fixture for golem's arch x platform x format matrix. Same ARM64 CPU as the
// Android targets; everything else differs: Mach-O format (rebase/bind
// opcodes instead of RELA), Darwin platform (x16 + svc #0x80 syscall
// transport, carry/errno result encoding, no auxv), no libc dependency except
// the single explicit import below (host_magic), which the tests interpose at
// link time (HostResolver stub) — exercising the bind-opcode channel.
//
// Build (committed prebuilt is hello_darwin_arm64.dylib; rebuild on macOS
// with build_darwin_fixture.sh, or manually):
//   clang -arch arm64 -target arm64-apple-macos11 -dynamiclib \
//         -fno-builtin -fno-stack-protector -O2 \
//         -Wl,-no_fixup_chains -nostdlib \
//         -o hello_darwin_arm64.dylib hello_darwin_arm64.c
// (-no_fixup_chains keeps classic LC_DYLD_INFO rebase/bind opcodes; chained
// fixups are the ARM64e/PAC world, deliberately out of P5b scope.)

long add(long a, long b) { return a + b; }

// Imported host function — golem interposes it (HostResolver materializes a
// guest stub; the call below reads the bound pointer from __DATA, which the
// loader's bind-opcode relocation fills through the SymbolResolver).
extern long host_magic(long x);

// A global function pointer initialized to the imported symbol: this is what
// forces a NON-lazy BIND_TYPE_POINTER opcode (a direct call would produce a
// lazy stub needing dyld's stub binder, which golem does not emulate).
long (*host_fp)(long) = host_magic;

long call_host(long x) { return host_fp(x) + 1; }

// Internal-pointer rebase target: a static initializer pointing at a local
// function produces a REBASE_TYPE_POINTER opcode in __DATA.
static long seven(void) { return 7; }
long (*fptr_table[2])(void) = { seven, 0 };

// Calls fptr_table[0] (seven) then add(1,2): 7 + 3 = 10 — proves the rebased
// pointer is callable from guest code.
long via_fptr_table(void) { return fptr_table[0]() + add(1, 2); }

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
long guest_bogus_syscall(void) {
    register long x16 __asm__("x16") = 0x7fff;
    long ret, carry;
    __asm__ volatile("svc #0x80\n\tcset %w1, lo"
                     : "=r"(ret), "=r"(carry)
                     : "r"(x16)
                     : "memory");
    return (carry << 32) | (ret & 0xffffffff);
}
