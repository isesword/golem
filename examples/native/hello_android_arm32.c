// Tiny Android/ARM32 (ELF32, EM_ARM, armv7 EABI) shared library — the P6e
// touchstone fixture for golem's arch x platform x format matrix: the THIRD
// architecture, exercising everything that is genuinely different at 32
// bits — the AAPCS32 register-pair argument rules, Thumb interworking, REL
// relocations with implicit addends, and the r7/svc Linux syscall ABI.
// No libc (-nostdlib); the single import below is interposed by the tests
// through golem's HostResolver.
//
// Build (committed prebuilt is hello_android_arm32.so; rebuild with
// build_android_arm32_fixture.sh, or manually):
//   zig cc -target arm-linux-gnueabihf -march=armv7-a -shared -nostdlib \
//          -fno-builtin -fno-stack-protector -O2 \
//          -o hello_android_arm32.so hello_android_arm32.c

long add(long a, long b) { return a + b; }

// AAPCS32 register-pair probe (P6 Architecture Exception #1 made this
// expressible): the signature (u32, u64) forces a into r0 and b into the
// r2:r3 pair with r1 SKIPPED — a loader/emulator that places b in r1:r2
// (the naive []uint64 layout) gets a visibly wrong result. Uses both
// halves of b so a split placement cannot accidentally pass.
unsigned add64lohi(unsigned a, unsigned long long b) {
    return a + (unsigned)b + (unsigned)(b >> 32);
}

// Imported host function — golem interposes it (HostResolver materializes a
// guest stub; the call below reads the bound pointer from .data, which the
// loader's R_ARM_ABS32 bind fills through the SymbolResolver).
extern long host_magic(long x);

// A global function pointer initialized to the imported symbol: forces a
// NON-lazy bind relocation (a direct call would produce a lazy PLT stub
// needing dyld/bionic's lazy binder, which golem does not emulate).
long (*host_fp)(long) = host_magic;

long call_host(long x) { return host_fp(x) + 1; }

// Internal-pointer rebase target: a static initializer pointing at a local
// function produces an R_ARM_RELATIVE relocation in .data.
static long seven(void) { return 7; }
long (*fptr_table[2])(void) = { seven, 0 };

// Calls fptr_table[0] (seven) then add(1,2): 7 + 3 = 10 — proves the rebased
// pointer is callable from guest code.
long via_fptr_table(void) { return fptr_table[0]() + add(1, 2); }

// A THUMB function: the compiler sets bit0 of its st_value, and the whole
// interworking chain is exercised — the loader preserves the odd export
// value, CallFunc's PrepareCall interprets bit0 via setPCBX (CPSR.T), and
// the unicorn backend enters Thumb state. Returns 2*a + b so an accidental
// ARM-state decode cannot produce the right answer by luck.
__attribute__((target("thumb"))) long thumb_add(long a, long b) { return a + a + b; }

// A REAL Linux syscall: getpid, number 20 in r7, svc #0 — the ARM32 EABI
// syscall convention (unlike ARM64's x8 and Darwin's x16).
long guest_getpid(void) {
    register long r7 __asm__("r7") = 20; // Linux arm __NR_getpid
    long ret;
    __asm__ volatile("svc #0" : "=r"(ret) : "r"(r7) : "memory");
    return ret;
}

// --- P10 wrap binding probes -------------------------------------------------
// Address-taken `add` forces an R_ARM_ABS32 data reloc naming a DEFINED,
// preemptible symbol — exactly the resolvable binding WrapSymbol redirects.
// (host_magic has no definition in any module, so it is NOT wrappable: the
// Sym lookup fails before any binding scan.)

long nest(long x) {
    long (*volatile p)(long, long) = add;
    return p(x, 4) + 1000;
}

// Same recursion-through-the-binding probe as the ARM64 fixture: each level
// re-enters the wrap entry stub. fact(5) plain = 120.
long fact(long n) {
    if (n <= 1) return 1;
    long (*volatile p)(long) = fact;
    return n * p(n - 1);
}
