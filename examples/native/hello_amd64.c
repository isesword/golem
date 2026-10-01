// Tiny x86-64 (AMD64) shared library — the touchstone fixture for
// golem's Android/AMD64 arch x platform x format assembly. No libc
// dependency except the single explicit import below (host_magic), which the
// tests interpose at link time (HostResolver stub) — exercising GOT
// relocation + the int3 host-stub trap channel.
//
// Build (committed prebuilt is hello_amd64.so; rebuild with):
//   zig cc -target x86_64-linux-gnu -shared -fPIC -nostdlib \
//          -fno-builtin -fno-stack-protector -O2 -o hello_amd64.so hello_amd64.c

int add(int a, int b) { return a + b; }

// Six-argument SysV probe: a+b+c+d+e+f arrives in RDI/RSI/RDX/RCX/R8/R9.
long sum6(long a, long b, long c, long d, long e, long f) {
    return a + b + c + d + e + f;
}

// Function-pointer table: the local `seven` entry relocates with
// R_X86_64_RELATIVE; the exported `add` entry relocates with R_X86_64_64
// (preemptible symbol, explicit RELA addend).
static int seven(void) { return 7; }
void *fptr_table[2] = { (void *)seven, (void *)add };

// Calls through fptr_table[0] (seven) then fptr_table[1] (add(1,2)):
// 7 + 3 = 10. Exercises both relocated entries from guest code.
int via_fptr_table(void) {
    int (*f0)(void) = (int (*)(void))fptr_table[0];
    int (*f1)(int, int) = (int (*)(int, int))fptr_table[1];
    return f0() + f1(1, 2);
}

// Imported host function — golem interposes it (HostResolver materializes an
// int3 guest stub; the call below goes through the GOT).
extern unsigned long host_magic(unsigned long x);

unsigned long call_host(unsigned long x) { return host_magic(x) + 1; }

// Two sequential interposed calls in one guest frame: stack discipline across
// repeated host interposition (each must pop exactly its own return address).
unsigned long call_host_twice(unsigned long x) {
    return host_magic(x) + host_magic(x + 1);
}

// A REAL guest syscall instruction (Linux x86-64: getpid = 39) — routes
// through the engine's UC_HOOK_INSN channel, strictly separate from the int3
// host-stub channel.
long guest_getpid(void) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(39L)
                     : "rcx", "r11", "memory");
    return ret;
}

// Eight-argument SysV stack-spill probe a..f arrive in
// RDI/RSI/RDX/RCX/R8/R9, g/h on the stack at [entry RSP+8] / [entry RSP+16]
// above the pushed return address. Naked on purpose: the asm observes the
// EXACT entry state — no prologue may move RSP first — and records it in
// static globals (static = non-preemptible, so the RIP-relative stores need
// no dynamic relocation; `used` forces emission — the inline-asm writes are
// invisible to the optimizer, which would otherwise dead-strip them); the
// exported accessors below report the recorded state to the test.
static unsigned long seen_rsp __attribute__((used));   // entry RSP (want ≡ 8 mod 16)
static unsigned long seen_ret __attribute__((used));   // [entry RSP] — the pushed return address
static unsigned long seen_align __attribute__((used)); // entry RSP & 15 (want 8)

__attribute__((naked))
long sum8(long a, long b, long c, long d, long e, long f, long g, long h) {
    __asm__ volatile(
        "mov %rsp, seen_rsp(%rip)\n\t"
        "mov %rsp, %rax\n\t"
        "and $15, %rax\n\t"
        "mov %rax, seen_align(%rip)\n\t"
        "mov (%rsp), %rax\n\t"
        "mov %rax, seen_ret(%rip)\n\t"
        // Sum the eight args: six registers + two stack slots.
        "mov %rdi, %rax\n\t"
        "add %rsi, %rax\n\t"
        "add %rdx, %rax\n\t"
        "add %rcx, %rax\n\t"
        "add %r8, %rax\n\t"
        "add %r9, %rax\n\t"
        "add 8(%rsp), %rax\n\t"
        "add 16(%rsp), %rax\n\t"
        "ret\n\t");
}

// Accessors for sum8's recorded entry state (the globals are static — see
// above — so the test reads them through these exported calls).
unsigned long sum8_observed_rsp(void)   { return seen_rsp; }
unsigned long sum8_observed_ret(void)   { return seen_ret; }
unsigned long sum8_observed_align(void) { return seen_align; }
