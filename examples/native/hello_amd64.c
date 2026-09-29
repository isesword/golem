// Tiny x86-64 (AMD64) shared library — the P5a touchstone fixture for
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
