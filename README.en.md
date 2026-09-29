[简体中文](README.md) | **English**

# golem

[![Release](https://img.shields.io/github/v/release/isesword/golem)](https://github.com/isesword/golem/releases/latest)
[![CI](https://github.com/isesword/golem/actions/workflows/ci.yml/badge.svg)](https://github.com/isesword/golem/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

golem is a multi-platform native-library emulation framework written in pure Go: it loads an Android AArch64 native library (`.so`) on your host machine and lets you call functions inside it without a JVM, a device, or Android. It builds a sufficient Android process environment around the `.so` — a dynamic linker, real bionic libc, a subset of Linux syscalls, and a JavaVM whose reference lifecycle follows the JNI specification — so you can call the library's exports, read and write its memory, and trace every instruction from Go.

The CPU engine sits behind an interface; the built-in [Unicorn](https://www.unicorn-engine.org/) backend loads the stock libunicorn at **runtime** via [purego](https://github.com/ebitengine/purego) — **zero cgo at build time** (`CGO_ENABLED=0`, no C compiler, no hand-written shim).

```go
e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so"})
defer e.Close()
sum, _ := e.CallSymbol("add", 2, 3) // -> 5, executed as real AArch64 code
```

> Current status: the Unicorn (purego) backend works end to end — loading and linking bionic and the target `.so`, running `init_array` and `JNI_OnLoad`, calling exports, handling syscalls and JNI — plus an engine pool for concurrent use. Under sustained load (real request signing), 100k signs at 100 QPS held constant latency with zero memory growth. CI-verified for real on Linux / macOS / Windows (amd64 and arm64) — on Windows the VEH-off unicorn.dll is built by CI and verified on real runners: release builds ship from [Releases](https://github.com/isesword/golem/releases/latest), with an out-of-the-box copy kept under `assets/windows/<arch>/`. See [Relationship to unidbg](#relationship-to-unidbg).

---

## Why the name

In legend, a golem is a clay figure without life of its own — inscribed with a word, it stands up and works. Its life comes from being animated, not from birth. That is exactly what this framework does: a static `.so` has no life; golem breathes one into it — a dynamic linker, libc, syscalls, and JNI — so it runs on a machine with no device and no Android. The name is borrowed for that one idea: waking the creation.

## Why

unidbg is the de-facto tool for emulating Android native libraries, but it runs on a JVM, pulls in a fairly large stack, and never reclaims JNI references (`DeleteLocalRef` is a no-op) — built for interactive analysis, not resident services. golem does the core of the same job in Go and treats **production-grade long-running use as a first-class citizen**:

- No JVM, and no C toolchain either. The build output is a single Go binary (`CGO_ENABLED=0`); cross-compiling is just `go build`.
- Swappable engine. The engine hides behind the `emu.Backend` interface; Unicorn (purego, runtime-loaded) is the built-in default.
- Reuses real bionic. It loads and emulates `libc/libm/libdl` from an AOSP sysroot instead of reimplementing libc.
- Built for resident services: JNI references reclaimed per the spec (local refs die with their call frames), compile/instantiate separation shares read-only pages across an engine pool, and the pool auto-recycles engines and rebuilds after panics.
- Honest failure semantics: memory/hook operations return errors or roll back transactionally; unrecoverable state transitions poison the emulator — later calls are rejected instead of pretending to be healthy.

## Features

- AArch64 ELF loading + dynamic linking (`RELATIVE` / `JUMP_SLOT` / `GLOB_DAT` / `ABS64`), `DT_INIT` + `init_array`.
- Real bionic `libc/libm/libdl` reuse (bundled AOSP sdk23 sysroot); cross-module symbol resolution.
- Linux/AArch64 syscall subset (mmap/mprotect/openat/read/write/clock_gettime/getrandom/futex/…), served against a small virtual filesystem (`/system/lib64`, `/proc/self/*`, properties, tzdata).
- JNI/JavaVM: a guest `JNIEnv`/`JavaVM` whose calls trap back to a Go handler you implement (`FindClass`, `GetMethodID`, `Call*Method*`, `RegisterNatives`, strings, byte arrays, …).
- Call native functions by symbol or by module offset, pass up to 8 integer args, and read the return value.
- Replace a native function with a Go callback (`ReplaceE`, transactional entry patch that restores the original instructions on failure), or **inline hook** (`HookAddr`, per-instruction, Unicorn) to rewrite registers / redirect PC; memory-writing paths flush the code cache automatically.
- **Console debugger**: breakpoints / single-step / registers / memory (Unicorn; I/O is injectable for scripting).
- Load **real class/method/field metadata from a classes.dex** (`Config.Android.DexPath` / `LoadDex`): FindClass/GetMethodID/GetFieldID resolve against true signatures and superclasses (metadata only, no bytecode).
- Memory helpers: alloc, read/write bytes, C-strings, and LE integers.
- Per-instruction trace, plus a full instruction-stream trace (`TraceInsns`: per-instruction offset + opcode + register deltas + call/syscall annotations, Tenet-style, diffable against a real-device trace; Unicorn).
- Selectable engine: build with `-tags unicorn` to compile in the purego backend, choose at runtime with `-engine` / `$GOLEM_ENGINE`.
- Tunable TCG translation buffer: `Config.TCGBufferMiB` (applied at construction; the 8 MiB default under Windows preallocation was set by measurement with `cmd/tcgsizing`).
- **JNI reference lifecycle per spec**: local refs live in pooled call frames (die with the call; one-beat grace for return-value reads), global refs are explicit with stable handle values, handles are monotonic and never reused (stale handles resolve to nil, never alias). Steady-state memory is O(one call's objects) — flat under sustained load.
- **Engine pool (`emulator.Pool`)**: the actor pattern — one engine belongs to one goroutine at a time; concurrency scales by engine count, not locks. Auto-recycling at MaxUses, transparent rebuild after worker panics, ctx deadlines when drained. This is the core of golem's concurrency story: **intra-guest threads** are the engine's cooperative scheduler, while **N concurrent goroutines** get N engines running truly in parallel (~70 QPS per core measured).
- **Compile/instantiate split**: each `.so` is parsed once (`loader.CompileOnce`) and its read-only segments are shared zero-copy across engines via `uc_mem_map_ptr` — one physical copy no matter the pool size (measured -20% maxRSS at 10 engines). Host patches privatize pages first and never corrupt other engines.
- **Honest failure semantics**: allocations return errors (failed backend maps roll back the address-space bookkeeping), `ReplaceE` is a five-step transaction (restores original instructions on failure), and unverifiable state transitions POISON the emulator — later calls are rejected instead of pretending to be healthy.

## Quick start

### Prerequisites

- Go 1.26+
- One CPU engine: Unicorn (the default). Building needs **no C compiler at all**; at runtime libunicorn is looked up in this order:
  1. `$GOLEM_UNICORN` — an explicit path, **highest priority on every platform**. To swap in your own engine build (e.g. a self-built VEH-off `unicorn.dll`), point it there — **no need to rebuild golem**;
  2. the platform loader's search path — macOS/Linux system installs (`brew install unicorn` / `apt install libunicorn2`);
  3. the bundled Windows copy — `assets/windows/<arch>/unicorn.dll` (CI-built VEH-off, works out of the box; release builds are also downloadable from [Releases](https://github.com/isesword/golem/releases/latest)).

  See [BUILD.md](BUILD.md).

### Build & run the example

```bash
# Linux / macOS / Windows (pure-Go build: no cgo, no zig)
CGO_ENABLED=0 go build -tags unicorn -o bin/golem ./cmd/golem
GOLEM_UNICORN=$(brew --prefix unicorn)/lib/libunicorn.dylib \
  ./bin/golem examples/native/native.so fib 20                # fib([20]) = 6765
# Windows: nothing to install — assets/windows/<arch>/unicorn.dll (VEH-off build) is used automatically;
#          to use your own DLL (PowerShell): $env:GOLEM_UNICORN = "C:\path\to\unicorn.dll"
```

Full demo (loads the bundled `native.so`, calls exports, an imported `strlen`, a pointer-out function, and a Go `Replace` hook):

```bash
CGO_ENABLED=0 go run -tags unicorn ./examples/run   # libunicorn must be findable at runtime (see BUILD.md)
# engine: unicorn
# add(2, 3)      = 5
# fib(20)        = 6765
# slen(...)      = 14
# sum_into -> *out = 42
# add(2, 3) after Replace = 23  (Go hook: a*10+b)
```

## Library usage

```go
import "github.com/isesword/golem/emulator"

e, err := emulator.New(emulator.Config{
    SOPath:    "libfoo.so",        // loaded + init_array + JNI_OnLoad at boot
    AssetRoot: emulator.Locate("assets"),
    Engine:    "",                 // "unicorn" | "" = auto
})
if err != nil { panic(err) }
defer e.Close()

// Call an export by name (up to 8 integer/pointer args, returns X0).
r, _ := e.CallSymbol("add", 2, 3)

// Call a non-exported entry by module offset (unidbg's callFunction(offset)).
r, _ = e.CallOffset(nil /*main module*/, 0x1234, argPtr)

// Exchange memory.
p := e.WriteCStringAlloc("hello")
n, _ := e.CallSymbol("strlen_wrapper", p)
out := e.Malloc(4); _, _ = e.CallSymbol("sum_into", out, 20, 22)
v, _ := e.ReadU32(out)

// Replace a native function with Go (hook).
e.ReplaceSymbol("add", func(h *emulator.Hook) uint64 { return h.Arg(0) + h.Arg(1) })
```

### Modeling the Java side (JNI)

Native libraries call back into Java via JNI. Implement `dvm.Jni` (or embed `dvm.AbstractJni` and override the few methods your library uses), then pass it in `Config.Android.JNI`:

```go
type MyJni struct{ dvm.AbstractJni }

func (MyJni) CallStaticObjectMethodV(vm *dvm.VM, cls *dvm.Class, sig string, va *dvm.VaList) *dvm.Object {
    if sig == "com/example/App->token()Ljava/lang/String;" {
        return &dvm.Object{Class: vm.ResolveClass("java/lang/String"), Value: "secret"}
    }
    return nil
}

e, _ := emulator.New(emulator.Config{SOPath: "libfoo.so", Android: emulator.AndroidConfig{JNI: MyJni{}}})
```

This is how unidbg's `AbstractJni` works: the guest's `RegisterNatives`/`GetMethodID`/`Call*Method` route to your switch on the `"class->method(sig)"` string.

## CPU engines

| engine | build tag | linkage | speed (warm) | license |
|---|---|---|---|---|
| **Unicorn2** | `-tags unicorn` | purego runtime `dlopen` of libunicorn | p50 ≈ 14–15 ms/call (measured, 100k signs @100 QPS) | GPLv2 |

- The Unicorn backend ships built-in; the interface (`emu.Backend`) and registry keep the extension point for other engines.
- The first call on a fresh emulator takes a few hundred ms (warm-up); after that, reuse the emulator and the calls are fast.
- Licensing note: Unicorn is GPLv2, and statically linking it would make the combined binary GPLv2, so golem keeps it behind a runtime `dlopen` boundary — the purego backend preserves that design.

## How it works

`emulator.New` mirrors unidbg's `Emulator` setup:

1. Address space: reserve the guest stack, TLS (`TPIDR_EL0` plus a `pthread_internal_t`), and an SVC-trampoline region, then pick the CPU backend.
2. Load and link: each `.so` is parsed once into a Plan (`loader.CompileOnce`) and instantiated per engine — read-only segments are shared zero-copy via `uc_mem_map_ptr`, writable segments stay private anonymous memory, relocations resolve per-engine symbols; unresolved imports point at `svc` trampolines that trap back into Go.
3. Initialize: run `DT_INIT` and `init_array`, plus `JNI_OnLoad` (if the library exports it) with a synthesized `JavaVM`.
4. Call: `CallSymbol`/`CallOffset` put the args in `X0..X7`, set `LR` to a sentinel, and run until return. An SVC trap is dispatched to the syscall layer (`internal/kernel`), the JNI layer, or a Go-implemented libc or replaced function.

Guest memory and registers are exchanged through the `Backend` interface, implemented by the Unicorn purego backend (the runtime-`dlopen`'d libunicorn reads and writes guest memory mapped on the host side).

### Layout

```
golem/
├── emulator/     public API: New, LoadLibrary, CallSymbol/CallOffset, ReplaceE, memory helpers
├── dvm/          public: fake Dalvik VM — VM, Object, Class, Jni, AbstractJni, VaList
├── internal/
│   ├── emu/      CPU backend interface + registry; unicorn backend (purego runtime-loaded libunicorn)
│   ├── loader/   ELF parsing + dynamic linker
│   ├── kernel/   AArch64 Linux syscall subset
│   ├── memory/   guest address-space allocator
│   └── vfs/      guest virtual filesystem (/system/lib64, /proc/self, properties, tzdata)
├── cmd/
│   ├── golem/  CLI: load a .so and call a symbol
│   ├── elfscan/  analyze a .so (imports/exports/init)
│   ├── loadplan/ relocation histogram / link complexity
│   ├── bsmoke/   engine self-test
│   └── tcgsizing/ TCG buffer sizing curves (throughput/latency/RSS)
├── examples/native/  a tiny AArch64 .so (source + prebuilt) used by the example + test
└── assets/android/sdk23/  bundled AOSP bionic sysroot (see NOTICE)
```

## Relationship to unidbg

golem's spiritual predecessor is [unidbg](https://github.com/zhkl0228/unidbg) — the load/link/bionic-reuse/JNI-trap skeleton carries the same DNA, with thanks. The substantive differences:

**Where golem differs:**

- **Pure Go, zero cgo**: no C toolchain needed to build; unidbg needs a JVM + Maven.
- **JNI references reclaimed per spec**: unidbg's `DeleteLocalRef` is a no-op and its local table only grows — unbounded under resident load; golem reclaims per call frame, steady-state O(1).
- **Error returns + transactional rollback + poison**: allocation and patch failures have explicit recoverable/unrecoverable semantics; the unidbg style is exceptions and swallowed errors.
- **Shared read-only pages**: `CompileOnce` + `uc_mem_map_ptr` keep read-only segments at one physical copy across an engine pool.

**What golem doesn't have yet (unidbg does):**

- ARM32 / x86 (AArch64 only today); iOS / Mach-O is on the roadmap.
- The full syscall table and all ~232 JNI slots (common usage is covered; unimplemented syscalls return ENOSYS).
- DEX bytecode execution (metadata only: class/method/field signatures for resolution; model Java behavior with `dvm.Jni`).

**Concurrency model (stated for both, to avoid misreading):**

- golem and unidbg both schedule guest threads **cooperatively**: `pthread_create` threads run as fibers (private stack, time-sliced by syscall count, CPU context saved/restored at futex/sleep) — functionally equivalent, and neither gives multi-core parallelism inside one engine (a single CPU backend is inherently serial).
- golem's **throughput concurrency** lives at the engine level: `emulator.Pool` lets N goroutines drive N independent engines truly in parallel (~70 QPS per core; measured ~510 QPS on 12 cores) — the right shape for concurrent requests, and a structural advantage over unidbg.

## Building from source / engines

See [BUILD.md](BUILD.md) for building the pure-Go and engine layers, cross-compiling, and locating libunicorn at runtime.

```bash
# pure-Go layer builds and tests anywhere (no engine):
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...

# engine integration test (loads the bundled native.so and runs it):
go test -tags unicorn  ./emulator
CGO_ENABLED=0 go test -tags unicorn ./emulator
```

## Credits & license

golem builds on:

- [unidbg](https://github.com/zhkl0228/unidbg) (Apache-2.0): the spiritual predecessor — the source of the domain model and the JNI-trap design.
- [gonidbg](https://github.com/sisi0318/gonidbg) (Apache-2.0): the direct starting point — the Go implementation of the loader, bionic reuse, cooperative scheduler, and JNI trap that golem evolved from, adding the purego engine binding, JNI reference lifecycle, engine pool, and shared read-only pages.
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn) (GPLv2): the default CPU backend, loaded at runtime.
- AOSP bionic (Apache-2.0) and others: the bundled sysroot under `assets/`. See [NOTICE](NOTICE).

golem's own code is licensed under Apache-2.0 (see [LICENSE](LICENSE)). Engine licensing as noted above: the Unicorn backend is loaded dynamically to keep its GPLv2 at a library boundary.

## Disclaimer

golem is a research and education tool for analyzing native libraries you are authorized to study. The repo contains no third-party application code or proprietary binaries, only a generic emulation framework and a tiny example library built from the source in this repo. Use it responsibly and in compliance with applicable law and the terms of any software you analyze.
