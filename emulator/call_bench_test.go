package emulator

// P9.5a-0 call-path benchmark set: separates fixed framework overhead from
// argument-count scaling and guest-execution share. Permanent regression
// harness — run with -count>=6 and compare medians.
import "testing"

func newBootedForBench(b *testing.B) *Emulator {
	b.Helper()
	e, err := New(Config{
		SOPath:    "../examples/native/native.so",
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	})
	if err != nil {
		b.Skipf("boot: %v", err)
	}
	b.Cleanup(func() { e.Close() })
	return e
}

// BenchmarkCallAdd2: the fixed-overhead probe (2 word args, trivial guest).
func BenchmarkCallAdd2(b *testing.B) {
	e := newBootedForBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallSymbol("add", Words(2, 3)...); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallFib20: same path with a slightly longer guest block. NOTE:
// the fixture fib is a LOOP (~60 insns), not recursion — the heavy-guest
// dimension is covered by the real-library sqlite driver, not here. Previous line was:

func BenchmarkCallFib20(b *testing.B) {
	e := newBootedForBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallSymbol("fib", Words(20)...); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallSlenPtr: pointer argument through guest memory (C string).
func BenchmarkCallSlenPtr(b *testing.B) {
	e := newBootedForBench(b)
	p := e.WriteCStringAlloc("hello")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallSymbol("slen", Ptr(p)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallSumInto3: three args incl. an out-pointer write into guest
// memory from the host side.
func BenchmarkCallSumInto3(b *testing.B) {
	e := newBootedForBench(b)
	out, err := e.Malloc(8)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallSymbol("sum_into", Words(out, 20, 22)...); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallFuncAdd2: the Advanced word path (the A/B baseline against
// the main branch's 1188 ns / 552 B / 22 allocs measurement).
func BenchmarkCallFuncAdd2(b *testing.B) {
	e := newBootedForBench(b)
	addr, ok := e.Sym("add")
	if !ok {
		b.Fatal("no add")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallFunc(addr, 2, 3); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCallUnameLen0: a zero-argument call whose guest body performs
// real VFS I/O (readlink/read through the virtual filesystem) — measures
// the syscall-IO-heavy shape, NOT a pure framework floor (the framework
// floor is BenchmarkCallAdd2 minus its two words).
func BenchmarkCallUnameLen0(b *testing.B) {
	e := newBootedForBench(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.CallSymbol("uname_machine_len"); err != nil {
			b.Fatal(err)
		}
	}
}
