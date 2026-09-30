//go:build unicorn

// Example: load the bundled native.so and call its exported functions through
// golem. Build with an engine and run from the repo root:
//
//	go run -tags unicorn  ./examples/run
//	go run -tags unicorn ./examples/run
//
// (set the engine env/flags from BUILD.md). Pass a different .so as arg 1.
package main

import (
	"fmt"
	"os"

	"github.com/isesword/golem/emulator"
)

func main() {
	so := "examples/native/native.so"
	if len(os.Args) > 1 {
		so = os.Args[1]
	}

	e, err := emulator.New(emulator.Config{
		SOPath:    so,
		AssetRoot: emulator.Locate("assets"),
	})
	if err != nil {
		fmt.Println("boot:", err)
		os.Exit(1)
	}
	defer e.Close()
	fmt.Printf("engine: %s\n", e.Engine())

	// add(2, 3)
	add, _ := e.CallSymbol("add", emulator.Words(2, 3)...)
	fmt.Printf("add(2, 3)      = %d\n", int32(add))

	// fib(20)
	fib, _ := e.CallSymbol("fib", emulator.Words(20)...)
	fmt.Printf("fib(20)        = %d\n", fib)

	// slen("hello, golem") — exercises an import (bionic strlen) from guest code
	p := e.WriteCStringAlloc("hello, golem")
	slen, _ := e.CallSymbol("slen", emulator.Words(p)...)
	fmt.Printf("slen(...)      = %d\n", int32(slen))

	// sum_into(&out, 20, 22) — guest writes through a pointer we then read back
	out, err2 := e.Malloc(4)
	if err2 != nil {
		panic(err2)
	}
	_, _ = e.CallSymbol("sum_into", emulator.Words(out, 20, 22)...)
	v, _ := e.ReadU32(out)
	fmt.Printf("sum_into -> *out = %d\n", v)

	// Replace: swap the native add with a Go implementation (unidbg-style hook)
	_ = e.ReplaceSymbol("add", func(h *emulator.Hook) uint64 {
		a, _ := h.Arg(0)
		b, _ := h.Arg(1)
		return a.Raw*10 + b.Raw // a+b becomes a*10+b
	})
	add2, _ := e.CallSymbol("add", emulator.Words(2, 3)...)
	fmt.Printf("add(2, 3) after Replace = %d  (Go hook: a*10+b)\n", int32(add2))
}
