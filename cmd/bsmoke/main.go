//go:build unicorn

// bsmoke: exercises the real emu.Backend end-to-end on whichever engine is
// compiled in (unicorn; pick with -engine / $GOLEM_ENGINE).
// Guest program: `svc #0 ; add x0,x0,#1`. The interrupt hook (a Go callback)
// does the thing that crashed naive attempts on Windows: maps a FRESH guest
// region and reads/writes it. If x0==16 and the readback is 0xdeadbeef, guest
// execution works including callback-time allocation.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/isesword/golem/internal/arch/arm64"
	"github.com/isesword/golem/internal/emu"
)

func must(err error, what string) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func main() {
	engine := flag.String("engine", "", "CPU engine: unicorn (default: auto / $GOLEM_ENGINE)")
	flag.Parse()
	fmt.Printf("engines compiled in: %s\n", strings.Join(emu.Available(), ", "))

	be, err := emu.NewNamed(*engine, emu.ArchARM64)
	must(err, "emu.NewNamed")
	defer be.Close()
	if eng, e := emu.Resolve(*engine); e == nil {
		fmt.Printf("engine: %s\n", eng)
	}

	const base = 0x1000
	must(be.MemMap(base, 0x1000, emu.ProtAll), "map code")

	// svc #0 (0xD4000001) ; add x0,x0,#1 (0x91000400)
	code := []byte{0x01, 0x00, 0x00, 0xd4, 0x00, 0x04, 0x00, 0x91}
	must(be.MemWrite(base, code), "write code")
	must(be.RegWrite(arm64.X0, 10), "set x0")

	hookRan := false
	ih, ok := be.(emu.InterruptHooker) // capability probe (P2.5a)
	if !ok {
		fmt.Println("FAIL engine lacks the InterruptHooker capability")
		os.Exit(1)
	}
	_, err = ih.HookInterrupt(func(b emu.Backend, intno uint32) {
		hookRan = true
		// callback-time fresh mapping — the scenario that faults on an
		// M-attached thread if the design were wrong.
		if e := b.MemMap(0x40000000, 0x1000, emu.ProtAll); e != nil {
			fmt.Println("  hook MemMap err:", e)
			return
		}
		if e := b.MemWrite(0x40000000, []byte{0xde, 0xad, 0xbe, 0xef}); e != nil {
			fmt.Println("  hook MemWrite err:", e)
			return
		}
		x0, _ := b.RegRead(arm64.X0)
		b.RegWrite(arm64.X0, x0+5)
	})
	must(err, "hook intr")

	must(be.Start(base, base+8), "emu_start")

	x0, _ := be.RegRead(arm64.X0)
	back, _ := be.MemRead(0x40000000, 4)
	fmt.Printf("hookRan=%v  x0=%d (expect 16)  mmap_readback=%x (expect deadbeef)\n",
		hookRan, x0, back)
	if x0 == 16 && len(back) == 4 && binary.BigEndian.Uint32(back) == 0xdeadbeef {
		fmt.Println("BACKEND OK — engine runs guest code, SVC callback, and callback-time mmap")
		return
	}
	os.Exit(2)
}
