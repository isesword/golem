//go:build unicorn

// tcgsizing — TCG buffer sizing probe: for each candidate TCG buffer size,
// boots a pool of engines (each pinned to that size via UC_CTL_TCG_BUFFER_SIZE)
// and runs a call workload, reporting throughput, per-call latency, peak RSS,
// and failures. Output is a table meant to pick the smallest size with no
// throughput loss (QPS/p99 plateau).
//
// Usage (from the module root):
//
//	go run -tags unicorn ./cmd/tcgsizing -so examples/native/native.so \
//	  -assets assets -pool 4 -iters 2000
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/isesword/golem/emulator"
	"github.com/isesword/golem/internal/emu"
)

func main() {
	so := flag.String("so", "examples/native/native.so", "guest .so to load per engine")
	assets := flag.String("assets", "assets", "bionic asset root")
	poolSize := flag.Int("pool", 4, "engines in the pool")
	iters := flag.Int("iters", 2000, "calls per engine during the workload")
	sizes := flag.String("sizes", "4,8,16,32,64,256,1024", "TCG buffer sizes in MiB, comma-separated")
	heavy := flag.Bool("heavy", false, "workload = fib(20) deep recursion instead of add (larger code footprint)")
	flag.Parse()

	var miBs []uint64
	for _, f := range strings.Split(*sizes, ",") {
		var v int
		if _, err := fmt.Sscanf(strings.TrimSpace(f), "%d", &v); err != nil || v <= 0 {
			fmt.Fprintf(os.Stderr, "bad size %q\n", f)
			os.Exit(1)
		}
		miBs = append(miBs, uint64(v))
	}

	wl := "native add via CallSymbol"
	if *heavy {
		wl = "fib(20) deep recursion"
	}
	fmt.Printf("tcgsizing: pool=%d engines × %d calls, workload=%s\n\n",
		*poolSize, *iters, wl)

	type row struct {
		mib      uint64
		qps      float64
		p50, p99 time.Duration
		rssMiB   float64
		fails    int64
	}
	var rows []row
	var maxRSS uint64

	for _, mib := range miBs {
		engines := make([]*emulator.Emulator, *poolSize)
		for i := range engines {
			e, err := emulator.New(emulator.Config{
				SOPath:    *so,
				AssetRoot: *assets,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "size %dMiB: boot engine %d: %v\n", mib, i, err)
				os.Exit(1)
			}
			if err := emu.SetTCGBufferSize(e.Backend(), uint32(mib)<<20); err != nil {
				fmt.Fprintf(os.Stderr, "size %dMiB: set tcg buffer: %v\n", mib, err)
				os.Exit(1)
			}
			engines[i] = e
		}

		var wg sync.WaitGroup
		durCh := make(chan time.Duration, *poolSize**iters+*poolSize)
		var fails int64
		start := time.Now()
		for _, e := range engines {
			wg.Add(1)
			go func(e *emulator.Emulator) {
				defer wg.Done()
				for i := 0; i < *iters; i++ {
					t0 := time.Now()
					sym := "add"
					if *heavy {
						sym = "fib"
					}
					arg := uint64(i)
					if *heavy {
						arg = 20 // fib(20) = deep recursion, large code footprint
					}
					if _, err := e.CallSymbol(sym, arg, 3); err != nil {
						fmt.Fprintf(os.Stderr, "call: %v\n", err)
						atomic.AddInt64(&fails, 1)
						continue
					}
					durCh <- time.Since(t0)
				}
			}(e)
		}
		wg.Wait()
		close(durCh)
		elapsed := time.Since(start)

		var durs []time.Duration
		for d := range durCh {
			durs = append(durs, d)
		}
		sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })

		rss := peakRSS()
		if rss > maxRSS {
			maxRSS = rss
		}
		rows = append(rows, row{
			mib:    mib,
			qps:    float64(len(durs)) / elapsed.Seconds(),
			p50:    durs[len(durs)/2],
			p99:    durs[len(durs)*99/100],
			rssMiB: float64(rss) / (1 << 20),
			fails:  fails,
		})

		for _, e := range engines {
			e.Close()
		}
		runtime.GC()
	}

	fmt.Printf("%-8s %-10s %-9s %-9s %-10s %s\n", "TCG-MiB", "QPS", "p50", "p99", "maxRSS-MiB", "fails")
	for _, r := range rows {
		fmt.Printf("%-8d %-10.0f %-9v %-9v %-10.1f %d\n",
			r.mib, r.qps, r.p50, r.p99, r.rssMiB, r.fails)
	}
	fmt.Println("\npick the smallest TCG size whose QPS/p99 match the largest (throughput plateau)")
}
