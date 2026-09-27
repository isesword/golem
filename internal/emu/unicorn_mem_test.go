//go:build unicorn && (darwin || linux)

package emu

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

// Memory-footprint test for the purego unicorn backend: 100k iterations per
// phase (overridable), reporting Go-heap and process-RSS growth at each
// checkpoint. The phases isolate the factors:
//
//	P1 purego dlopen     — binding overhead: libunicorn mapping (lazy, RSS),
//	                       3 static NewCallback trampolines, Go-side bindings.
//	P3a rewrite+execute  — single engine, 100k× [mem_write(new instruction) +
//	                       emu_start + 3 hook callbacks]: TB-cache / code-churn
//	                       pressure with a persistent hook.
//	P3b hook churn       — single engine, 100k× [hook add + remove]: the cbid
//	                       registry and unicorn's hook allocation lifecycle.
//	P4 engine churn      — 100k× full [create → map → run → close]: per-engine
//	                       cost; a sustained RSS slope here is a true C leak.
//
// Go side is read from runtime.MemStats after forced GC; process side from
// getrusage ru_maxrss (a high-water mark — plateaus are clean, linear growth
// is a leak).
//
//	Opt-in (heavy): GOLEM_MEMTEST=1 go test -tags unicorn \
//	  -run TestUnicornMemory -v ./internal/emu
//
// Counts: GOLEM_MEM_N (default 100000), GOLEM_MEM_CHURN (default 100000).
func TestUnicornMemory(t *testing.T) {
	if os.Getenv("GOLEM_MEMTEST") != "1" {
		t.Skip("heavy memory test; set GOLEM_MEMTEST=1 to run")
	}
	hotN := envCount("GOLEM_MEM_N", 100000)
	churnN := envCount("GOLEM_MEM_CHURN", 100000)

	type snap struct {
		label   string
		heap    uint64 // HeapAlloc bytes, after GC
		mallocs uint64
		rss     uint64 // ru_maxrss normalized to bytes
	}
	take := func(label string) snap {
		runtime.GC()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatalf("getrusage: %v", err)
		}
		rss := uint64(ru.Maxrss)
		if runtime.GOOS == "linux" {
			rss *= 1024 // Linux reports KB, darwin reports bytes
		}
		s := snap{label, ms.HeapAlloc, ms.Mallocs, rss}
		t.Logf("%-28s heap=%8.2f MiB  mallocs=%12d  maxRSS=%8.2f MiB",
			s.label, float64(s.heap)/(1<<20), s.mallocs, float64(s.rss)/(1<<20))
		return s
	}
	delta := func(a, b snap) string {
		return fmt.Sprintf("heap %+7.2f MiB, maxRSS %+7.2f MiB",
			float64(int64(b.heap)-int64(a.heap))/(1<<20),
			float64(int64(b.rss)-int64(a.rss))/(1<<20))
	}

	// ---- phase 1: purego load (dlopen libunicorn + bindings + trampolines) --
	s0 := take("P0 baseline")
	be0, err := New()
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	s1 := take("P1 after purego dlopen")
	t.Logf("    Δ %s   <- libunicorn mapping + 3 trampolines + Go bindings (purego overhead)",
		delta(s0, s1))
	if lib := os.Getenv("GOLEM_UNICORN"); lib != "" {
		if fi, err := os.Stat(lib); err == nil {
			t.Logf("    libunicorn file: %.2f MiB (mapped lazily — RSS fills on use)", float64(fi.Size())/(1<<20))
		}
	}

	// ---- shared per-engine workload (also the churn body) -------------------
	const codeBase = 0x100000
	const dataPage = 0x200000
	runOne := func(b Backend, verify bool) error {
		if err := b.MemMap(codeBase, 0x1000, ProtAll); err != nil {
			return err
		}
		// 3× ADD X0,X0,#1 (0x91000400) + RET (0xD65F03C0)
		for i := 0; i < 3; i++ {
			if err := b.MemWrite(codeBase+uint64(i*4), []byte{0x00, 0x04, 0x00, 0x91}); err != nil {
				return err
			}
		}
		if err := b.MemWrite(codeBase+12, []byte{0xC0, 0x03, 0x5F, 0xD6}); err != nil {
			return err
		}
		// LDR X1,[X2] + RET for the demand-map path
		if err := b.MemWrite(codeBase+0x100, []byte{0x41, 0x00, 0x40, 0xF9}); err != nil {
			return err
		}
		if err := b.MemWrite(codeBase+0x104, []byte{0xC0, 0x03, 0x5F, 0xD6}); err != nil {
			return err
		}
		if err := b.RegWrite(RegX0, 5); err != nil {
			return err
		}
		// 3 starts × 3 adds (X0 reset per pass), firing the code hook each insn
		for i := 0; i < 3; i++ {
			if err := b.RegWrite(RegX0, 5); err != nil {
				return err
			}
			if err := b.Start(codeBase, codeBase+12); err != nil {
				return err
			}
		}
		// demand-map: LDR from unmapped page, hook maps it inside the callback
		mh, err := b.HookMemInvalid(func(b Backend, typ int, addr uint64, size int, value int64) bool {
			if err := b.MemMap(addr&^0xFFF, 0x1000, ProtRead|ProtWrite); err != nil {
				return false
			}
			return b.MemWrite(addr&^0xFFF, []byte{0xEF, 0xBE, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE}) == nil
		})
		if err != nil {
			return err
		}
		defer mh.Remove()
		if err := b.RegWrite(RegX2, dataPage); err != nil {
			return err
		}
		if err := b.Start(codeBase+0x100, codeBase+0x104); err != nil {
			return err
		}
		if verify {
			if got, _ := b.RegRead(RegX0); got != 8 {
				return fmt.Errorf("X0=%d, want 8", got)
			}
			if got, _ := b.RegRead(RegX1); got != 0xDEADC0DEDEADBEEF {
				return fmt.Errorf("X1=%#x, want demand-mapped value", got)
			}
		}
		return nil
	}

	if err := runOne(be0, true); err != nil {
		t.Fatalf("warm-up run: %v", err)
	}
	be0.Close()
	take("P2 after warm engine run")

	cbRegLen := func() int { cbMu.Lock(); defer cbMu.Unlock(); return len(cbReg) }
	noopHook := func(Backend, uint64, uint32) {}

	// ---- P3a: single engine, 100k× [rewrite instruction + execute] ----------
	// Persistent code hook → 3 callback crossings per Start. This is the
	// realistic hot-path shape (sign service reusing one engine).
	be, err := New()
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()
	if err := runOne(be, false); err != nil {
		t.Fatalf("hot prep: %v", err)
	}
	ph, err := be.HookCode(codeBase, codeBase+8, noopHook)
	if err != nil {
		t.Fatal(err)
	}
	var p3a []snap
	p3a = append(p3a, take("P3a rewrite+exec start"))
	for i := 0; i < hotN; i++ {
		// vary the ADD X0,X0,#imm immediate (bits 10-21) instead of clobbering
		// the instruction with data — emu_start must stay on valid code.
		insn := uint32(0x91000000) | ((1 + uint32(i)%4095) << 10)
		w := [4]byte{byte(insn), byte(insn >> 8), byte(insn >> 16), byte(insn >> 24)}
		if err := be.MemWrite(codeBase, w[:]); err != nil {
			t.Fatal(err)
		}
		if err := be.RegWrite(RegX0, uint64(i)); err != nil {
			t.Fatal(err)
		}
		if err := be.Start(codeBase, codeBase+12); err != nil {
			t.Fatal(err)
		}
		if (i+1)%(hotN/10) == 0 {
			p3a = append(p3a, take(fmt.Sprintf("P3a rewrite+exec %d/%d", i+1, hotN)))
		}
	}
	if err := ph.Remove(); err != nil {
		t.Fatal(err)
	}

	// P3a2: does FlushCache reclaim the TB growth? 10k more rewrites after a
	// full TB flush — if the slope flattens, the code cache recycles on flush
	// and periodic FlushCache bounds long-lived engines that rewrite guest code.
	if err := be.FlushCache(); err != nil {
		t.Fatal(err)
	}
	f0 := take("P3a2 after FlushCache")
	for i := 0; i < hotN/10; i++ {
		insn := uint32(0x91000000) | ((1 + uint32(i)%4095) << 10)
		w := [4]byte{byte(insn), byte(insn >> 8), byte(insn >> 16), byte(insn >> 24)}
		if err := be.MemWrite(codeBase, w[:]); err != nil {
			t.Fatal(err)
		}
		if err := be.RegWrite(RegX0, uint64(i)); err != nil {
			t.Fatal(err)
		}
		if err := be.Start(codeBase, codeBase+12); err != nil {
			t.Fatal(err)
		}
	}
	f1 := take("P3a2 after 10k more rewrites")
	t.Logf("    post-flush RSS slope: %.0f B/iter (%s)",
		float64(int64(f1.rss)-int64(f0.rss))/float64(hotN/10),
		map[bool]string{true: "TB cache recycles on flush — growth bounded",
			false: "growth continues past flush"}[int64(f1.rss)-int64(f0.rss) < int64(hotN/10)*100])

	// ---- P3b: single engine, 100k× [hook add + remove] ----------------------
	var p3b []snap
	p3b = append(p3b, take("P3b hook churn start"))
	for i := 0; i < hotN; i++ {
		h, err := be.HookCode(codeBase, codeBase+8, noopHook)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.Remove(); err != nil {
			t.Fatal(err)
		}
		if (i+1)%(hotN/10) == 0 {
			p3b = append(p3b, take(fmt.Sprintf("P3b hook churn %d/%d", i+1, hotN)))
		}
	}
	if got := cbRegLen(); got != 0 {
		t.Errorf("hook registry holds %d entries after P3b, want 0 (Go-side leak)", got)
	}

	// ---- P4: engine churn — 100k× full [create → use → close] ---------------
	var churn []snap
	for i := 0; i < churnN; i++ {
		b, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if err := runOne(b, i%4096 == 0); err != nil {
			t.Fatalf("churn iter %d: %v", i, err)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if (i+1)%(churnN/10) == 0 {
			churn = append(churn, take(fmt.Sprintf("P4 engine churn %d/%d", i+1, churnN)))
		}
	}
	if got := cbRegLen(); got != 0 {
		t.Errorf("hook registry holds %d entries after churn, want 0 (Go-side leak)", got)
	}

	// ---- verdict ------------------------------------------------------------
	runtime.GC()
	runtime.GC()
	sEnd := take("P5 after full workload")

	slope := func(phase []snap) float64 {
		if len(phase) < 3 {
			return 0
		}
		n := hotN / (len(phase) - 1) * (len(phase) - 1)
		return float64(int64(phase[len(phase)-1].rss)-int64(phase[0].rss)) / float64(n)
	}
	t.Logf("")
	t.Logf("=== summary (n_hot=%d n_churn=%d) ===", hotN, churnN)
	t.Logf("purego dlopen overhead     : %s", delta(s0, s1))
	t.Logf("P3a rewrite+exec (100k×)   : %s", delta(p3a[0], p3a[len(p3a)-1]))
	t.Logf("     RSS slope             : %.0f B/iter (unicorn TB/code churn on rewrite)", slope(p3a))
	t.Logf("P3b hook churn   (100k×)   : %s", delta(p3b[0], p3b[len(p3b)-1]))
	t.Logf("     RSS slope             : %.0f B/iter (hook alloc/del lifecycle)", slope(p3b))
	if n := len(p3b); n >= 3 && p3b[n-1].rss == p3b[n-2].rss {
		t.Logf("     note: RSS plateaued at %.2f MiB (allocator free-list saturated — bounded, not an unbounded leak)",
			float64(p3b[n-1].rss)/(1<<20))
	}
	t.Logf("P4 engine churn  (100k×)   : %s", delta(churn[0], churn[len(churn)-1]))
	t.Logf("     RSS slope             : %.0f B/lifecycle", float64(int64(churn[len(churn)-1].rss)-int64(churn[0].rss))/float64(churnN))
	t.Logf("total workload             : %s", delta(s0, sEnd))

	totalIters := int64(2*hotN + hotN/10 + churnN) // P3a + P3a2 + P3b + churn
	heapSlope := float64(int64(sEnd.heap)-int64(s0.heap)) / float64(totalIters)
	// GC pacing grows the retained heap under allocation churn (bounded, not a
	// leak); a per-iteration slope stays tight even at 1M+ iterations.
	if heapSlope > 16 {
		t.Errorf("Go heap retains %.1f B/iteration over %d workload iterations — leak suspected",
			heapSlope, totalIters)
	} else {
		t.Logf("Go heap slope: %.1f B/iter over %d iterations (GC steady state, no leak)",
			heapSlope, totalIters)
	}
	if len(churn) >= 2 {
		churnSlope := float64(int64(churn[len(churn)-1].rss)-int64(churn[0].rss)) / float64(churnN)
		if churnSlope > 256 { // >256 B per full engine lifecycle, sustained = C leak
			t.Errorf("RSS grows %.0f bytes per engine lifecycle — C-side leak suspected", churnSlope)
		}
	}
}

func envCount(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
