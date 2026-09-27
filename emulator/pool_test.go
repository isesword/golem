package emulator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeEngine stands in for *Emulator so pool semantics are testable without a
// CPU engine; the real engine is exercised by the golden/e2e suites.
type fakeEngine struct {
	closed atomic.Bool
}

func TestPoolConcurrentDo(t *testing.T) {
	var built atomic.Int64
	p, err := NewPool(8, 0,
		func() (*fakeEngine, error) { built.Add(1); return &fakeEngine{}, nil },
		func(e *fakeEngine) { e.closed.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	var wg sync.WaitGroup
	var running, maxRunning atomic.Int64
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := p.Do(context.Background(), func(e *fakeEngine) error {
					n := running.Add(1)
					for { // track max concurrent engine use
						old := maxRunning.Load()
						if n <= old || maxRunning.CompareAndSwap(old, n) {
							break
						}
					}
					if e.closed.Load() {
						t.Error("acquired an engine that was already closed")
					}
					time.Sleep(time.Millisecond)
					running.Add(-1)
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	if maxRunning.Load() > 8 {
		t.Errorf("max concurrent in-engine work = %d, must never exceed pool size 8", maxRunning.Load())
	}
	if built.Load() != 8 {
		t.Errorf("engines built = %d, want 8 (no recycle without MaxUses)", built.Load())
	}
	st := p.Stats()
	if st.InUse != 0 || st.Idle != 8 {
		t.Errorf("pool not fully idle after workload: %+v", st)
	}
}

func TestPoolRecyclesAtMaxUses(t *testing.T) {
	var built, closed atomic.Int64
	p, err := NewPool(2, 3,
		func() (*fakeEngine, error) { built.Add(1); return &fakeEngine{}, nil },
		func(e *fakeEngine) { closed.Add(1); e.closed.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	for i := 0; i < 12; i++ {
		if err := p.Do(context.Background(), func(e *fakeEngine) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// 12 uses / maxUses 3 = 6 engine lifetimes over 2 slots → 2 warmup + 4 rebuilds
	if built.Load() != 6 || closed.Load() != 4 {
		t.Errorf("built=%d closed=%d, want built=6 closed=4", built.Load(), closed.Load())
	}
}

func TestPoolRecoversFromPanic(t *testing.T) {
	var closed atomic.Int64
	p, err := NewPool(1, 0,
		func() (*fakeEngine, error) { return &fakeEngine{}, nil },
		func(e *fakeEngine) { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	workErr := errors.New("boom inside guest")
	if err := p.Do(context.Background(), func(e *fakeEngine) error {
		panic("guest blew up")
	}); err == nil {
		t.Fatal("panic must surface as an error")
	}
	// the pool must survive and hand out a FRESH engine afterwards
	var same bool
	if err := p.Do(context.Background(), func(e *fakeEngine) error {
		if e.closed.Load() {
			t.Error("panic engine must have been closed and replaced")
		}
		_ = workErr
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = same
	if closed.Load() != 1 {
		t.Errorf("panic engine closed %d times, want 1", closed.Load())
	}
}

func TestPoolDeadlineWhenDrained(t *testing.T) {
	p, err := NewPool(1, 0,
		func() (*fakeEngine, error) { return &fakeEngine{}, nil },
		func(e *fakeEngine) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	release := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Do(context.Background(), func(e *fakeEngine) error {
			<-release
			return nil
		})
	}()
	time.Sleep(50 * time.Millisecond) // let the holder drain the pool

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := p.Do(ctx, func(e *fakeEngine) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drained pool must honor ctx deadline, got %v", err)
	}
	close(release)
	if err := <-errCh; err != nil {
		t.Fatalf("holder errored: %v", err)
	}
}

// Regression for the drain-race accounting bug: waiters with random short
// deadlines race the handoff; assigned must stay >= 0 and Idle+InUse == Size.
func TestPoolTimeoutRaceAccounting(t *testing.T) {
	p, err := NewPool(4, 0,
		func() (*fakeEngine, error) { return &fakeEngine{}, nil },
		func(e *fakeEngine) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	var wg sync.WaitGroup
	for g := 0; g < 96; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				deadline := time.Duration(1+g%5) * time.Millisecond
				ctx, cancel := context.WithTimeout(context.Background(), deadline)
				_ = p.Do(ctx, func(e *fakeEngine) error {
					time.Sleep(2 * time.Millisecond)
					return nil
				})
				cancel()
			}
		}(g)
	}
	wg.Wait()

	st := p.Stats()
	if st.InUse < 0 {
		t.Fatalf("InUse went negative (%d) — accounting bug", st.InUse)
	}
	if st.InUse+st.Idle != st.Size {
		t.Fatalf("pool leaked engines: InUse=%d Idle=%d Size=%d", st.InUse, st.Idle, st.Size)
	}
}

func TestPoolErrorPropagatesWithoutRecycle(t *testing.T) {
	var built, closed atomic.Int64
	p, err := NewPool(1, 0,
		func() (*fakeEngine, error) { built.Add(1); return &fakeEngine{}, nil },
		func(e *fakeEngine) { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	want := errors.New("guest said no")
	for i := 0; i < 3; i++ {
		if err := p.Do(context.Background(), func(e *fakeEngine) error { return want }); !errors.Is(err, want) {
			t.Fatalf("Do error = %v, want the fn error verbatim", err)
		}
	}
	if built.Load() != 1 || closed.Load() != 0 {
		t.Errorf("built=%d closed=%d — fn errors must NOT recycle engines", built.Load(), closed.Load())
	}
}

func TestPoolCloseAllWakesWaitersAndRejectsDo(t *testing.T) {
	p, _ := NewPool(1, 0,
		func() (*fakeEngine, error) { return &fakeEngine{}, nil },
		func(e *fakeEngine) {})
	release := make(chan struct{})
	holderErr := make(chan error, 1)
	go func() {
		holderErr <- p.Do(context.Background(), func(e *fakeEngine) error {
			<-release // hold the only engine
			return nil
		})
	}()
	time.Sleep(50 * time.Millisecond)

	// a waiter blocked on the drained pool must be woken by CloseAll
	waiterErr := make(chan error, 1)
	go func() {
		waiterErr <- p.Do(context.Background(), func(e *fakeEngine) error { return nil })
	}()
	time.Sleep(50 * time.Millisecond)

	p.CloseAll()
	close(release)

	select {
	case err := <-waiterErr:
		if err == nil || err.Error() != "emulator: pool closed" {
			t.Fatalf("waiter err = %v, want pool closed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseAll did not wake the blocked waiter")
	}
	if err := <-holderErr; err != nil {
		t.Fatalf("holder errored: %v", err)
	}
	// Do after CloseAll must fail fast with "pool closed"
	if err := p.Do(context.Background(), func(e *fakeEngine) error { return nil }); err == nil {
		t.Fatal("Do on a closed pool must fail")
	}
}

func TestPoolConcurrentCloseAllAccounting(t *testing.T) {
	// CloseAll racing in-flight Do must never produce negative InUse.
	for round := 0; round < 20; round++ {
		p, _ := NewPool(4, 0,
			func() (*fakeEngine, error) { return &fakeEngine{}, nil },
			func(e *fakeEngine) {})
		var wg sync.WaitGroup
		for g := 0; g < 16; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
				defer cancel()
				_ = p.Do(ctx, func(e *fakeEngine) error { return nil })
			}()
		}
		time.Sleep(time.Duration(round%5) * time.Millisecond)
		p.CloseAll()
		wg.Wait()
		// post-close Stats are void; the assertion is only "no panic, no hang"
	}
}

func TestPoolRebuildFailureShrinks(t *testing.T) {
	var built atomic.Int64
	fail := false
	p, err := NewPool(2, 2, // maxUses=2: every second Do recycles
		func() (*fakeEngine, error) {
			built.Add(1)
			if fail {
				return nil, errors.New("no engine for you")
			}
			return &fakeEngine{}, nil
		},
		func(e *fakeEngine) {})
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseAll()

	_ = p.Do(context.Background(), func(e *fakeEngine) error { return nil }) // uses=1
	fail = true
	err = p.Do(context.Background(), func(e *fakeEngine) error { return nil }) // uses=2 → recycle → rebuild fails
	if err != nil {
		t.Fatalf("fn succeeded; Do must report no error despite rebuild failure, got %v", err)
	}
	if st := p.Stats(); st.Size != 1 {
		t.Fatalf("pool size = %d after rebuild failure, want 1 (shrunken)", st.Size)
	}
	// the pool still works with its remaining engine
	if err := p.Do(context.Background(), func(e *fakeEngine) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
