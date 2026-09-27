package emulator

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Pool shares a set of expensive stateful engines across concurrent callers.
//
// An Emulator is NOT goroutine-safe: it belongs to one owner goroutine at a
// time (the actor pattern — state has one owner, work is serialized per
// engine, and concurrency scales by engine count instead of by locks). The
// pool is the framework's answer to "call this engine from many goroutines":
// acquire an engine, run one unit of work, release it.
//
// Engines are recycled after MaxUses invocations (bounds any per-engine
// accumulation on very long runs) and rebuilt transparently after a worker
// panic, so a guest bug in one engine never poisons the pool. Rebuilds may
// run concurrently with each other and with in-flight work; newFn must be
// safe under that (closeFn is called for recycled/closed engines, one call
// per engine, never concurrently for the same engine).
//
// CloseAll shuts the pool down for good: pending and future Do calls fail
// with "pool closed", and Stats stop being meaningful afterwards.
type Pool[T any] struct {
	newFn    func() (T, error)
	closeFn  func(T)
	maxUses  int64
	mu       sync.Mutex
	idle     []*poolItem[T]
	wait     []chan *poolItem[T] // FIFO waiters when the pool is drained
	size     int
	assigned int // handed out and not yet returned
	closed   bool
}

type poolItem[T any] struct {
	e    T
	uses int64
}

// PoolStats reports pool occupancy for monitoring.
type PoolStats struct {
	Size  int // configured engine count
	InUse int // engines currently lent out
	Idle  int // engines sitting idle
}

// NewPool builds and warms a pool of `size` engines. newFn constructs one
// engine (boot + init); it is called serially during warmup and rebuilds.
// maxUses <= 0 means no recycle limit.
func NewPool[T any](size int, maxUses int64, newFn func() (T, error), closeFn func(T)) (*Pool[T], error) {
	if size <= 0 {
		return nil, errors.New("emulator: pool size must be > 0")
	}
	if newFn == nil {
		return nil, errors.New("emulator: pool needs a constructor")
	}
	if closeFn == nil {
		return nil, errors.New("emulator: pool needs a close function")
	}
	p := &Pool[T]{newFn: newFn, closeFn: closeFn, maxUses: maxUses, size: size}
	for i := 0; i < size; i++ {
		e, err := newFn()
		if err != nil {
			p.CloseAll()
			return nil, fmt.Errorf("emulator: pool warmup %d/%d: %w", i+1, size, err)
		}
		p.idle = append(p.idle, &poolItem[T]{e: e})
	}
	return p, nil
}

// Do acquires an engine, runs fn, and releases the engine back — or recycles
// it if it exceeded MaxUses or fn panicked. fn must not retain the engine past
// its return; all use happens inside the call.
func (p *Pool[T]) Do(ctx context.Context, fn func(T) error) error {
	it, err := p.acquire(ctx)
	if err != nil {
		return err
	}

	dead := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				dead = true
				err = fmt.Errorf("emulator: worker panic: %v", r)
			}
		}()
		err = fn(it.e)
	}()

	it.uses++
	if dead || (p.maxUses > 0 && it.uses >= p.maxUses) {
		p.safeClose(it.e) // recycle: guest blew up or the engine aged out
		if it = p.rebuild(); it == nil {
			// rebuild failed: the pool shrank by one — drop the accounting
			// entry of the recycled engine so Stats stay truthful
			p.mu.Lock()
			p.assigned--
			p.size--
			p.mu.Unlock()
			return err
		}
	}
	p.release(it)
	return err
}

// Stats returns current occupancy.
func (p *Pool[T]) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStats{Size: p.size, InUse: p.assigned, Idle: len(p.idle)}
}

// CloseAll shuts every idle engine down and wakes all waiters with a
// "pool closed" error. Engines currently lent out are closed by their
// holders' final release. Stats stop being meaningful after CloseAll.
func (p *Pool[T]) CloseAll() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	idle := p.idle
	wait := p.wait
	p.idle = nil
	p.wait = nil
	p.mu.Unlock()
	for _, it := range idle {
		p.closeFn(it.e)
	}
	for _, w := range wait {
		w <- nil // buffered: the waiter reads it as "pool closed"
	}
}

func (p *Pool[T]) acquire(ctx context.Context) (*poolItem[T], error) {
	p.mu.Lock()
	for {
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("emulator: pool closed")
		}
		if n := len(p.idle); n > 0 {
			it := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.assigned++
			p.mu.Unlock()
			return it, nil
		}
		ch := make(chan *poolItem[T], 1)
		p.wait = append(p.wait, ch)
		p.mu.Unlock()

		select {
		case it := <-ch:
			p.mu.Lock()
			p.assigned++
			p.mu.Unlock()
			if it == nil {
				return nil, errors.New("emulator: pool closed")
			}
			return it, nil
		case <-ctx.Done():
			// De-register best-effort. A raced handoff lands on the buffered
			// channel; the item was already accounted as returned by release,
			// so give() must run WITHOUT touching the assigned counter.
			p.mu.Lock()
			for i, w := range p.wait {
				if w == ch {
					p.wait = append(p.wait[:i], p.wait[i+1:]...)
					break
				}
			}
			select {
			case it := <-ch:
				p.give(it)
			default:
			}
			p.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

func (p *Pool[T]) release(it *poolItem[T]) {
	p.mu.Lock()
	if !p.closed {
		p.assigned-- // after CloseAll the counter is frozen: Stats are void
	}
	p.give(it)
	p.mu.Unlock()
}

// give returns an item to the pool. Caller holds p.mu; the assigned counter
// must already reflect the item's availability (give never adjusts it).
func (p *Pool[T]) give(it *poolItem[T]) {
	if p.closed {
		p.mu.Unlock()
		p.safeClose(it.e)
		p.mu.Lock()
		return
	}
	if len(p.wait) > 0 {
		w := p.wait[0]
		p.wait = p.wait[1:]
		w <- it // buffered: never blocks even if the waiter timed out
		return
	}
	p.idle = append(p.idle, it)
}

// safeClose invokes closeFn with panic protection — a closeFn crash on an
// already-broken engine must not skip the pool's accounting.
func (p *Pool[T]) safeClose(e T) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[pool] closeFn panicked: %v\n", r)
		}
	}()
	p.closeFn(e)
}

// rebuild replaces a recycled engine, keeping the pool at its configured
// size. Called without p.mu held; may run concurrently with other rebuilds.
func (p *Pool[T]) rebuild() *poolItem[T] {
	e, err := p.newFn()
	if err != nil {
		// Persistent construction failure shrinks the pool; Do reports the
		// original work error either way.
		p.mu.Lock()
		size := p.size - 1
		p.mu.Unlock()
		fmt.Printf("[pool] engine rebuild failed: %v (pool size now %d)\n", err, size)
		return nil
	}
	return &poolItem[T]{e: e}
}
