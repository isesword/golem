package emulator

import (
	"fmt"

	"github.com/isesword/golem/internal/loader"
)

// Phase B: shared read-only module pages.
//
// Modules are compiled once (loader.CompileOnce → Image → Plan, including
// page-aligned host buffers for every shareable read-only segment) and each
// engine instantiates the plan with uc_mem_map_ptr — the guest's read-only
// pages are the SAME host memory in every engine of a pool, so they exist in
// physical RAM once. Writable segments (.data/.got/.bss) stay per-engine
// anonymous memory; relocations are applied per engine.
//
// Safety: a shared range is read-only to the guest (unicorn enforces it) and
// must never be written by the HOST either — Replace/HookAddr patch guest
// code, so any host write that targets a shared range first PRIVATIZES that
// module's pages in this engine (fresh anonymous memory with identical
// content). After privatization the engine is back to pre-Phase-B semantics
// for that module; other engines keep sharing.

type sharedRange struct {
	addr, size uint64
	plan       *loader.Plan // owns the content buffers for privatization
	mapIdx     int          // index into plan.Maps
}

// privatize re-maps every shared range covering [addr, addr+size) as private
// anonymous memory with identical content. Idempotent: ranges already
// private are skipped. Returns an error if ANY step of the re-mapping fails
// — the caller must not write to a range it believes is private when the
// privatization did not fully succeed, or every engine sharing those pages
// would be corrupted.
func (e *Emulator) privatize(addr, size uint64) error {
	lo, hi := addr, addr+size
	kept := e.shared[:0]
	var firstErr error
	for _, sr := range e.shared {
		overlaps := lo < sr.addr+sr.size && sr.addr < hi
		if !overlaps {
			kept = append(kept, sr)
			continue
		}
		m := &sr.plan.Maps[sr.mapIdx]
		// Each range is privatized independently: a failed unmap leaves the
		// range SHARED (it stays tracked — the shared host buffer is still
		// the live memory); anything past a failed unmap is skipped for that
		// range. Ranges whose unmap succeeded but remap/content failed are no
		// longer shared by definition (the guest pages are engine-private,
		// possibly broken) and are dropped from tracking; the error bubbles
		// up and Replace panics, so the engine never pretends to be healthy.
		if err := e.be.MemUnmap(sr.addr, sr.size); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("unmap shared %#x: %w", sr.addr, err)
			}
			kept = append(kept, sr) // unmap failed -> still shared -> keep tracking
			continue
		}
		if err := e.be.MemMap(sr.addr, sr.size, m.Prot); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("re-map private %#x: %w", sr.addr, err)
			}
			continue // unmapped but not re-mapped: dropped from tracking
		}
		if len(m.Content) > 0 {
			if err := e.be.MemWrite(sr.addr, m.Content); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("restore content %#x: %w", sr.addr, err)
				}
				continue // re-mapped but content unknown: dropped from tracking
			}
		}
		// fully privatized: intentionally NOT re-added to e.shared
	}
	e.shared = kept
	if firstErr != nil {
		return firstErr
	}
	if err := e.be.FlushCache(); err != nil {
		return fmt.Errorf("flush after privatize: %w", err)
	}
	return nil
}

// applyPlan instantiates the plan in this engine, recording shared ranges.
func (e *Emulator) applyPlan(plan *loader.Plan, base uint64, resolve loader.Resolver) error {
	if e.cfg.NoSharedModules {
		return plan.ApplyPrivate(e.be, base, resolve)
	}
	if err := plan.Apply(e.be, base, resolve); err != nil {
		return err
	}
	for i := range plan.Maps {
		if plan.Maps[i].Shareable {
			e.shared = append(e.shared, sharedRange{
				addr: base + plan.Maps[i].Addr, size: plan.Maps[i].Size,
				plan: plan, mapIdx: i,
			})
		}
	}
	return nil
}

// assertNoSharedWrite is a guard for host-side patch sites: writing into a
// shared range without privatizing would corrupt every engine sharing those
// pages. Replace/HookAddr call this through privatize instead.
func (e *Emulator) isShared(addr, size uint64) bool {
	for _, sr := range e.shared {
		if addr < sr.addr+sr.size && sr.addr < addr+size {
			return true
		}
	}
	return false
}

var _ = fmt.Sprintf // fmt retained for verbose paths in this file
