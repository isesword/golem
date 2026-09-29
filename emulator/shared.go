package emulator

import (
	"unsafe"

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
// must never be written by the HOST either. P2.5d made that structural
// (DESIGN.md §8 "privatize 退役"): the only host writer into module .text was
// ReplaceE's entry patch, and function replacement is now Function
// Interposition — an execution hook on the entry address that touches no
// guest memory (HookAddr, the user inline-hook API, never wrote guest memory
// either). The old write-triggered privatize compensation therefore had no
// writer left to serve and was retired; what remains here is the sharing
// itself plus its bookkeeping (diagnostics/tests: isShared).

type sharedRange struct {
	addr, size uint64
	plan       *loader.Plan   // owns the content buffers backing the shared pages
	mapIdx     int            // index into plan.Maps
	hostPtr    unsafe.Pointer // shared host buffer
	hostLen    uint64
}

// applyPlan instantiates the plan in this engine, recording shared ranges.
func (e *Emulator) applyPlan(plan *loader.Plan, base uint64, res loader.SymbolResolver) error {
	if e.cfg.NoSharedModules {
		return plan.ApplyPrivate(e.be, base, res)
	}
	if err := plan.Apply(e.be, base, res); err != nil {
		return err
	}
	for i := range plan.Maps {
		if plan.Maps[i].Shareable {
			ptr, sz, err := plan.SharedBuffer(i)
			if err != nil {
				return err
			}
			e.shared = append(e.shared, sharedRange{
				addr: base + plan.Maps[i].Addr, size: plan.Maps[i].Size,
				plan: plan, mapIdx: i,
				hostPtr: ptr, hostLen: sz,
			})
		}
	}
	return nil
}

// isShared reports whether [addr, addr+size) overlaps a shared (MemMapPtr'd)
// range. Diagnostic query over the Phase B bookkeeping — tests use it to
// prove page sharing engaged and that interposition left it intact.
func (e *Emulator) isShared(addr, size uint64) bool {
	for _, sr := range e.shared {
		if addr < sr.addr+sr.size && sr.addr < addr+size {
			return true
		}
	}
	return false
}
