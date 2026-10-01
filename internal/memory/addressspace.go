package memory

import (
	"fmt"

	"github.com/isesword/golem/internal/emu"
)

// Purpose identifies which region of the guest address space an allocation
// belongs to (DESIGN.md invariant 12: every guest VA allocation goes through
// AddressSpace, attributed to exactly one purpose).
type Purpose uint8

const (
	PurposeModule Purpose = iota + 1 // loaded shared objects (bump upward)
	PurposeStub                      // svc trampolines (unresolved imports, host fns, JNI slots)
	PurposeStack                     // initial thread stack (fixed, boot-time Reserve)
	PurposeTLS                       // thread-local storage block (fixed, boot-time Reserve)
	PurposeMmap                      // anonymous mmap arena (managed internally by Space)
	PurposeGuard                     // guard pages (reserved; no allocator yet)
	PurposeHeap                      // brk heap (managed internally by the kernel brk cursor)
)

func (p Purpose) String() string {
	switch p {
	case PurposeModule:
		return "module"
	case PurposeStub:
		return "stub"
	case PurposeStack:
		return "stack"
	case PurposeTLS:
		return "tls"
	case PurposeMmap:
		return "mmap"
	case PurposeGuard:
		return "guard"
	case PurposeHeap:
		return "heap"
	}
	return fmt.Sprintf("purpose(%d)", int(p))
}

// area is one bump-allocated region derived from the Layout.
type area struct {
	base uint64
	size uint64
	cur  uint64 // bump cursor: bytes handed out so far
}

func (a *area) end() uint64 { return a.base + a.size }

// reservation is a fixed-address range attributed to a purpose: boot-time
// stack/TLS mappings, and the ownership registration of arenas whose internal
// management lives elsewhere (the mmap Space, the kernel brk heap). Bump
// allocation never hands out a range overlapping a reservation.
type reservation struct {
	addr uint64
	size uint64
	p    Purpose
}

func (r reservation) end() uint64 { return r.addr + r.size }

// AddressSpace holds the Layout plus the per-region allocation state and is
// the single entry point for guest VA allocation (DESIGN.md §3.7, invariant
// 12). It is pure bookkeeping: which bytes a range corresponds to and how
// they are mapped into the CPU backend stay with the callers.
//
// Two allocation styles:
//   - Alloc: bump allocation inside a purpose's Layout region (module load
//     bases, stub trampolines). Fails loudly on region exhaustion or on
//     collision with a reserved range — never silently picks another address.
//   - Reserve: claims a fixed-address range (boot stack/TLS) or registers
//     ownership of a sub-arena managed elsewhere (mmap heap via Space, brk
//     heap via the kernel) so bump allocations cannot drift into it.
//
// Snapshot semantics: the bump cursors are deliberately NOT part of the
// emulator's Snapshot/Restore — restore does not roll back module/stub
// allocation (matching the legacy emulator cursor fields, which were
// likewise outside the snapshot).
type AddressSpace struct {
	layout Layout
	areas  map[Purpose]*area
	res    []reservation
}

// NewAddressSpace builds the allocation state from a Layout: one bump area
// per Layout region (module/stub/stack/tls). Purposes without a bump area
// (mmap/guard/heap) own no cursor — their Layout ranges (HeapRegion,
// MmapRegion) enter via Reserve, registered by the composition root.
func NewAddressSpace(l Layout) *AddressSpace {
	return &AddressSpace{
		layout: l,
		areas: map[Purpose]*area{
			PurposeModule: {base: l.ModuleRegion.Addr, size: l.ModuleRegion.Size},
			PurposeStub:   {base: l.StubBase, size: l.StubSize},
			PurposeStack:  {base: l.StackBase, size: l.StackSize},
			PurposeTLS:    {base: l.TLSBase, size: l.TLSSize},
		},
	}
}

// Layout returns the layout the address space was built from.
func (as *AddressSpace) Layout() Layout { return as.layout }

// Alloc bump-allocates size bytes inside purpose p's region and returns the
// base. It errors — rather than silently relocating — when p has no region,
// the region is exhausted, or the next chunk would overlap a reserved range
// (e.g. a module bump reaching the registered brk/mmap sub-arenas).
func (as *AddressSpace) Alloc(p Purpose, size uint64) (emu.GuestAddr, error) {
	a, ok := as.areas[p]
	if !ok {
		return 0, fmt.Errorf("memory: alloc %s: no such region", p)
	}
	if size == 0 {
		return 0, fmt.Errorf("memory: alloc %s: zero size", p)
	}
	if size > a.size-a.cur {
		return 0, fmt.Errorf("memory: alloc %s: %#x bytes exhausted region [%#x,%#x) (cursor %#x)",
			p, size, a.base, a.end(), a.cur)
	}
	addr := a.base + a.cur
	if r, ok := as.overlapsReserved(addr, size); ok {
		return 0, fmt.Errorf("memory: alloc %s at %#x+%#x collides with reserved %s range [%#x,%#x)",
			p, addr, size, r.p, r.addr, r.end())
	}
	a.cur += size
	return emu.GuestAddr(addr), nil
}

// Reserve claims the fixed range [addr, addr+size) for purpose p. Used at
// boot for the stack/TLS mappings and to register the mmap/brk sub-arenas
// (whose internals stay managed by Space / the kernel brk cursor this stage).
// Overlapping an existing reservation is an error.
func (as *AddressSpace) Reserve(addr emu.GuestAddr, size uint64, p Purpose) error {
	if size == 0 {
		return fmt.Errorf("memory: reserve %s: zero size at %#x", p, uint64(addr))
	}
	base := uint64(addr)
	if base+size < base {
		return fmt.Errorf("memory: reserve %s: range %#x+%#x wraps", p, base, size)
	}
	for _, r := range as.res {
		if base < r.end() && r.addr < base+size {
			return fmt.Errorf("memory: reserve %s [%#x,%#x) overlaps reserved %s range [%#x,%#x)",
				p, base, base+size, r.p, r.addr, r.end())
		}
	}
	as.res = append(as.res, reservation{addr: base, size: size, p: p})
	return nil
}

func (as *AddressSpace) overlapsReserved(addr, size uint64) (reservation, bool) {
	for _, r := range as.res {
		if addr < r.end() && r.addr < addr+size {
			return r, true
		}
	}
	return reservation{}, false
}

// Area reports the bounds of purpose p's bump region (ok=false if p has none).
func (as *AddressSpace) Area(p Purpose) (base, size uint64, ok bool) {
	a, ok := as.areas[p]
	if !ok {
		return 0, 0, false
	}
	return a.base, a.size, true
}

// Used returns how many bytes purpose p's bump allocator has handed out.
func (as *AddressSpace) Used(p Purpose) uint64 {
	if a, ok := as.areas[p]; ok {
		return a.cur
	}
	return 0
}

// Remaining returns the unallocated bytes left in purpose p's bump region
// (0 for purposes without one). Reserved sub-ranges are not subtracted — an
// Alloc that would reach one fails instead.
func (as *AddressSpace) Remaining(p Purpose) uint64 {
	if a, ok := as.areas[p]; ok {
		return a.size - a.cur
	}
	return 0
}

// ReservedRange is one fixed reserved range (boot stack/TLS mappings,
// registered sub-arenas), as reported by Reservations.
type ReservedRange struct {
	Addr    uint64
	Size    uint64
	Purpose Purpose
}

// Reservations returns the fixed reserved ranges, for diagnostics and tests.
func (as *AddressSpace) Reservations() []ReservedRange {
	out := make([]ReservedRange, len(as.res))
	for i, r := range as.res {
		out[i] = ReservedRange{Addr: r.addr, Size: r.size, Purpose: r.p}
	}
	return out
}
