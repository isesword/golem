package android

import (
	"fmt"

	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// Layout geometry of the Android/AArch64 guest process — the exact values
// the emulator has booted with since P1 made them explicit data. Module,
// heap and mmap windows tile [0x12000000, 0x60000000) contiguously; stubs,
// stack and TLS sit clear above. The heap and mmap bases are not restated
// here: they reference kernel.BrkBase (the kernel's program-break origin)
// and memory.MmapBase (unidbg's ARM64 mmap base) so each number has exactly
// one definition site.
const (
	legacyModuleBase = 0x12000000
	legacyStubBase   = 0x60000000
	legacyStubSize   = 0x00100000
	legacyStackBase  = 0xC0000000 // 8 MiB stack
	legacyStackSize  = 0x00800000
	legacyTLSBase    = 0xD0000000 // thread-local storage block
	legacyTLSSize    = 0x00010000
)

// LayoutPolicy is the Android personality's platform.LayoutPolicy (P4c,
// DESIGN.md §3.4): it plans the initial guest address space — pure geometry,
// no Map/Alloc/Reserve. For AArch64 it produces exactly the legacy layout the
// emulator booted with before P4c (behavior-invariant red line).
type LayoutPolicy struct{}

var _ platform.LayoutPolicy = LayoutPolicy{}

// Resolve plans the Android guest address-space layout. The module window is
// [moduleBase, heapBase): the pre-P4c ModuleSize shim (stubBase−moduleBase,
// an informal upper bound over an arena that also contained the heap and
// mmap sub-arenas) is retired in favor of explicit, adjacent Module/Heap/Mmap
// regions — the bump allocator's exhaustion check at the module window end
// fires at exactly the address where it previously collided with the heap
// reservation, so enforcement is unchanged.
//
// overrides is the reserved user-override channel; only the zero value
// (platform defaults) is supported this stage.
func (LayoutPolicy) Resolve(t platform.TargetInfo, o platform.LayoutOverrides) (memory.Layout, error) {
	if t.Platform != platform.Android {
		return memory.Layout{}, fmt.Errorf("android layout: cannot plan for platform %s", t.Platform)
	}
	if c := t.Caps; c.PointerBits != 64 || c.PageSize != memory.PageSize {
		return memory.Layout{}, fmt.Errorf("android layout: unsupported address-space caps %+v (need 64-bit pointers, %#x pages)", c, memory.PageSize)
	}
	if o != (platform.LayoutOverrides{}) {
		return memory.Layout{}, fmt.Errorf("android layout: layout overrides are reserved (P5+); only the zero value is supported")
	}
	return memory.Layout{
		ModuleRegion: memory.Region{Addr: legacyModuleBase, Size: kernel.BrkBase - legacyModuleBase},
		HeapRegion:   memory.Region{Addr: kernel.BrkBase, Size: memory.MmapBase - kernel.BrkBase},
		MmapRegion:   memory.Region{Addr: memory.MmapBase, Size: legacyStubBase - memory.MmapBase},
		StubBase:     legacyStubBase,
		StubSize:     legacyStubSize,
		StackBase:    legacyStackBase,
		StackSize:    legacyStackSize,
		TLSBase:      legacyTLSBase,
		TLSSize:      legacyTLSSize,
	}, nil
}
