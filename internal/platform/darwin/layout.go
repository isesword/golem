package darwin

import (
	"fmt"

	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// Layout geometry of the Darwin/ARM64 guest process. The values are chosen
// fresh for Darwin — the point of is that a second platform picks its OWN
// geometry instead of inheriting Android's — with module/heap/mmap tiling
// [0x40000000, 0x70000000) contiguously and stubs, stack and TLS clear above.
// The window deliberately sits above kernel.BrkBase (0x30000000): the Darwin
// table binds no brk handler, so the kernel's program-break range stays an
// empty [BrkBase, BrkBase) that nothing maps.
const (
	moduleBase = 0x40000000
	moduleSize = 0x10000000
	heapBase   = 0x50000000
	heapSize   = 0x10000000
	mmapBase   = 0x60000000
	mmapSize   = 0x10000000
	stubBase   = 0x70000000
	stubSize   = 0x00100000
	stackBase  = 0xB0000000 // 8 MiB stack
	stackSize  = 0x00800000
	tlsBase    = 0xE0000000 // thread-local storage block
	tlsSize    = 0x00010000
)

// LayoutPolicy is the Darwin personality's platform.LayoutPolicy (shape,
// DESIGN.md §3.4): it plans the initial guest address space — pure geometry,
// no Map/Alloc/Reserve.
type LayoutPolicy struct{}

var _ platform.LayoutPolicy = LayoutPolicy{}

// Resolve plans the Darwin guest address-space layout for a 64-bit,
// 4 KiB-page target. overrides is the reserved user-override channel; only
// the zero value (platform defaults) is supported this stage.
func (LayoutPolicy) Resolve(t platform.TargetInfo, o platform.LayoutOverrides) (memory.Layout, error) {
	if t.Platform != platform.Darwin {
		return memory.Layout{}, fmt.Errorf("darwin layout: cannot plan for platform %s", t.Platform)
	}
	if c := t.Caps; c.PointerBits != 64 || c.PageSize != memory.PageSize {
		return memory.Layout{}, fmt.Errorf("darwin layout: unsupported address-space caps %+v (need 64-bit pointers, %#x pages)", c, memory.PageSize)
	}
	if o != (platform.LayoutOverrides{}) {
		return memory.Layout{}, fmt.Errorf("darwin layout: layout overrides are reserved (P5+); only the zero value is supported")
	}
	return memory.Layout{
		ModuleRegion: memory.Region{Addr: moduleBase, Size: moduleSize},
		HeapRegion:   memory.Region{Addr: heapBase, Size: heapSize},
		MmapRegion:   memory.Region{Addr: mmapBase, Size: mmapSize},
		StubBase:     stubBase,
		StubSize:     stubSize,
		StackBase:    stackBase,
		StackSize:    stackSize,
		TLSBase:      tlsBase,
		TLSSize:      tlsSize,
	}, nil
}
