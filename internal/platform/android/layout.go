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

// 32-bit geometry (P6e): the module/heap/mmap/stub windows are IDENTICAL to
// the 64-bit layout — they tile [0x12000000, 0x60100000), comfortably below
// the ARM Linux 3G/1G user ceiling (arch/arm32 MaxUserVA = 0xBF000000) —
// while the stack and TLS move down from their 64-bit spots (0xC0000000 /
// 0xD0000000 would exceed that ceiling). Stack top 0xB0800000 and TLS end
// 0xB1010000 leave a wide guard gap to MaxUserVA.
const (
	legacyStackBase32 = 0xB0000000 // 8 MiB stack (same size as 64-bit)
	legacyTLSBase32   = 0xB1000000 // 64 KiB TLS block
)

// LayoutPolicy is the Android personality's platform.LayoutPolicy (P4c,
// DESIGN.md §3.4): it plans the initial guest address space — pure geometry,
// no Map/Alloc/Reserve. For AArch64 it produces exactly the legacy layout the
// emulator booted with before P4c (behavior-invariant red line); for ARM32
// (P6e) the same tiling with the 32-bit stack/TLS spots. The policy stays
// EXPLICIT about the target's address-space caps: every region must fit
// below MaxUserVA — a cap that cannot hold the geometry is a loud error,
// never a silent mis-map.
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
	c := t.Caps
	if c.PageSize != memory.PageSize {
		return memory.Layout{}, fmt.Errorf("android layout: unsupported page size %#x (need %#x)", c.PageSize, memory.PageSize)
	}
	var l memory.Layout
	switch c.PointerBits {
	case 64:
		l = memory.Layout{
			ModuleRegion: memory.Region{Addr: legacyModuleBase, Size: kernel.BrkBase - legacyModuleBase},
			HeapRegion:   memory.Region{Addr: kernel.BrkBase, Size: memory.MmapBase - kernel.BrkBase},
			MmapRegion:   memory.Region{Addr: memory.MmapBase, Size: legacyStubBase - memory.MmapBase},
			StubBase:     legacyStubBase,
			StubSize:     legacyStubSize,
			StackBase:    legacyStackBase,
			StackSize:    legacyStackSize,
			TLSBase:      legacyTLSBase,
			TLSSize:      legacyTLSSize,
		}
	case 32:
		l = memory.Layout{
			ModuleRegion: memory.Region{Addr: legacyModuleBase, Size: kernel.BrkBase - legacyModuleBase},
			HeapRegion:   memory.Region{Addr: kernel.BrkBase, Size: memory.MmapBase - kernel.BrkBase},
			MmapRegion:   memory.Region{Addr: memory.MmapBase, Size: legacyStubBase - memory.MmapBase},
			StubBase:     legacyStubBase,
			StubSize:     legacyStubSize,
			StackBase:    legacyStackBase32,
			StackSize:    legacyStackSize,
			TLSBase:      legacyTLSBase32,
			TLSSize:      legacyTLSSize,
		}
	default:
		return memory.Layout{}, fmt.Errorf("android layout: unsupported pointer width %d (need 64 or 32)", c.PointerBits)
	}
	// Explicit fit check (P6e): every region must end at or below the
	// target's user-VA ceiling — e.g. a 32-bit cap below the stub window is
	// a loud, named error, never a silently truncated map.
	for name, end := range map[string]uint64{
		"module": uint64(l.ModuleRegion.Addr) + uint64(l.ModuleRegion.Size),
		"heap":   uint64(l.HeapRegion.Addr) + uint64(l.HeapRegion.Size),
		"mmap":   uint64(l.MmapRegion.Addr) + uint64(l.MmapRegion.Size),
		"stub":   uint64(l.StubBase) + uint64(l.StubSize),
		"stack":  uint64(l.StackBase) + uint64(l.StackSize),
		"tls":    uint64(l.TLSBase) + uint64(l.TLSSize),
	} {
		if end > c.MaxUserVA {
			return memory.Layout{}, fmt.Errorf("android layout: %s region end %#x exceeds the target's user ceiling %#x", name, end, c.MaxUserVA)
		}
	}
	if o != (platform.LayoutOverrides{}) {
		return memory.Layout{}, fmt.Errorf("android layout: layout overrides are reserved (P5+); only the zero value is supported")
	}
	return l, nil
}
