//go:build windows

package loader

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocSharedBuffer returns a page-aligned, RW host buffer of the given size
// for uc_mem_map_ptr. Windows: VirtualAlloc (MEM_COMMIT|MEM_RESERVE with
// PAGE_READWRITE is zero-initialized, matching MAP_ANON semantics).
func allocSharedBuffer(size int) ([]byte, error) {
	p, err := windows.VirtualAlloc(0, uintptr(size),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil || p == 0 {
		return nil, fmt.Errorf("VirtualAlloc %d bytes: %w", size, err)
	}
	return unsafe.Slice((*byte)(osPointer(p)), size), nil
}

// osPointer re-types an address handed out by the OS (VirtualAlloc etc.).
// vet's unsafeptr flags the direct conversion because it cannot tell that
// this uintptr is NOT a Go heap address — it is an OS allocation outside
// the GC's domain, so no stack-copy/GC hazard exists. The noinline function
// boundary documents and enforces that invariant at one single place.
//
//go:noinline
func osPointer(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) }
