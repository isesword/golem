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
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), size), nil
}
