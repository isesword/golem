//go:build windows

package emulator

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocTestSharedBuffer returns a page-aligned RW buffer for test shared
// pages (Windows: VirtualAlloc, zero-initialized like MAP_ANON).
func allocTestSharedBuffer(size int) ([]byte, error) {
	p, err := windows.VirtualAlloc(0, uintptr(size),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil || p == 0 {
		return nil, err
	}
	return unsafe.Slice((*byte)(osTestPointer(p)), size), nil
}

// osTestPointer: see loader.alloc_windows.go osPointer — same OS-address
// re-typing rationale, duplicated here because the packages are separate.
//
//go:noinline
func osTestPointer(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) }
