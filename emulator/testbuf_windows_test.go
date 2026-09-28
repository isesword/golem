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
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), size), nil
}
