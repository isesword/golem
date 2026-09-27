//go:build !windows

package loader

import "syscall"

// allocSharedBuffer returns a page-aligned, RW host buffer of the given size
// for uc_mem_map_ptr. POSIX: anonymous mmap (zero-initialized by definition).
func allocSharedBuffer(size int) ([]byte, error) {
	return syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
}

// hostPageSize returns the host page size for alignment assertions.
func hostPageSize() int { return syscall.Getpagesize() }
