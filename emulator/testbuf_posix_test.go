//go:build !windows

package emulator

import "syscall"

// allocTestSharedBuffer returns a page-aligned RW buffer for test shared
// pages (POSIX: anonymous mmap).
func allocTestSharedBuffer(size int) ([]byte, error) {
	return syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
}
