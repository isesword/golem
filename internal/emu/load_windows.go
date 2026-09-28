//go:build unicorn && windows

package emu

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// loadLibrary loads a dynamic library by path. Windows: LoadLibrary via
// x/sys/windows — purego.Dlopen does not exist there (its dlfcn shim is
// POSIX-only by build constraint).
func loadLibrary(path string) (uintptr, error) {
	h, err := windows.LoadLibrary(path)
	if err != nil {
		return 0, err
	}
	return uintptr(h), nil
}

// findSymbol resolves an exported symbol (GetProcAddress).
func findSymbol(handle uintptr, name string) (uintptr, error) {
	p, err := windows.GetProcAddress(windows.Handle(handle), name)
	if err != nil || p == 0 {
		if err == nil {
			err = fmt.Errorf("symbol %q not found", name)
		}
		return 0, err
	}
	return uintptr(p), nil
}
