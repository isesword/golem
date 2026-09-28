//go:build unicorn && (darwin || linux)

package emu

import (
	"github.com/ebitengine/purego"
)

// loadLibrary loads a dynamic library by path (dlopen). POSIX: purego.
func loadLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

// findSymbol resolves an exported symbol (dlsym).
func findSymbol(handle uintptr, name string) (uintptr, error) {
	return purego.Dlsym(handle, name)
}
