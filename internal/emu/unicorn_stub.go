//go:build !unicorn

package emu

import "fmt"

// SetTCGBufferSize is the pure-Go-build stub for the unicorn engine's TCG
// buffer sizing (the real implementation lives in unicorn_purego.go behind
// the `unicorn` build tag). Keeping the symbol available in tagless builds
// lets emulator.New validate Config.TCGBufferMiB unconditionally: without
// the unicorn engine compiled in there is no TCG buffer to size, and the
// caller gets an explicit error instead of a silent no-op.
func SetTCGBufferSize(Backend, uint32) error {
	return fmt.Errorf("emu: TCG buffer sizing requires the unicorn engine (build with -tags unicorn)")
}
