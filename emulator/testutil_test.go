package emulator

import (
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform/android"
	"github.com/isesword/golem/internal/vfs"
)

// newTestEmulator builds an Emulator for unit tests with the full platform
// personality injected — resolved ABI, cached role registers, and a kernel
// Context carrying the Android/AArch64 syscall transport, dispatch table and
// struct codecs exactly as New wires them (P2: no test may rely on zero-value
// coincidences; a bare &Emulator{} has a nil transport/table and its first
// guest syscall would panic). be may be nil for tests that never touch the
// backend (e.g. JNI clock tests).
func newTestEmulator(t *testing.T, be emu.Backend) *Emulator {
	t.Helper()
	abi, err := arch.Resolve(arch.IDARM64, arch.VariantGeneric)
	if err != nil {
		t.Fatal(err)
	}
	mem := memory.NewSpace()
	fs := vfs.New(t.TempDir(), defaultPid, "testproc")
	e := &Emulator{
		be:          be,
		abi:         abi,
		mem:         mem,
		fs:          fs,
		layout:      legacyARM64Layout,
		stubs:       map[uint64]string{},
		stubHits:    map[string]int{},
		hostByName:  map[string]hostFn{},
		hostImpl:    map[uint64]hostFn{},
		replaced:    map[uint64]hostFn{},
		jniDispatch: map[uint64]int{},
		kctx: &kernel.Context{
			B: be, Mem: mem, VFS: fs, Pid: defaultPid,
			Transport: android.LinuxARM64Transport{},
			Table:     android.NewSyscallTable(),
			Codecs:    android.AsmGenericLP64Codecs{},
		},
	}
	e.cacheRoleRegs()
	return e
}
