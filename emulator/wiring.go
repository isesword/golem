package emulator

// Composition-root wiring (P3): the emulator is where the loader's
// registries get populated for the supported targets. The loader facade
// (Parse/CompileOnce/Plan) dispatches through these registrations; neither
// loader nor its subpackages may import emulator.
import (
	_ "github.com/isesword/golem/internal/loader/elf"       // FormatELF parser
	_ "github.com/isesword/golem/internal/loader/elf/arm64" // (FormatELF, ArchARM64) relocator
	_ "github.com/isesword/golem/internal/loader/elf/amd64" // (FormatELF, ArchAMD64) relocator (P5a)

	// P5a: register the AMD64 (Arch, CallABI, StubEncoder, CPUFeatures) quad.
	// (The ARM64 quad arrives via debugger.go's functional import.) Note the
	// emulator's own boot flow is still ARM64-shaped this stage (LR-sentinel
	// call setup, svc trap handler) — the registration only makes
	// arch.Resolve(IDAMD64) answer; AMD64 assembly is proven component-level
	// in platform/android's acceptance-chain test.
	_ "github.com/isesword/golem/internal/arch/amd64"
)
