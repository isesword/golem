package emulator

// Composition-root wiring (P3): the emulator is where the loader's
// registries get populated for the supported targets. The loader facade
// (Parse/CompileOnce/Plan) dispatches through these registrations; neither
// loader nor its subpackages may import emulator.
import (
	_ "github.com/isesword/golem/internal/loader/elf"       // FormatELF parser
	_ "github.com/isesword/golem/internal/loader/elf/arm64" // (FormatELF, ArchARM64) relocator
	_ "github.com/isesword/golem/internal/loader/elf/amd64" // (FormatELF, ArchAMD64) relocator (P5a)

	// P5b: the Mach-O container — parser + (FormatMachO, ArchARM64)
	// relocator. Darwin boots are proven end-to-end by the unicorn-tagged
	// acceptance chain (boot_darwin_arm64_unicorn_test.go).
	_ "github.com/isesword/golem/internal/loader/macho"
	_ "github.com/isesword/golem/internal/loader/macho/arm64"

	// P5a: register the AMD64 (Arch, CallABI, StubEncoder, CPUFeatures) quad.
	// (The ARM64 quad arrives via debugger.go's functional import.)
	_ "github.com/isesword/golem/internal/arch/amd64"
)
