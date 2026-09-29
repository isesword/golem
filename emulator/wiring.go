package emulator

// Composition-root wiring (P3): the emulator is where the loader's
// registries get populated for the Android/AArch64 target. The loader facade
// (Parse/CompileOnce/Plan) dispatches through these registrations; neither
// loader nor its subpackages may import emulator.
import (
	_ "github.com/isesword/golem/internal/loader/elf"       // FormatELF parser
	_ "github.com/isesword/golem/internal/loader/elf/arm64" // (FormatELF, ArchARM64) relocator
)
