package arm64

import "github.com/isesword/golem/internal/arch"

// cpuFeatures is the AArch64 arch.CPUFeatures implementation . The
// feature set is EMPTY this stage — Has is always false and HWCAP encodes
// (0, 0) — which preserves the legacy behavior bit for bit: the interposed
// getauxval has always answered AT_HWCAP=0 / AT_HWCAP2=0 ("advertise no
// optional CPU features"). Modeling real ARM64 HWCAP bits (HWCAP_FP,
// HWCAP_ASIMD, ...) is explicitly out of scope (DESIGN.md §8 YAGNI); when it
// lands, this type is the ONLY place the bitmap may live.
type cpuFeatures struct{}

var _ arch.CPUFeatures = cpuFeatures{}

func (cpuFeatures) Has(arch.Feature) bool { return false }

func (cpuFeatures) HWCAP() (hwcap, hwcap2 uint64) { return 0, 0 }
