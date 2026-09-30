package arm32

import "github.com/isesword/golem/internal/arch"

// cpuFeatures is the ARM32 arch.CPUFeatures implementation (P6b). The
// feature set is EMPTY this stage — Has is always false and HWCAP encodes
// (0, 0) — mirroring amd64: advertise no optional CPU features. (ARM32
// Linux AT_HWCAP/AT_HWCAP2 bitmaps — HWCAP_NEON, HWCAP_ARMv7, ... — are a
// bionic/glibc discovery channel; modeling them is a platform-side
// decision, and when it lands this type is the ONLY place the bitmap may
// live, per the P4d single-source-of-truth rule.)
type cpuFeatures struct{}

var _ arch.CPUFeatures = cpuFeatures{}

func (cpuFeatures) Has(arch.Feature) bool { return false }

func (cpuFeatures) HWCAP() (hwcap, hwcap2 uint64) { return 0, 0 }
