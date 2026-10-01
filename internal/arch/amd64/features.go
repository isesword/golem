package amd64

import "github.com/isesword/golem/internal/arch"

// cpuFeatures is the AMD64 arch.CPUFeatures implementation . The feature
// set is EMPTY this stage — Has is always false and HWCAP encodes (0, 0) —
// mirroring the arm64 stage: advertise no optional CPU features. (Linux
// x86-64 AT_HWCAP is a glibc-internal bitmap with no Android consumer in
// golem's syscall surface; x86 CPU feature discovery happens through CPUID,
// which golem does not interpose.) When real HWCAP modeling lands, this type
// is the ONLY place the bitmap may live (single-source-of-truth rule).
type cpuFeatures struct{}

var _ arch.CPUFeatures = cpuFeatures{}

func (cpuFeatures) Has(arch.Feature) bool { return false }

func (cpuFeatures) HWCAP() (hwcap, hwcap2 uint64) { return 0, 0 }
