package android

import "github.com/isesword/golem/internal/kernel"

// NewSyscallTable returns the Android/AArch64 syscall dispatch table
// (asm-generic numbers -> kernel semantics handlers, plus trace names).
//
// The constructor itself lives in the kernel package
// (kernel.NewAndroidARM64Table) because kernel's internal test suite
// dispatches through the real table and Go forbids a package's internal test
// files from importing a package that imports it — android → kernel would be
// a test import cycle. This re-export keeps the composition root sourcing the
// table from the platform package alongside the transport and codecs.
func NewSyscallTable() *kernel.Table { return kernel.NewAndroidARM64Table() }
