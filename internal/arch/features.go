package arch

// Feature identifies one CPU capability the guest may probe — the abstract
// vocabulary behind the Linux auxv AT_HWCAP/AT_HWCAP2 bitmaps (ARM64:
// HWCAP_FP/HWCAP_ASIMD/...; the concrete bit assignments belong to each arch
// implementation package). deliberately does NOT model the full feature
// set (DESIGN.md §8 YAGNI: "CPUFeatures 全量建模" is out of scope); the type
// exists so the single-source-of-truth contract has something to name.
type Feature uint32

// CPUFeatures is the arch layer's single source of truth for the CPU
// capability bits a guest can observe (DESIGN.md §6): it answers
// Has(feature) and encodes the Linux auxv AT_HWCAP/AT_HWCAP2 bitmaps. Any
// auxv/getauxval path (platform.StartupABI, an interposed getauxval) must
// derive its HWCAP values from here — a second, independently hardcoded
// bitmap is forbidden (red line: no two feature sources of truth).
//
// A CPUFeatures value is produced once per Target by arch.Resolve and carried
// in target.Target.Features; it is immutable thereafter.
type CPUFeatures interface {
	// Has reports whether the CPU advertises capability f.
	Has(f Feature) bool

	// HWCAP encodes the feature set as the Linux auxv AT_HWCAP / AT_HWCAP2
	// bitmaps (the arch implementation owns the bit assignments).
	HWCAP() (hwcap, hwcap2 uint64)
}
