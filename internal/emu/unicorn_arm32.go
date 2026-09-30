//go:build unicorn

// ARM32 (armv7) support for the unicorn backend (P6b): engine creation
// constants, the UC_ARM_REG_* translation table, and the CP15 thread-pointer
// register path.
//
// The UC constant values below are pinned against unicorn2's
// include/unicorn/unicorn.h and include/unicorn/arm.h — machine-derived from
// the installed headers (the enum has comment gaps; never infer by line
// number) and verified by live-engine tests (TestUnicornARM32*): a wrong reg
// id fails uc_reg_read/write loudly, and the TLS test reads it back through
// guest mrc.
//
// ISA state: uc_open takes UC_MODE_ARM (the RESET state); Thumb entry is by
// the START ADDRESS bit0 (uc_emu_start with an odd begin executes Thumb) —
// the classic unicorn ARM contract, probed and pinned by
// TestUnicornARM32ThumbEntry. The arch side (arm32.setPCBX) keeps CPSR.T
// consistent at every control transfer it performs.
package emu

const (
	ucArchARM   = 1      // UC_ARCH_ARM
	ucModeThumb = 1 << 4 // UC_MODE_THUMB (uc_open mode; NOT how golem enters Thumb — see the header)

	// UC_ARM_REG_* values used by the ARM32 mapping.
	ucArmRegCPSR   = 3
	ucArmRegLR     = 10
	ucArmRegPC     = 11
	ucArmRegSP     = 12
	ucArmRegR0     = 66  // R0..R12 contiguous: 66..78
	ucArmRegC13C03 = 113 // UC_ARM_REG_C13_C0_3 — TPIDRURW (deprecated upstream in favor of UC_ARM_REG_CP_REG; functional, verified live)
)

// regMapARM32 translates an abstract emu.Reg to its UC_ARM_REG_* id. It keys
// on the id NUMBERS internal/arch/arm32 assigns (R0=96 .. R15=111, CPSR=112,
// TPIDRURW=113 — emu cannot import that package: arm32 imports emu for
// emu.Reg, the reverse would be an import cycle). arch/arm32's
// TestFrozenRegIDs pins those numbers, so any drift fails tests loudly
// instead of corrupting registers. Note R13/R14/R15 map to unicorn's
// SP/LR/PC ids (aliases there, exactly as arm32's SP/LR/PC alias R13/R14/R15).
func regMapARM32(r Reg) int32 {
	switch {
	case r >= 96 && r <= 108: // arm32.R0 .. arm32.R12
		return ucArmRegR0 + int32(r-96)
	case r == 109: // arm32.R13 (SP)
		return ucArmRegSP
	case r == 110: // arm32.R14 (LR)
		return ucArmRegLR
	case r == 111: // arm32.R15 (PC)
		return ucArmRegPC
	case r == 112: // arm32.CPSR
		return ucArmRegCPSR
	case r == 113: // arm32.TPIDRURW (CP15 c13,c0,3)
		return ucArmRegC13C03
	default: // every unassigned id (negative, arm64's 0..17, amd64's 64..83) — loud failure
		return ucRegInvalid
	}
}
