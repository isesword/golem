package emu

// Test-only aliases for the arch/arm64 register ids. Test files in this
// package cannot import internal/arch/arm64 — that package imports emu (for
// emu.Reg), so the test import would be an import cycle — hence the few ids
// the backend tests need are restated here. arch/arm64's TestFrozenRegIDs
// pins the numbers, so a drift fails tests there.
const (
	regX0 = Reg(0) // arm64.X0
	regX1 = Reg(1) // arm64.X1
	regX2 = Reg(2) // arm64.X2
)
