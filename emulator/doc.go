// Package emulator is golem's public facade: load a native library, call
// its functions, hook them, and inspect guest state — without naming a
// single architecture-specific register.
//
// # Portable API (default)
//
// Express WHAT you want to know; the same code runs on ARM64, ARM32 and
// AMD64:
//
//	ret, err := e.CallSymbol("nativeEncrypt",
//		emulator.Ptr(input),       // guest pointer
//		emulator.Words(n)...)      // plain word arguments
//
//	_ = e.ReplaceSymbol("md5_update", func(h *emulator.Hook) uint64 {
//		src, _ := h.Arg(0)             // ABI argument (entry hooks only)
//		caller, _ := h.ReturnAddress() // per-convention: X30 / R14 / [RSP]
//		fmt.Println(src.Raw, caller)
//		return 0
//	})
//
//	lr, err := h.ReadRole(emulator.RoleLR) // CPU observation, any hook kind
//
// Entry-scoped questions (Arg, ReturnAddress, ReturnValue) are answerable
// only where the ABI defines them (function-entry / function-exit hooks);
// anywhere else they fail with ErrContextUnavailable instead of guessing.
// Role reads (ReadRole) are CPU-state observation and work at any PC; a
// role the architecture lacks (AMD64 has no link register) answers
// ErrUnsupportedRole.
//
// # Advanced API (architecture-specific, not portable)
//
//	RegRead / RegWrite        // abstract register ids (per-arch numbering)
//	Reg(i)                    // register-FILE index dump (arm64 order)
//	ReadRole vs raw ids       // see internal/arch — internal on purpose
//	Backend-level memory ops  // via Hook.Emu() helpers or raw addresses
//
// Advanced callers own architecture binding: switching target arch may
// change what these return, and the code must be re-verified. The arch
// packages that define register identities are internal — a deliberate
// boundary: raw ids are stable within a release, not a public contract.
//
// # Layering
//
//	emulator (this package, Portable + Advanced)
//	  → internal/arch (CallABI, register roles)   ← observation semantics
//	  → internal/emu  (Backend + capabilities)     ← frozen core
//	  → internal/{loader,kernel,memory,platform}   ← frozen core
package emulator
