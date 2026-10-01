package android

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// Linux auxv type numbers (ELF ABI; these values are part of the Linux user
// ABI, same source the legacy interposed getauxval hardcoded).
const (
	atNull   = 0
	atPhdr   = 3
	atPhnum  = 5
	atPagesz = 6
	atEntry  = 9
	atHwcap  = 16
	atSecure = 23
	atRandom = 25
	atHwcap2 = 26
)

// StackTopReserve is the headroom between the initial SP and the top of the
// stack mapping — the exact geometry the emulator booted with originally
// (SP = StackBase+StackSize-0x200). StartupABI owns this constant now
// (invariant 10: the initial process image is platform's): the boot sets SP
// from it, and BuildInitialState parks the auxv block just below it.
const StackTopReserve = 0x200

// auxvRandomSeed is the FIXED seed for the auxv AT_RANDOM 16 bytes: they come
// from kernel.DeterministicRandom — the same deterministic stream the
// getrandom syscall serves (one deterministic randomness source) — not
// from an ad-hoc per-site byte string. Fixed seed => reproducible across runs,
// exactly like the deterministic getrandom mode.
const auxvRandomSeed = 0x676F6C656D2D6164 // "golem-ad" (Android), little-endian ASCII

// StartupABI is the Android personality's platform.StartupABI (DESIGN.md
// §3.4/§6).
//
// Landing form — auxv DATA BLOCK, not an exec-style initial stack frame.
// golem loads .so files and calls their functions; it never execs a guest
// process, so bionic's __libc_init (the consumer of argc/argv/envp on the
// initial stack) never runs. What bionic initialization DOES consume in
// practice is getauxval() — interposed by the emulator (hostGetauxval). So
// BuildInitialState materializes the auxv vector plus the 16 AT_RANDOM bytes
// as a data block at the top of the (already mapped, already reserved) stack
// region, keeps the same vector host-side, and the interposed getauxval
// serves from it (emulator/hostfns.go) — ONE auxv source of truth, no
// per-key hardcoding left in the host function.
//
// The HWCAP/HWCAP2 bitmaps come exclusively from StartupContext.Features
// (arch.CPUFeatures, carried by the immutable Target). With the current empty
// arm64 feature set both are 0 — bit-identical to the legacy behavior.
type StartupABI struct {
	auxv       []platform.AuxvEntry // the built vector, AT_NULL-terminated
	randomAddr emu.GuestAddr        // what AT_RANDOM points at
	blockAddr  emu.GuestAddr        // base of the materialized block (diagnostics)
	built      bool
}

var _ platform.StartupABI = (*StartupABI)(nil)

// BuildInitialState builds the auxv vector from the loader's image metadata
// (PHDR/ENTRY) and the arch feature set (HWCAP) and writes it plus the
// AT_RANDOM bytes into the top of the stack region. It must be called at
// most once per StartupABI — the vector it builds is THE auxv for the
// emulator's lifetime.
//
// ctx.Image may be nil (bionic-only boot, no main module yet): AT_PHDR /
// AT_PHNUM / AT_ENTRY are then omitted and getauxval answers 0 for them, the
// legacy behavior for unknown keys. This lazy, metadata-less build is a
// deliberate decision, not an accident — see platform.StartupABI for the
// ordering rule.
func (s *StartupABI) BuildInitialState(ctx *platform.StartupContext) error {
	if s.built {
		return errors.New("android startup: BuildInitialState called twice (auxv is built once per emulator)")
	}
	if ctx == nil {
		return errors.New("android startup: nil StartupContext")
	}
	if ctx.Features == nil {
		return errors.New("android startup: nil Features (arch.CPUFeatures is the only HWCAP source)")
	}
	if ctx.Mem == nil {
		return errors.New("android startup: nil Mem writer")
	}
	if ctx.Stack.Size < StackTopReserve+0x100 {
		return fmt.Errorf("android startup: stack region %#x+%#x too small for the auxv block", ctx.Stack.Addr, ctx.Stack.Size)
	}

	hwcap, hwcap2 := ctx.Features.HWCAP()
	base := uint64(ctx.Base)
	var entries []platform.AuxvEntry
	if img := ctx.Image; img != nil {
		if img.PhdrAddr != 0 && img.PhdrNum > 0 {
			entries = append(entries,
				platform.AuxvEntry{Type: atPhdr, Val: base + img.PhdrAddr},
				platform.AuxvEntry{Type: atPhnum, Val: uint64(img.PhdrNum)},
			)
		}
		if img.Entry != 0 {
			entries = append(entries, platform.AuxvEntry{Type: atEntry, Val: base + img.Entry})
		}
	}
	entries = append(entries,
		platform.AuxvEntry{Type: atPagesz, Val: memory.PageSize},
		platform.AuxvEntry{Type: atHwcap, Val: hwcap},
		platform.AuxvEntry{Type: atHwcap2, Val: hwcap2},
		platform.AuxvEntry{Type: atSecure, Val: 0},
	)
	// AT_RANDOM's pointer is only known once the block's address is computed;
	// append a placeholder and patch it below, before materializing.
	entries = append(entries, platform.AuxvEntry{Type: atRandom, Val: 0})

	// Block layout, just below the initial-SP reserve at the stack top:
	//   [ auxv pairs ... | AT_NULL | 16 AT_RANDOM bytes ]
	// Everything is 16-byte units under a 16-aligned top, so the block base,
	// every pair, and the AT_RANDOM pointer are all 16-aligned.
	top := ctx.Stack.Addr + ctx.Stack.Size
	vecBytes := uint64(len(entries)+1) * 16 // +1: the AT_NULL terminator
	blockSize := vecBytes + 16
	blockAddr := top - StackTopReserve - blockSize
	if blockAddr < ctx.Stack.Addr {
		return fmt.Errorf("android startup: auxv block (%#x bytes) does not fit below the SP reserve in stack %#x+%#x",
			blockSize, ctx.Stack.Addr, ctx.Stack.Size)
	}
	randomAddr := blockAddr + vecBytes
	entries[len(entries)-1].Val = randomAddr // patch AT_RANDOM

	block := make([]byte, blockSize) // AT_NULL pair stays zero
	for i, en := range entries {
		binary.LittleEndian.PutUint64(block[i*16:], en.Type)
		binary.LittleEndian.PutUint64(block[i*16+8:], en.Val)
	}
	kernel.DeterministicRandom(auxvRandomSeed, block[vecBytes:])
	if err := ctx.Mem.MemWrite(emu.GuestAddr(blockAddr), block); err != nil {
		return fmt.Errorf("android startup: write auxv block at %#x: %w", blockAddr, err)
	}

	s.auxv = append(entries, platform.AuxvEntry{Type: atNull, Val: 0})
	s.randomAddr = emu.GuestAddr(randomAddr)
	s.blockAddr = emu.GuestAddr(blockAddr)
	s.built = true
	return nil
}

// Auxv returns the built auxv vector (AT_NULL-terminated), nil before
// BuildInitialState. The slice is shared — callers must not mutate it. The
// interposed getauxval serves from exactly this vector, so auxv data and the
// CPU-feature query can never drift apart (single source of truth).
func (s *StartupABI) Auxv() []platform.AuxvEntry { return s.auxv }

// ATRandom returns the guest pointer AT_RANDOM carries (16 readable bytes in
// the stack block), 0 before BuildInitialState.
func (s *StartupABI) ATRandom() emu.GuestAddr { return s.randomAddr }

// Lookup is the getauxval semantics over the built vector: the value for tag
// t, or 0 when the vector carries no such entry (the legacy default).
func (s *StartupABI) Lookup(t uint64) uint64 {
	for _, en := range s.auxv {
		if en.Type == t {
			return en.Val
		}
	}
	return 0
}
