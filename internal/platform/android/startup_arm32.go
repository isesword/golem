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

// StartupABI32 is the ARM32 (ILP32) variant of the Android personality's
// platform.StartupABI (P6d). The auxv CONTENT rules are identical to the
// 64-bit StartupABI (same AT_* keys, HWCAP exclusively from
// StartupContext.Features, deterministic AT_RANDOM, data-block-not-exec-
// frame landing form — see startup.go for the rationale); the REAL
// difference is the pointer width on the wire:
//
//   - Elf32_auxv_t is {u32 a_type; u32 a_val} — 8-byte pairs, not 16.
//   - AT_RANDOM's pointer and every address value are 32-bit.
//
// A 32-bit guest reading a 16-byte-pair vector would mis-parse every second
// entry, so the two ABIs are separate implementations, each stating its own
// layout fact (the project rule: per-arch facts at their own definition
// site, never hidden behind a shared coincidence).
type StartupABI32 struct {
	auxv       []platform.AuxvEntry // the built vector, AT_NULL-terminated
	randomAddr emu.GuestAddr        // what AT_RANDOM points at
	blockAddr  emu.GuestAddr        // base of the materialized block (diagnostics)
	built      bool
}

var _ platform.StartupABI = (*StartupABI32)(nil)

// BuildInitialState builds the auxv vector (same entry set as the 64-bit
// StartupABI) and materializes it as 8-byte Elf32_auxv_t pairs plus the 16
// AT_RANDOM bytes at the top of the stack region. It must be called at most
// once per StartupABI32.
func (s *StartupABI32) BuildInitialState(ctx *platform.StartupContext) error {
	if s.built {
		return errors.New("android startup32: BuildInitialState called twice (auxv is built once per emulator)")
	}
	if ctx == nil {
		return errors.New("android startup32: nil StartupContext")
	}
	if ctx.Features == nil {
		return errors.New("android startup32: nil Features (arch.CPUFeatures is the only HWCAP source)")
	}
	if ctx.Mem == nil {
		return errors.New("android startup32: nil Mem writer")
	}
	if ctx.Stack.Size < StackTopReserve+0x100 {
		return fmt.Errorf("android startup32: stack region %#x+%#x too small for the auxv block", ctx.Stack.Addr, ctx.Stack.Size)
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
	//   [ auxv pairs (8 B each) ... | AT_NULL | 16 AT_RANDOM bytes ]
	// Everything is 8-byte units under a 16-aligned top, so the block base,
	// every pair, and the AT_RANDOM pointer are all (at least) 8-aligned.
	top := ctx.Stack.Addr + ctx.Stack.Size
	vecBytes := uint64(len(entries)+1) * 8 // +1: the AT_NULL terminator
	blockSize := vecBytes + 16
	blockAddr := top - StackTopReserve - blockSize
	if blockAddr < ctx.Stack.Addr {
		return fmt.Errorf("android startup32: auxv block (%#x bytes) does not fit below the SP reserve in stack %#x+%#x",
			blockSize, ctx.Stack.Addr, ctx.Stack.Size)
	}
	randomAddr := blockAddr + vecBytes
	entries[len(entries)-1].Val = randomAddr // patch AT_RANDOM

	block := make([]byte, blockSize) // AT_NULL pair stays zero
	for i, en := range entries {
		binary.LittleEndian.PutUint32(block[i*8:], uint32(en.Type))
		binary.LittleEndian.PutUint32(block[i*8+4:], uint32(en.Val))
	}
	kernel.DeterministicRandom(auxvRandomSeed, block[vecBytes:])
	if err := ctx.Mem.MemWrite(emu.GuestAddr(blockAddr), block); err != nil {
		return fmt.Errorf("android startup32: write auxv block at %#x: %w", blockAddr, err)
	}

	s.auxv = append(entries, platform.AuxvEntry{Type: atNull, Val: 0})
	s.randomAddr = emu.GuestAddr(randomAddr)
	s.blockAddr = emu.GuestAddr(blockAddr)
	s.built = true
	return nil
}

// Auxv returns the built auxv vector (AT_NULL-terminated), nil before
// BuildInitialState. The slice is shared — callers must not mutate it.
func (s *StartupABI32) Auxv() []platform.AuxvEntry { return s.auxv }

// ATRandom returns the guest pointer AT_RANDOM carries (16 readable bytes in
// the stack block), 0 before BuildInitialState.
func (s *StartupABI32) ATRandom() emu.GuestAddr { return s.randomAddr }

// Lookup is the getauxval semantics over the built vector: the value for tag
// t, or 0 when the vector carries no such entry.
func (s *StartupABI32) Lookup(t uint64) uint64 {
	for _, en := range s.auxv {
		if en.Type == t {
			return en.Val
		}
	}
	return 0
}
