package android

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/kernel"
)

// LinuxX8664Codecs encodes/decodes the guest ABI structures in the Linux
// x86-64 UAPI layout. It is a SEPARATE implementation from
// AsmGenericLP64Codecs (ARM64) — not an alias — because the layouts were
// verified struct by struct and are NOT all identical:
//
//	struct          x86-64 UAPI                asm-generic LP64 (ARM64)
//	stat            st_nlink@16 (u64),          st_mode@16, st_nlink@20;
//	                st_mode@24, size 144        size 128           → DIFFERS
//	statx           256 bytes, fixed cross-arch ABI (arch/x86 has no own)  → same
//	timespec/timeval two 8-byte fields (LP64)                            → same
//	sysinfo         LP64 layout (uptime@0 .. mem_unit@104), 128 bytes    → same
//	rlimit          two rlim_t (unsigned long)                           → same
//	iovec           {void*, size_t} = 16 bytes                           → same
//
// (Sources: arch/x86/include/uapi/asm/stat.h, include/uapi/asm-generic/
// stat.h, include/uapi/linux/stat.h; both 64-bit little-endian LP64.)
// The identical bodies below are therefore a verified FACT about two ABIs,
// each stated at its own definition site — sharing one type would hide the
// stat difference behind a coincidence.
type LinuxX8664Codecs struct{}

var _ kernel.StructCodecs = LinuxX8664Codecs{}

func needX(dst []byte, n int) error {
	if len(dst) < n {
		return fmt.Errorf("codec: dst too small (%d < %d)", len(dst), n)
	}
	return nil
}

// struct stat, x86-64 UAPI: 144 bytes (st_nlink is a full unsigned long at
// offset 16, pushing st_mode to 24 — the asm-generic LP64 layout has them at
// 20/16 and totals 128 bytes).
func (LinuxX8664Codecs) StatSize() int { return 144 }

func (c LinuxX8664Codecs) EncodeStat(dst []byte, s kernel.Stat) error {
	if err := needX(dst, c.StatSize()); err != nil {
		return err
	}
	for i := range dst[:c.StatSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[24:], s.Mode)           // st_mode
	binary.LittleEndian.PutUint64(dst[48:], s.Size)           // st_size
	binary.LittleEndian.PutUint64(dst[56:], 0x1000)           // st_blksize (long)
	binary.LittleEndian.PutUint64(dst[64:], (s.Size+511)/512) // st_blocks
	return nil
}

// struct statx: 256 bytes, one fixed cross-architecture layout.
func (LinuxX8664Codecs) StatxSize() int { return 256 }

func (c LinuxX8664Codecs) EncodeStatx(dst []byte, s kernel.Statx) error {
	if err := needX(dst, c.StatxSize()); err != nil {
		return err
	}
	for i := range dst[:c.StatxSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[0:], s.Mask)    // stx_mask
	binary.LittleEndian.PutUint32(dst[4:], s.Blksize) // stx_blksize
	binary.LittleEndian.PutUint32(dst[16:], s.Nlink)  // stx_nlink
	binary.LittleEndian.PutUint16(dst[28:], s.Mode)   // stx_mode
	binary.LittleEndian.PutUint64(dst[40:], s.Size)   // stx_size
	binary.LittleEndian.PutUint64(dst[48:], s.Blocks) // stx_blocks
	return nil
}

// struct timespec, LP64: two 8-byte fields (time_t / long).
func (LinuxX8664Codecs) TimespecSize() int { return 16 }

func (c LinuxX8664Codecs) EncodeTimespec(dst []byte, t kernel.Timespec) error {
	if err := needX(dst, c.TimespecSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Nsec))
	return nil
}

// struct timeval, LP64: two 8-byte fields (time_t / suseconds_t).
func (LinuxX8664Codecs) TimevalSize() int { return 16 }

func (c LinuxX8664Codecs) EncodeTimeval(dst []byte, t kernel.Timeval) error {
	if err := needX(dst, c.TimevalSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Usec))
	return nil
}

// struct sysinfo, LP64 layout: uptime (long) @0, u64 loads @8.., totalram @32,
// freeram @40, procs (u16) @80, mem_unit (u32) @104; 128 bytes total.
func (LinuxX8664Codecs) SysinfoSize() int { return 128 }

func (c LinuxX8664Codecs) EncodeSysinfo(dst []byte, s kernel.Sysinfo) error {
	if err := needX(dst, c.SysinfoSize()); err != nil {
		return err
	}
	for i := range dst[:c.SysinfoSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint64(dst[0:], s.UptimeSec)
	binary.LittleEndian.PutUint64(dst[32:], s.TotalRAM)
	binary.LittleEndian.PutUint64(dst[40:], s.FreeRAM)
	binary.LittleEndian.PutUint16(dst[80:], s.Procs)
	binary.LittleEndian.PutUint32(dst[104:], s.MemUnit)
	return nil
}

// struct rlimit, LP64: two rlim_t (unsigned long, 8 bytes each).
func (LinuxX8664Codecs) RlimitSize() int { return 16 }

func (c LinuxX8664Codecs) EncodeRlimit(dst []byte, r kernel.Rlimit) error {
	if err := needX(dst, c.RlimitSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], r.Cur)
	binary.LittleEndian.PutUint64(dst[8:], r.Max)
	return nil
}

// struct iovec, LP64: {void *base; size_t len} — 16 bytes.
func (LinuxX8664Codecs) IovecSize() int { return 16 }

func (c LinuxX8664Codecs) DecodeIovec(src []byte) (kernel.Iovec, error) {
	if err := needX(src, c.IovecSize()); err != nil {
		return kernel.Iovec{}, err
	}
	return kernel.Iovec{
		Base: binary.LittleEndian.Uint64(src[0:]),
		Len:  binary.LittleEndian.Uint64(src[8:]),
	}, nil
}
