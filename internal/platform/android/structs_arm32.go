package android

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/kernel"
)

// LinuxARM32Codecs encodes/decodes the guest ABI structures golem's syscall
// handlers touch, in the Linux ARM32 (armv7 EABI, ILP32) UAPI layout:
// 4-byte longs/pointers, 8-byte-aligned long long, little-endian. It is a
// SEPARATE implementation from AsmGenericLP64Codecs / LinuxX8664Codecs — the
// layouts were verified struct by struct against the kernel UAPI headers
// :
//
//	struct          ARM32 UAPI (ILP32)                                    vs 64-bit
//	stat (stat64)   st_mode@16, st_size@48, st_blksize@56 (u32),    → DIFFERS
//	                st_blocks@64, st_ino@96; 104 bytes total
//	                (arch/arm/include/uapi/asm/stat.h struct stat64 —
//	                fstat64/fstatat64; the old 32-bit-ino struct stat
//	                is not what bionic uses)
//	statx           256 bytes, fixed cross-arch ABI                    → same
//	timespec        two int32 (32-bit time_t), 8 bytes                 → DIFFERS
//	timeval         two int32, 8 bytes                                 → DIFFERS
//	sysinfo         ILP32: uptime@0, totalram@16, freeram@20,          → DIFFERS
//	                procs@40, mem_unit@52; 64 bytes total
//	rlimit          prlimit64 carries struct rlimit64 = two u64        → same
//	iovec           {u32 base, u32 len}, 8 bytes                       → DIFFERS
//
// (Sources: arch/arm/include/uapi/asm/stat.h, include/uapi/linux/stat.h,
// include/uapi/linux/sysinfo.h, include/uapi/linux/resource.h.)
type LinuxARM32Codecs struct{}

var _ kernel.StructCodecs = LinuxARM32Codecs{}

func need32(dst []byte, n int) error {
	if len(dst) < n {
		return fmt.Errorf("codec: dst too small (%d < %d)", len(dst), n)
	}
	return nil
}

// struct stat64, ARM32 UAPI: 104 bytes. st_size sits at 48 (not 44): the
// EABI aligns long long to 8, so __pad3 (ending at 44) is followed by 4
// bytes of implicit alignment padding.
func (LinuxARM32Codecs) StatSize() int { return 104 }

func (c LinuxARM32Codecs) EncodeStat(dst []byte, s kernel.Stat) error {
	if err := need32(dst, c.StatSize()); err != nil {
		return err
	}
	for i := range dst[:c.StatSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[16:], s.Mode)           // st_mode
	binary.LittleEndian.PutUint64(dst[48:], s.Size)           // st_size
	binary.LittleEndian.PutUint32(dst[56:], 0x1000)           // st_blksize
	binary.LittleEndian.PutUint64(dst[64:], (s.Size+511)/512) // st_blocks
	return nil
}

// struct statx: 256 bytes, one fixed cross-architecture layout (statx is a
// modern syscall with a single ABI — identical to the LP64 encoding, stated
// here independently like LinuxX8664Codecs does).
func (LinuxARM32Codecs) StatxSize() int { return 256 }

func (c LinuxARM32Codecs) EncodeStatx(dst []byte, s kernel.Statx) error {
	if err := need32(dst, c.StatxSize()); err != nil {
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

// struct timespec, ARM32: two int32 (32-bit time_t / long) — 8 bytes.
func (LinuxARM32Codecs) TimespecSize() int { return 8 }

func (c LinuxARM32Codecs) EncodeTimespec(dst []byte, t kernel.Timespec) error {
	if err := need32(dst, c.TimespecSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(dst[0:], uint32(int32(t.Sec)))
	binary.LittleEndian.PutUint32(dst[4:], uint32(int32(t.Nsec)))
	return nil
}

// struct timeval, ARM32: two int32 (time_t / suseconds_t) — 8 bytes.
func (LinuxARM32Codecs) TimevalSize() int { return 8 }

func (c LinuxARM32Codecs) EncodeTimeval(dst []byte, t kernel.Timeval) error {
	if err := need32(dst, c.TimevalSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(dst[0:], uint32(int32(t.Sec)))
	binary.LittleEndian.PutUint32(dst[4:], uint32(int32(t.Usec)))
	return nil
}

// struct sysinfo, ARM32 ILP32 layout: uptime (long) @0, u32 loads @4/8/12,
// totalram @16, freeram @20, procs (u16) @40, mem_unit (u32) @52; 64 bytes
// total (include/uapi/linux/sysinfo.h with 4-byte longs).
//
// 32-bit caveat: the RAM fields are unsigned long — 4 GiB at mem_unit=1 does
// not fit. Values that would overflow are SATURATED to 0xffffffff (a 32-bit
// device reporting "3+ GiB" is more plausible to libc heuristics than a
// wraparound to 0).
func (LinuxARM32Codecs) SysinfoSize() int { return 64 }

func (c LinuxARM32Codecs) EncodeSysinfo(dst []byte, s kernel.Sysinfo) error {
	if err := need32(dst, c.SysinfoSize()); err != nil {
		return err
	}
	for i := range dst[:c.SysinfoSize()] {
		dst[i] = 0
	}
	sat := func(v uint64) uint32 {
		if v > 0xffffffff {
			return 0xffffffff
		}
		return uint32(v)
	}
	binary.LittleEndian.PutUint32(dst[0:], uint32(s.UptimeSec))
	binary.LittleEndian.PutUint32(dst[16:], sat(s.TotalRAM))
	binary.LittleEndian.PutUint32(dst[20:], sat(s.FreeRAM))
	binary.LittleEndian.PutUint16(dst[40:], s.Procs)
	binary.LittleEndian.PutUint32(dst[52:], s.MemUnit)
	return nil
}

// struct rlimit64 (prlimit64): two u64 rlim64_t — the *64 syscall fixes the
// width cross-architecture, so this is byte-identical to the LP64 rlimit
// encoding (stated independently: the 32-bit plain struct rlimit, two u32,
// is NOT what prlimit64 carries).
func (LinuxARM32Codecs) RlimitSize() int { return 16 }

func (c LinuxARM32Codecs) EncodeRlimit(dst []byte, r kernel.Rlimit) error {
	if err := need32(dst, c.RlimitSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], r.Cur)
	binary.LittleEndian.PutUint64(dst[8:], r.Max)
	return nil
}

// struct iovec, ARM32: {u32 base, u32 len} — 8 bytes.
func (LinuxARM32Codecs) IovecSize() int { return 8 }

func (c LinuxARM32Codecs) DecodeIovec(src []byte) (kernel.Iovec, error) {
	if err := need32(src, c.IovecSize()); err != nil {
		return kernel.Iovec{}, err
	}
	return kernel.Iovec{
		Base: uint64(binary.LittleEndian.Uint32(src[0:])),
		Len:  uint64(binary.LittleEndian.Uint32(src[4:])),
	}, nil
}
