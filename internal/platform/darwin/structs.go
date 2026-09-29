package darwin

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/kernel"
)

// XNUARM64Codecs encodes/decodes the guest ABI structures golem's syscall
// handlers touch, in the XNU ARM64 (LP64, little-endian) layout. Every offset
// below is a layout fact owned by this package; kernel code only ever sees
// the semantic kernel.Stat/Timespec/... values.
//
// P5b reality check: the Darwin table (table.go) binds no syscall that
// touches a guest struct, so NONE of these codecs is exercised by the e2e
// acceptance chain. They are implemented for real — the interface demands the
// full set — but each layout is pinned by unit test here and re-verified the
// day a syscall consuming it gets bound ("随用随钉").
type XNUARM64Codecs struct{}

var _ kernel.StructCodecs = XNUARM64Codecs{}

func need(dst []byte, n int) error {
	if len(dst) < n {
		return fmt.Errorf("codec: dst too small (%d < %d)", len(dst), n)
	}
	return nil
}

// struct stat, XNU ARM64 (_DARWIN_FEATURE_64_BIT_INODE, LP64): 144 bytes.
// The offsets pinned here are the two the semantic kernel.Stat carries:
// st_mode (u16) @4 and st_size (i64) @96 — after st_dev@0, st_nlink@6,
// st_ino@8, st_uid@16, st_gid@20, st_rdev@24 and the four timespecs
// @32..@95.
func (XNUARM64Codecs) StatSize() int { return 144 }

func (c XNUARM64Codecs) EncodeStat(dst []byte, s kernel.Stat) error {
	if err := need(dst, c.StatSize()); err != nil {
		return err
	}
	for i := range dst[:c.StatSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint16(dst[4:], uint16(s.Mode)) // st_mode
	binary.LittleEndian.PutUint64(dst[96:], s.Size)        // st_size
	return nil
}

// struct statx is a LINUX-only structure — XNU has no statx syscall. A
// plausible LP64 layout is provided so the interface is complete; binding
// statx into the Darwin table would be the bug, not this codec.
func (XNUARM64Codecs) StatxSize() int { return 256 }

func (c XNUARM64Codecs) EncodeStatx(dst []byte, s kernel.Statx) error {
	if err := need(dst, c.StatxSize()); err != nil {
		return err
	}
	for i := range dst[:c.StatxSize()] {
		dst[i] = 0
	}
	binary.LittleEndian.PutUint32(dst[0:], s.Mask)
	binary.LittleEndian.PutUint32(dst[4:], s.Blksize)
	binary.LittleEndian.PutUint32(dst[16:], s.Nlink)
	binary.LittleEndian.PutUint16(dst[28:], s.Mode)
	binary.LittleEndian.PutUint64(dst[40:], s.Size)
	binary.LittleEndian.PutUint64(dst[48:], s.Blocks)
	return nil
}

// struct timespec, XNU LP64: two 8-byte fields (time_t / long) — same shape
// as Linux LP64.
func (XNUARM64Codecs) TimespecSize() int { return 16 }

func (c XNUARM64Codecs) EncodeTimespec(dst []byte, t kernel.Timespec) error {
	if err := need(dst, c.TimespecSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Nsec))
	return nil
}

// struct timeval, XNU LP64: two 8-byte fields (time_t / suseconds_t).
func (XNUARM64Codecs) TimevalSize() int { return 16 }

func (c XNUARM64Codecs) EncodeTimeval(dst []byte, t kernel.Timeval) error {
	if err := need(dst, c.TimevalSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Usec))
	return nil
}

// struct sysinfo is a LINUX-only structure — XNU has no sysinfo syscall
// (the Darwin equivalents are sysctl/mig host_info). Same "complete the
// interface" status as statx.
func (XNUARM64Codecs) SysinfoSize() int { return 128 }

func (c XNUARM64Codecs) EncodeSysinfo(dst []byte, s kernel.Sysinfo) error {
	if err := need(dst, c.SysinfoSize()); err != nil {
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

// struct rlimit, XNU LP64: two rlim_t (u64) — real XNU layout, 16 bytes.
func (XNUARM64Codecs) RlimitSize() int { return 16 }

func (c XNUARM64Codecs) EncodeRlimit(dst []byte, r kernel.Rlimit) error {
	if err := need(dst, c.RlimitSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], r.Cur)
	binary.LittleEndian.PutUint64(dst[8:], r.Max)
	return nil
}

// struct iovec, XNU LP64: {void *base; size_t len} — 16 bytes, the real XNU
// layout (and identical to Linux LP64, as both are pointer+size_t).
func (XNUARM64Codecs) IovecSize() int { return 16 }

func (c XNUARM64Codecs) DecodeIovec(src []byte) (kernel.Iovec, error) {
	if err := need(src, c.IovecSize()); err != nil {
		return kernel.Iovec{}, err
	}
	return kernel.Iovec{
		Base: binary.LittleEndian.Uint64(src[0:]),
		Len:  binary.LittleEndian.Uint64(src[8:]),
	}, nil
}
