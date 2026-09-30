package android

import (
	"encoding/binary"
	"fmt"

	"github.com/isesword/golem/internal/kernel"
)

// AsmGenericLP64Codecs encodes/decodes the guest ABI structures golem's
// syscall handlers touch, in the Linux asm-generic LP64 layout used by
// AArch64 (and, incidentally, AMD64) Android: 8-byte longs/pointers,
// little-endian. Every offset below is a layout fact owned by this package;
// kernel code only ever sees the semantic kernel.Stat/Timespec/... values.
//
// The set is exactly what the handlers use (DESIGN.md invariant 7):
// stat/statx/timespec/timeval/sysinfo/rlimit encode, iovec decode. utsname is
// deliberately absent — its 6×65-byte layout is fixed across Linux
// architectures, so it is not ABI-layout dependent and stays inline in
// kernel.SysUname.
type AsmGenericLP64Codecs struct{}

var _ kernel.StructCodecs = AsmGenericLP64Codecs{}

func need(dst []byte, n int) error {
	if len(dst) < n {
		return fmt.Errorf("codec: dst too small (%d < %d)", len(dst), n)
	}
	return nil
}

// struct stat, asm-generic LP64: 128 bytes.
func (AsmGenericLP64Codecs) StatSize() int { return 128 }

func (c AsmGenericLP64Codecs) EncodeStat(dst []byte, s kernel.Stat) error {
	if err := need(dst, c.StatSize()); err != nil {
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

// struct statx, asm-generic LP64: 256 bytes.
func (AsmGenericLP64Codecs) StatxSize() int { return 256 }

func (c AsmGenericLP64Codecs) EncodeStatx(dst []byte, s kernel.Statx) error {
	if err := need(dst, c.StatxSize()); err != nil {
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
func (AsmGenericLP64Codecs) TimespecSize() int { return 16 }

func (c AsmGenericLP64Codecs) EncodeTimespec(dst []byte, t kernel.Timespec) error {
	if err := need(dst, c.TimespecSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Nsec))
	return nil
}

// struct timeval, LP64: two 8-byte fields (time_t / suseconds_t).
func (AsmGenericLP64Codecs) TimevalSize() int { return 16 }

func (c AsmGenericLP64Codecs) EncodeTimeval(dst []byte, t kernel.Timeval) error {
	if err := need(dst, c.TimevalSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], uint64(t.Sec))
	binary.LittleEndian.PutUint64(dst[8:], uint64(t.Usec))
	return nil
}

// struct sysinfo, LP64 layout: uptime (long) @0, u64 loads @8.., totalram @32,
// freeram @40, procs (u16) @80, mem_unit (u32) @104; 128 bytes total.
func (AsmGenericLP64Codecs) SysinfoSize() int { return 128 }

func (c AsmGenericLP64Codecs) EncodeSysinfo(dst []byte, s kernel.Sysinfo) error {
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

// struct rlimit, LP64: two rlim_t (unsigned long, 8 bytes each).
func (AsmGenericLP64Codecs) RlimitSize() int { return 16 }

func (c AsmGenericLP64Codecs) EncodeRlimit(dst []byte, r kernel.Rlimit) error {
	if err := need(dst, c.RlimitSize()); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(dst[0:], r.Cur)
	binary.LittleEndian.PutUint64(dst[8:], r.Max)
	return nil
}

// struct iovec, LP64: {void *base; size_t len} — 16 bytes.
func (AsmGenericLP64Codecs) IovecSize() int { return 16 }

func (c AsmGenericLP64Codecs) DecodeIovec(src []byte) (kernel.Iovec, error) {
	if err := need(src, c.IovecSize()); err != nil {
		return kernel.Iovec{}, err
	}
	return kernel.Iovec{
		Base: binary.LittleEndian.Uint64(src[0:]),
		Len:  binary.LittleEndian.Uint64(src[8:]),
	}, nil
}
