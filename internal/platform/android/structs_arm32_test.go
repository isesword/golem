package android

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// TestARM32Stat64Layout pins the ARM32 stat64 layout byte-exactly (the
// "layout verified" test): st_mode@16, st_size@48 (8-aligned long long, NOT
// 44 — the EABI padding after __pad3 is the classic off-by-4 bug), u32
// st_blksize@56, st_blocks@64, total size 104.
func TestARM32Stat64Layout(t *testing.T) {
	c := LinuxARM32Codecs{}
	if c.StatSize() != 104 {
		t.Fatalf("StatSize = %d, want 104 (ARM32 stat64)", c.StatSize())
	}
	buf := make([]byte, c.StatSize())
	if err := c.EncodeStat(buf, kernel.Stat{Mode: 0x81a4, Size: 0x1122334455}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(buf[16:]); got != 0x81a4 {
		t.Fatalf("st_mode @16 = %#x, want 0x81a4", got)
	}
	if got := binary.LittleEndian.Uint64(buf[48:]); got != 0x1122334455 {
		t.Fatalf("st_size @48 = %#x, want 0x1122334455", got)
	}
	// Nothing may leak into the implicit alignment padding @44..47.
	for i := 44; i < 48; i++ {
		if buf[i] != 0 {
			t.Fatalf("byte %d (st_size alignment padding) = %#x, want 0", i, buf[i])
		}
	}
	if got := binary.LittleEndian.Uint32(buf[56:]); got != 0x1000 {
		t.Fatalf("st_blksize @56 = %#x, want 0x1000", got)
	}
	if got := binary.LittleEndian.Uint64(buf[64:]); got != (0x1122334455+511)/512 {
		t.Fatalf("st_blocks @64 = %#x, want derived blocks", got)
	}
	// st_ino @96 is left zero by the encoder but must be inside the struct.
	if len(buf) != 104 {
		t.Fatalf("encoded %d bytes, want 104", len(buf))
	}
}

// TestARM32TimespecTimevalAreILP32 pins the 32-bit time_t encodings: two
// int32 fields, 8 bytes each — NOT the LP64 16-byte shape.
func TestARM32TimespecTimevalAreILP32(t *testing.T) {
	c := LinuxARM32Codecs{}
	if c.TimespecSize() != 8 || c.TimevalSize() != 8 {
		t.Fatalf("sizes = %d/%d, want 8/8 (ILP32)", c.TimespecSize(), c.TimevalSize())
	}
	buf := make([]byte, 8)
	if err := c.EncodeTimespec(buf, kernel.Timespec{Sec: 0x01020304, Nsec: 0x05060708}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(buf[0:]) != 0x01020304 || binary.LittleEndian.Uint32(buf[4:]) != 0x05060708 {
		t.Fatalf("timespec = %v, want two int32 fields", buf)
	}
	if err := c.EncodeTimeval(buf, kernel.Timeval{Sec: 0x01020304, Usec: 999999}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(buf[0:]) != 0x01020304 || binary.LittleEndian.Uint32(buf[4:]) != 999999 {
		t.Fatalf("timeval = %v, want two int32 fields", buf)
	}
}

// TestARM32SysinfoLayout pins the ILP32 sysinfo layout: uptime@0, totalram@16,
// freeram@20, procs@40, mem_unit@52, 64 bytes — plus the u32 saturation of
// RAM values that do not fit a 32-bit unsigned long.
func TestARM32SysinfoLayout(t *testing.T) {
	c := LinuxARM32Codecs{}
	if c.SysinfoSize() != 64 {
		t.Fatalf("SysinfoSize = %d, want 64 (ILP32 sysinfo)", c.SysinfoSize())
	}
	buf := make([]byte, c.SysinfoSize())
	err := c.EncodeSysinfo(buf, kernel.Sysinfo{
		UptimeSec: 1234, TotalRAM: 4 << 30, FreeRAM: 2 << 30, Procs: 64, MemUnit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(buf[0:]); got != 1234 {
		t.Fatalf("uptime @0 = %d, want 1234", got)
	}
	// 4 GiB does not fit a u32 at mem_unit=1: saturated, not wrapped to 0.
	if got := binary.LittleEndian.Uint32(buf[16:]); got != 0xffffffff {
		t.Fatalf("totalram @16 = %#x, want 0xffffffff (saturated)", got)
	}
	if got := binary.LittleEndian.Uint32(buf[20:]); got != 2<<30 {
		t.Fatalf("freeram @20 = %#x, want 2 GiB", got)
	}
	if got := binary.LittleEndian.Uint16(buf[40:]); got != 64 {
		t.Fatalf("procs @40 = %d, want 64", got)
	}
	if got := binary.LittleEndian.Uint32(buf[52:]); got != 1 {
		t.Fatalf("mem_unit @52 = %d, want 1", got)
	}
}

// TestARM32RlimitIsRlimit64 pins that prlimit64's rlimit64 (two u64) is used
// even on 32-bit ARM — the *64 syscall fixes the field width cross-arch.
func TestARM32RlimitIsRlimit64(t *testing.T) {
	c := LinuxARM32Codecs{}
	if c.RlimitSize() != 16 {
		t.Fatalf("RlimitSize = %d, want 16 (rlimit64)", c.RlimitSize())
	}
	buf := make([]byte, 16)
	if err := c.EncodeRlimit(buf, kernel.Rlimit{Cur: 8 << 20, Max: ^uint64(0)}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(buf[0:]) != 8<<20 || binary.LittleEndian.Uint64(buf[8:]) != ^uint64(0) {
		t.Fatalf("rlimit = %v, want two u64 (RLIM_INFINITY = -1 untruncated)", buf)
	}
}

// TestARM32IovecLayout pins the ILP32 iovec: {u32 base, u32 len}, 8 bytes.
func TestARM32IovecLayout(t *testing.T) {
	c := LinuxARM32Codecs{}
	if c.IovecSize() != 8 {
		t.Fatalf("IovecSize = %d, want 8", c.IovecSize())
	}
	var src [8]byte
	binary.LittleEndian.PutUint32(src[0:], 0xbeef0000)
	binary.LittleEndian.PutUint32(src[4:], 0x1234)
	iv, err := c.DecodeIovec(src[:])
	if err != nil {
		t.Fatal(err)
	}
	if iv.Base != 0xbeef0000 || iv.Len != 0x1234 {
		t.Fatalf("iovec = %+v, want {0xbeef0000, 0x1234}", iv)
	}
	if _, err := c.DecodeIovec(src[:7]); err == nil {
		t.Fatal("short buffer must error")
	}
}

// TestARM32StatxSameFixedABI: statx is a fixed cross-arch layout — the
// ARM32 encoder must agree with the LP64 one byte for byte.
func TestARM32StatxSameFixedABI(t *testing.T) {
	s := kernel.Statx{Mask: 0xfff, Blksize: 0x1000, Nlink: 3, Mode: 0x81a4, Size: 12345, Blocks: 25}
	a := make([]byte, 256)
	b := make([]byte, 256)
	if err := (LinuxARM32Codecs{}).EncodeStatx(a, s); err != nil {
		t.Fatal(err)
	}
	if err := (AsmGenericLP64Codecs{}).EncodeStatx(b, s); err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("statx byte %d: arm32=%#x lp64=%#x — the fixed statx ABI drifted", i, a[i], b[i])
		}
	}
}
