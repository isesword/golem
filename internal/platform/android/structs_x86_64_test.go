package android

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// TestX8664StatLayout pins the x86-64 UAPI struct stat layout — the ONE
// struct that differs from asm-generic LP64 (ARM64): st_nlink is a full
// unsigned long at offset 16, st_mode sits at 24, and the total size is 144
// (vs mode@16/nlink@20/128 on asm-generic). This difference is exactly why
// LinuxX8664Codecs is a separate implementation, not a shared codec.
func TestX8664StatLayout(t *testing.T) {
	c := LinuxX8664Codecs{}
	if c.StatSize() != 144 {
		t.Fatalf("StatSize = %d, want 144 (x86-64 UAPI)", c.StatSize())
	}
	buf := make([]byte, c.StatSize())
	if err := c.EncodeStat(buf, kernel.Stat{Mode: 0x81a4, Size: 0x1234}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(buf[24:]); got != 0x81a4 {
		t.Fatalf("st_mode @24 = %#x, want 0x81a4", got)
	}
	if got := binary.LittleEndian.Uint64(buf[48:]); got != 0x1234 {
		t.Fatalf("st_size @48 = %#x, want 0x1234", got)
	}
	if got := binary.LittleEndian.Uint64(buf[56:]); got != 0x1000 {
		t.Fatalf("st_blksize @56 = %#x, want 0x1000", got)
	}
	if got := binary.LittleEndian.Uint64(buf[64:]); got != (0x1234+511)/512 {
		t.Fatalf("st_blocks @64 = %d, want %d", got, (0x1234+511)/512)
	}
	// The asm-generic offsets must be ZERO here — proof the layouts differ.
	if got := binary.LittleEndian.Uint32(buf[16:]); got != 0 {
		t.Fatalf("offset 16 (asm-generic st_mode) = %#x, want 0 — x86-64 keeps st_nlink there", got)
	}
}

// TestX8664SharedLayoutsMatchAsmGeneric pins the verified-identical structs:
// statx/timespec/timeval/sysinfo/rlimit/iovec encode byte-for-byte the same
// under both codecs (the sharing is a verified fact, not an alias).
func TestX8664SharedLayoutsMatchAsmGeneric(t *testing.T) {
	x := LinuxX8664Codecs{}
	g := AsmGenericLP64Codecs{}

	encode := func(t *testing.T, name string, szX, szG int, ex, eg func([]byte) error) {
		t.Helper()
		if szX != szG {
			t.Fatalf("%s size: x86-64=%d asm-generic=%d, want equal", name, szX, szG)
		}
		bx, bg := make([]byte, szX), make([]byte, szG)
		if err := ex(bx); err != nil {
			t.Fatalf("%s x86-64 encode: %v", name, err)
		}
		if err := eg(bg); err != nil {
			t.Fatalf("%s asm-generic encode: %v", name, err)
		}
		if !bytes.Equal(bx, bg) {
			t.Fatalf("%s: x86-64 and asm-generic encodings differ\n x86: %x\n agen: %x", name, bx, bg)
		}
	}

	stx := kernel.Statx{Mask: 1, Blksize: 4096, Nlink: 2, Mode: 0x81a4, Size: 100, Blocks: 1}
	encode(t, "statx", x.StatxSize(), g.StatxSize(),
		func(b []byte) error { return x.EncodeStatx(b, stx) },
		func(b []byte) error { return g.EncodeStatx(b, stx) })

	ts := kernel.Timespec{Sec: 1700000000, Nsec: 12345}
	encode(t, "timespec", x.TimespecSize(), g.TimespecSize(),
		func(b []byte) error { return x.EncodeTimespec(b, ts) },
		func(b []byte) error { return g.EncodeTimespec(b, ts) })

	tv := kernel.Timeval{Sec: 1700000000, Usec: 999}
	encode(t, "timeval", x.TimevalSize(), g.TimevalSize(),
		func(b []byte) error { return x.EncodeTimeval(b, tv) },
		func(b []byte) error { return g.EncodeTimeval(b, tv) })

	si := kernel.Sysinfo{UptimeSec: 5, TotalRAM: 1 << 32, FreeRAM: 1 << 31, Procs: 64, MemUnit: 1}
	encode(t, "sysinfo", x.SysinfoSize(), g.SysinfoSize(),
		func(b []byte) error { return x.EncodeSysinfo(b, si) },
		func(b []byte) error { return g.EncodeSysinfo(b, si) })

	rl := kernel.Rlimit{Cur: 1024, Max: 4096}
	encode(t, "rlimit", x.RlimitSize(), g.RlimitSize(),
		func(b []byte) error { return x.EncodeRlimit(b, rl) },
		func(b []byte) error { return g.EncodeRlimit(b, rl) })

	if x.IovecSize() != g.IovecSize() {
		t.Fatalf("iovec size: x86-64=%d asm-generic=%d", x.IovecSize(), g.IovecSize())
	}
	src := make([]byte, x.IovecSize())
	binary.LittleEndian.PutUint64(src[0:], 0xaaaa)
	binary.LittleEndian.PutUint64(src[8:], 0xbbbb)
	ivX, err := x.DecodeIovec(src)
	if err != nil {
		t.Fatal(err)
	}
	ivG, err := g.DecodeIovec(src)
	if err != nil {
		t.Fatal(err)
	}
	if ivX != ivG {
		t.Fatalf("iovec decode differs: x86-64=%+v asm-generic=%+v", ivX, ivG)
	}
}
