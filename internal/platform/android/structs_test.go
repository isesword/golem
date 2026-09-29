package android

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// Layout pinning for the asm-generic LP64 guest struct codecs: byte offsets
// here ARE the guest ABI contract — kernel tests assert the semantic content,
// these tests assert the layout.

func TestEncodeStatLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	buf := make([]byte, c.StatSize())
	if len(buf) != 128 {
		t.Fatalf("stat size = %d, want 128", len(buf))
	}
	if err := c.EncodeStat(buf, kernel.Stat{Mode: 0x81a4, Size: 11}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(buf[16:]); got != 0x81a4 {
		t.Errorf("st_mode @16 = %#o, want 0x81a4", got)
	}
	if got := binary.LittleEndian.Uint64(buf[48:]); got != 11 {
		t.Errorf("st_size @48 = %d, want 11", got)
	}
	if got := binary.LittleEndian.Uint32(buf[56:]); got != 0x1000 {
		t.Errorf("st_blksize @56 = %#x, want 0x1000", got)
	}
	if got := binary.LittleEndian.Uint64(buf[64:]); got != 1 {
		t.Errorf("st_blocks @64 = %d, want 1 ((11+511)/512)", got)
	}
	if err := c.EncodeStat(buf[:8], kernel.Stat{}); err == nil {
		t.Error("short dst must error")
	}
}

func TestEncodeStatxLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	buf := make([]byte, c.StatxSize())
	if len(buf) != 256 {
		t.Fatalf("statx size = %d, want 256", len(buf))
	}
	sx := kernel.Statx{Mask: 0x7ff, Blksize: 0x1000, Nlink: 1, Mode: 0x41ed, Size: 4096, Blocks: 8}
	if err := c.EncodeStatx(buf, sx); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		off  int
		got  uint64
		want uint64
		name string
	}{
		{0, uint64(binary.LittleEndian.Uint32(buf[0:])), 0x7ff, "stx_mask"},
		{4, uint64(binary.LittleEndian.Uint32(buf[4:])), 0x1000, "stx_blksize"},
		{16, uint64(binary.LittleEndian.Uint32(buf[16:])), 1, "stx_nlink"},
		{28, uint64(binary.LittleEndian.Uint16(buf[28:])), 0x41ed, "stx_mode"},
		{40, binary.LittleEndian.Uint64(buf[40:]), 4096, "stx_size"},
		{48, binary.LittleEndian.Uint64(buf[48:]), 8, "stx_blocks"},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s @%d = %#x, want %#x", ch.name, ch.off, ch.got, ch.want)
		}
	}
}

func TestEncodeTimespecTimevalLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	ts := make([]byte, c.TimespecSize())
	if err := c.EncodeTimespec(ts, kernel.Timespec{Sec: 1700000000, Nsec: 123}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(ts[0:]); got != 1700000000 {
		t.Errorf("timespec sec @0 = %d", got)
	}
	if got := binary.LittleEndian.Uint64(ts[8:]); got != 123 {
		t.Errorf("timespec nsec @8 = %d", got)
	}
	tv := make([]byte, c.TimevalSize())
	if err := c.EncodeTimeval(tv, kernel.Timeval{Sec: 1700000000, Usec: 456}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(tv[0:]); got != 1700000000 {
		t.Errorf("timeval sec @0 = %d", got)
	}
	if got := binary.LittleEndian.Uint64(tv[8:]); got != 456 {
		t.Errorf("timeval usec @8 = %d", got)
	}
}

func TestEncodeSysinfoLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	buf := make([]byte, c.SysinfoSize())
	if len(buf) != 128 {
		t.Fatalf("sysinfo size = %d, want 128", len(buf))
	}
	s := kernel.Sysinfo{UptimeSec: 999, TotalRAM: 4 << 30, FreeRAM: 2 << 30, Procs: 64, MemUnit: 1}
	if err := c.EncodeSysinfo(buf, s); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(buf[0:]); got != 999 {
		t.Errorf("uptime @0 = %d, want 999", got)
	}
	if got := binary.LittleEndian.Uint64(buf[32:]); got != 4<<30 {
		t.Errorf("totalram @32 = %d", got)
	}
	if got := binary.LittleEndian.Uint64(buf[40:]); got != 2<<30 {
		t.Errorf("freeram @40 = %d", got)
	}
	if got := binary.LittleEndian.Uint16(buf[80:]); got != 64 {
		t.Errorf("procs @80 = %d", got)
	}
	if got := binary.LittleEndian.Uint32(buf[104:]); got != 1 {
		t.Errorf("mem_unit @104 = %d", got)
	}
}

func TestEncodeRlimitLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	buf := make([]byte, c.RlimitSize())
	if err := c.EncodeRlimit(buf, kernel.Rlimit{Cur: 1024, Max: 4096}); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(buf[0:]); got != 1024 {
		t.Errorf("rlim_cur @0 = %d", got)
	}
	if got := binary.LittleEndian.Uint64(buf[8:]); got != 4096 {
		t.Errorf("rlim_max @8 = %d", got)
	}
}

func TestDecodeIovecLayout(t *testing.T) {
	c := AsmGenericLP64Codecs{}
	if c.IovecSize() != 16 {
		t.Fatalf("iovec size = %d, want 16 (LP64)", c.IovecSize())
	}
	var src [16]byte
	binary.LittleEndian.PutUint64(src[0:], 0xAAAA0000)
	binary.LittleEndian.PutUint64(src[8:], 64)
	iv, err := c.DecodeIovec(src[:])
	if err != nil {
		t.Fatal(err)
	}
	if iv.Base != 0xAAAA0000 || iv.Len != 64 {
		t.Errorf("iovec = %+v, want base 0xaaaa0000 len 64", iv)
	}
	if _, err := c.DecodeIovec(src[:8]); err == nil {
		t.Error("short src must error")
	}
}
