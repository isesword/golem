package darwin

import (
	"encoding/binary"
	"testing"

	"github.com/isesword/golem/internal/kernel"
)

// TestStatLayout pins the XNU ARM64 struct stat offsets the semantic
// kernel.Stat carries: st_mode (u16) @4, st_size (i64) @96, 144 bytes total.
func TestStatLayout(t *testing.T) {
	c := XNUARM64Codecs{}
	dst := make([]byte, c.StatSize()+8) // oversized: must still encode
	s := kernel.Stat{Mode: 0o100644, Size: 0x1122334455667788}
	if err := c.EncodeStat(dst, s); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(dst[4:]); got != 0o100644 {
		t.Errorf("st_mode@4 = %#o, want %#o", got, 0o100644)
	}
	if got := binary.LittleEndian.Uint64(dst[96:]); got != s.Size {
		t.Errorf("st_size@96 = %#x, want %#x", got, s.Size)
	}
	if c.StatSize() != 144 {
		t.Errorf("StatSize = %d, want 144 (XNU ARM64 64-bit-inode stat)", c.StatSize())
	}
	if err := c.EncodeStat(make([]byte, 8), s); err == nil {
		t.Error("short dst must error")
	}
}

// TestTimespecTimevalLayout: two i64 fields, LP64 — same shape as Linux,
// pinned anyway (coincidence is not a contract).
func TestTimespecTimevalLayout(t *testing.T) {
	c := XNUARM64Codecs{}
	ts := make([]byte, c.TimespecSize())
	if err := c.EncodeTimespec(ts, kernel.Timespec{Sec: 1, Nsec: 2}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(ts[0:]) != 1 || binary.LittleEndian.Uint64(ts[8:]) != 2 {
		t.Fatalf("timespec = %v", ts)
	}
	tv := make([]byte, c.TimevalSize())
	if err := c.EncodeTimeval(tv, kernel.Timeval{Sec: 3, Usec: 4}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(tv[0:]) != 3 || binary.LittleEndian.Uint64(tv[8:]) != 4 {
		t.Fatalf("timeval = %v", tv)
	}
}

// TestRlimitIovecLayout: rlimit = two u64; iovec = {base, len} 16 bytes.
func TestRlimitIovecLayout(t *testing.T) {
	c := XNUARM64Codecs{}
	rl := make([]byte, c.RlimitSize())
	if err := c.EncodeRlimit(rl, kernel.Rlimit{Cur: 5, Max: 6}); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(rl[0:]) != 5 || binary.LittleEndian.Uint64(rl[8:]) != 6 {
		t.Fatalf("rlimit = %v", rl)
	}
	var src [16]byte
	binary.LittleEndian.PutUint64(src[0:], 0xAAAA)
	binary.LittleEndian.PutUint64(src[8:], 0xBBBB)
	iv, err := c.DecodeIovec(src[:])
	if err != nil {
		t.Fatal(err)
	}
	if iv.Base != 0xAAAA || iv.Len != 0xBBBB {
		t.Fatalf("iovec = %+v", iv)
	}
	if _, err := c.DecodeIovec(make([]byte, 8)); err == nil {
		t.Error("short src must error")
	}
}

// TestLinuxOnlyStructs documents that statx/sysinfo are interface-completeness
// shims: XNU has neither syscall, so no Darwin table entry may ever reach
// them. They still encode deterministically (and error on short buffers).
func TestLinuxOnlyStructs(t *testing.T) {
	c := XNUARM64Codecs{}
	if err := c.EncodeStatx(make([]byte, c.StatxSize()), kernel.Statx{Size: 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.EncodeSysinfo(make([]byte, c.SysinfoSize()), kernel.Sysinfo{Procs: 1}); err != nil {
		t.Fatal(err)
	}
	if err := c.EncodeStatx(make([]byte, 4), kernel.Statx{}); err == nil {
		t.Error("short dst must error")
	}
	if err := c.EncodeSysinfo(make([]byte, 4), kernel.Sysinfo{}); err == nil {
		t.Error("short dst must error")
	}
}
