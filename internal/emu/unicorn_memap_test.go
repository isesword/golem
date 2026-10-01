//go:build unicorn && (darwin || linux)

package emu

import (
	"encoding/binary"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// ucMemWriteProt is UC_MEM_WRITE_PROT from unicorn.h (uc_mem_type) — the event
// type the invalid-memory hook receives for a guest access into a mapped but
// insufficiently-permitted region (a store here).
const ucMemWriteProt = 22

// mapAnonPage allocates one anonymous, page-aligned (os.Getpagesize) host page,
// RW — the exact shape MemMapPtr expects for a caller-provided backing buffer.
// No PROT_EXEC is needed even for regions the guest executes from: unicorn's
// translator reads guest code out of the backing buffer as plain host data.
func mapAnonPage(tb testing.TB) []byte {
	tb.Helper()
	buf, err := syscall.Mmap(-1, 0, os.Getpagesize(),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		tb.Fatalf("mmap anon page: %v", err)
	}
	tb.Cleanup(func() { _ = syscall.Munmap(buf) })
	return buf
}

func le64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// Core MemMapPtr semantics: the guest region is the caller's buffer, not a
// copy. One page is mapped into two engines at different guest addresses and
// every direction (Go -> guest, guest -> Go, guest -> guest via the shared
// backing) must be observed by the others without any explicit synchronization:
//
//  1. engine A maps the page RWX, guest code executes straight out of it;
//  2. engine B maps the SAME page RW and reads the same magic;
//  3. engine A MemWrites the data area -> the Go slice changes in place and
//     engine B's next MemRead reflects the write.
func TestMemMapPtrSharedHostBuffer(t *testing.T) {
	const (
		aBase = 0x10000000 // RWX view (engine A, executes from the buffer)
		bBase = 0x20000000 // RW  view (engine B, same buffer)
	)
	const magicOff = 0x100

	buf := mapAnonPage(t)
	binary.LittleEndian.PutUint64(buf[magicOff:], 0xCAFEBABEDEADBEEF)
	// LDR X1,[X1,#0x100]; ADD X1,X1,#1 — loads the magic and increments it.
	binary.LittleEndian.PutUint32(buf[0x0:], 0xF9408021)
	binary.LittleEndian.PutUint32(buf[0x4:], 0x91000421)

	a := openBE(t)
	defer a.Close()
	if err := a.MemMapPtr(aBase, uint64(len(buf)), ProtAll, unsafe.Pointer(&buf[0])); err != nil {
		t.Fatalf("MemMapPtr: %v", err)
	}

	// The map is not a copy: what Go wrote into the buffer before mapping is
	// guest-visible, and Go mutations after mapping are seen by the engine too.
	if got, err := a.MemRead(aBase+magicOff, 8); err != nil || binary.LittleEndian.Uint64(got) != 0xCAFEBABEDEADBEEF {
		t.Fatalf("engine A does not see pre-map magic: got %#x err %v", got, err)
	}
	binary.LittleEndian.PutUint64(buf[magicOff:], 0x1122334455667788)
	if got, err := a.MemRead(aBase+magicOff, 8); err != nil || binary.LittleEndian.Uint64(got) != 0x1122334455667788 {
		t.Fatalf("MemMapPtr snapshot-copied the buffer: got %#x err %v", got, err)
	}

	// Execute code that lives in the caller-provided buffer: X1 = magic + 1.
	if err := a.RegWrite(regX1, aBase); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(aBase, aBase+8); err != nil {
		t.Fatalf("exec from mapped host buffer: %v", err)
	}
	if got, err := a.RegRead(regX1); err != nil || got != 0x1122334455667788+1 {
		t.Fatalf("X1 after exec = %#x, want %#x (err %v)", got, 0x1122334455667788+1, err)
	}

	// A second engine maps the SAME host buffer at a different guest address.
	b := openBE(t)
	defer b.Close()
	if err := b.MemMapPtr(bBase, uint64(len(buf)), ProtRead|ProtWrite, unsafe.Pointer(&buf[0])); err != nil {
		t.Fatalf("engine B MemMapPtr: %v", err)
	}
	if got, err := b.MemRead(bBase+magicOff, 8); err != nil || binary.LittleEndian.Uint64(got) != 0x1122334455667788 {
		t.Fatalf("engine B does not see the shared magic: got %#x err %v", got, err)
	}

	// Guest write through engine A lands in the host buffer in place: the Go
	// slice changes (zero-copy proof) and engine B observes the new value.
	const magic2 = uint64(0xDEADC0DECAFEF00D)
	if err := a.MemWrite(aBase+magicOff, le64(magic2)); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(buf[magicOff:]); got != magic2 {
		t.Fatalf("guest write did not reach the host buffer: got %#x, want %#x", got, magic2)
	}
	if got, err := b.MemRead(bBase+magicOff, 8); err != nil || binary.LittleEndian.Uint64(got) != magic2 {
		t.Fatalf("engine B does not see engine A's write: got %#x err %v", got, err)
	}
}

// Permission verification. A read-only mapping of the shared buffer must reject
// a guest store: HookMemInvalid fires with UC_MEM_WRITE_PROT, emu_start aborts
// with an error, and the backing buffer is untouched.
//
// (The uc_mem_write host API is a different story: unicorn2 performs it
// regardless of region perms — verified on 2.1.4 — so only the guest path is a
// permission guarantee; that is asserted here.)
func TestMemMapPtrReadOnlyRejectsGuestWrite(t *testing.T) {
	const (
		cBase = 0x30000000 // RO view of the shared buffer
		cCode = 0x31000000 // engine-owned RWX code page
	)
	const magicOff = 0x100
	const magic = uint64(0x5AFE5AFE5AFE5AFE)

	buf := mapAnonPage(t)
	binary.LittleEndian.PutUint64(buf[magicOff:], magic)

	c := openBE(t)
	defer c.Close()
	if err := c.MemMapPtr(cBase, uint64(len(buf)), ProtRead, unsafe.Pointer(&buf[0])); err != nil {
		t.Fatalf("MemMapPtr RO: %v", err)
	}
	if err := c.MemMap(cCode, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	// STR X1,[X2]
	if err := c.MemWrite(cCode, []byte{0x41, 0x00, 0x00, 0xF9}); err != nil {
		t.Fatal(err)
	}

	fired := 0
	var typ, faultAddr uint64
	inv, ok := c.(InvalidMemHooker) // capability probe
	if !ok {
		t.Fatal("backend lacks the InvalidMemHooker capability")
	}
	h, err := inv.HookMemInvalid(func(b Backend, t2 int, addr GuestAddr, size int, value int64) bool {
		fired++
		typ = uint64(t2)
		faultAddr = uint64(addr) // GuestAddr→raw for the test assertion
		return false             // not handled: unicorn must abort the emulation
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Remove()

	if err := c.RegWrite(regX1, 0x1234567890ABCDEF); err != nil {
		t.Fatal(err)
	}
	if err := c.RegWrite(regX2, cBase+magicOff); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(cCode, cCode+4); err == nil {
		t.Fatal("guest store into a read-only mapped region did not abort the emulation")
	}
	if fired != 1 {
		t.Fatalf("HookMemInvalid fired %d times, want 1", fired)
	}
	if typ != ucMemWriteProt {
		t.Fatalf("fault type = %#x, want UC_MEM_WRITE_PROT (%#x)", typ, ucMemWriteProt)
	}
	if faultAddr != cBase+magicOff {
		t.Fatalf("fault addr = %#x, want %#x", faultAddr, cBase+magicOff)
	}
	if got := binary.LittleEndian.Uint64(buf[magicOff:]); got != magic {
		t.Fatalf("backing buffer was modified by the rejected store: got %#x, want %#x", got, magic)
	}
}

// Alignment contract: MemMapPtr validates addr/size/host against the host page
// size in Go and returns an error (never a panic, and never a C-level call)
// for unaligned arguments. A valid mapping must still succeed afterwards —
// rejected calls leave the engine untouched.
func TestMemMapPtrRejectsUnaligned(t *testing.T) {
	const base = 0x40000000
	const magicOff = 0x100
	const magic = uint64(0xFEEDFACEFEEDFACE)

	buf := mapAnonPage(t)
	binary.LittleEndian.PutUint64(buf[magicOff:], magic)
	page := uint64(os.Getpagesize())

	a := openBE(t)
	defer a.Close()

	for name, run := range map[string]func() error{
		"nil host pointer":       func() error { return a.MemMapPtr(base, page, ProtAll, nil) },
		"unaligned host pointer": func() error { return a.MemMapPtr(base, page, ProtAll, unsafe.Pointer(&buf[1])) },
		"unaligned guest addr":   func() error { return a.MemMapPtr(base+8, page, ProtAll, unsafe.Pointer(&buf[0])) },
		"size not page multiple": func() error { return a.MemMapPtr(base, page-4, ProtAll, unsafe.Pointer(&buf[0])) },
		"zero size":              func() error { return a.MemMapPtr(base, 0, ProtAll, unsafe.Pointer(&buf[0])) },
	} {
		if err := run(); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}

	// A rejected call must not have mapped anything or corrupted state.
	if err := a.MemMapPtr(base, page, ProtAll, unsafe.Pointer(&buf[0])); err != nil {
		t.Fatalf("valid MemMapPtr after rejected calls: %v", err)
	}
	if got, err := a.MemRead(base+magicOff, 8); err != nil || binary.LittleEndian.Uint64(got) != magic {
		t.Fatalf("post-rejection MemRead: got %#x err %v", got, err)
	}
}
