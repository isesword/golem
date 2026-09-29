package macho

import (
	"os"
	"testing"

	debugelf "debug/elf"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/loader"
)

// fixture is the committed clang-built Mach-O arm64 dylib
// (examples/native/hello_darwin_arm64.c + build_darwin_fixture.sh).
const fixture = "../../../examples/native/hello_darwin_arm64.dylib"

// TestParseFixture pins the whole parse of the committed fixture: container
// identity, segment mapping with protection conversion, the symbol namespace
// (leading underscores stripped), dependencies, and the rebase/bind opcode
// streams expanded to explicit relocations.
func TestParseFixture(t *testing.T) {
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	img, err := Parse(fixture)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if img.Format != loader.FormatMachO || img.Arch != emu.ArchARM64 || img.Machine != arch.IDARM64 {
		t.Fatalf("identity = (%v, %v, %v), want (macho, arm64, IDARM64)", img.Format, img.Arch, img.Machine)
	}
	if img.Entry != 0 || img.PhdrAddr != 0 || img.PhdrNum != 0 {
		t.Fatalf("dylib must carry no ELF-style startup metadata, got entry=%#x phdr=%#x/%d",
			img.Entry, img.PhdrAddr, img.PhdrNum)
	}

	// Segments: __TEXT (RX), __DATA (RW), __LINKEDIT (R) — Mach-O VM_PROT
	// mapped onto the ELF PF_* vocabulary.
	if len(img.Segments) != 3 {
		t.Fatalf("segments = %d, want 3 (__TEXT/__DATA/__LINKEDIT)", len(img.Segments))
	}
	wantProt := []debugelf.ProgFlag{debugelf.PF_R | debugelf.PF_X, debugelf.PF_R | debugelf.PF_W, debugelf.PF_R}
	for i, s := range img.Segments {
		if s.Flags != wantProt[i] {
			t.Errorf("segment %d flags = %v, want %v", i, s.Flags, wantProt[i])
		}
		if s.Vaddr != uint64(i)*0x4000 {
			t.Errorf("segment %d vaddr = %#x, want %#x", i, s.Vaddr, uint64(i)*0x4000)
		}
	}
	if img.LoadSpan != 0xC000 {
		t.Errorf("LoadSpan = %#x, want 0xc000", img.LoadSpan)
	}

	// Symbol namespace: leading "_" stripped, exports defined, host_magic the
	// single import.
	for _, name := range []string{"add", "call_host", "via_fptr_table", "guest_getpid", "guest_bogus_syscall", "host_fp", "fptr_table"} {
		if _, ok := img.Exports[name]; !ok {
			t.Errorf("export %q missing (exports: %v)", name, img.Exports)
		}
	}
	if len(img.Imports) != 1 || img.Imports[0] != "host_magic" {
		t.Errorf("imports = %v, want [host_magic]", img.Imports)
	}
	if len(img.Needed) != 1 || img.Needed[0] != "/usr/lib/libSystem.B.dylib" {
		t.Errorf("needed = %v, want [libSystem]", img.Needed)
	}

	// Relocations from the opcode streams: one rebase (fptr_table[0] ->
	// `seven`, file value 0x3c0) and one bind (host_fp <- host_magic).
	if len(img.Relocs) != 2 {
		t.Fatalf("relocs = %v, want exactly 2 (1 rebase + 1 bind)", img.Relocs)
	}
	var rebase, bind *loader.Reloc
	for i := range img.Relocs {
		r := &img.Relocs[i]
		switch r.Type {
		case RelocRebasePointer:
			rebase = r
		case RelocBindPointer:
			bind = r
		}
	}
	if rebase == nil || bind == nil {
		t.Fatalf("want one RelocRebasePointer and one RelocBindPointer, got %v", img.Relocs)
	}
	if rebase.Offset != 0x4008 || rebase.Addend != 0x3c0 {
		t.Errorf("rebase = %#x/%#x, want offset 0x4008 (fptr_table[0]), addend 0x3c0 (seven)", rebase.Offset, rebase.Addend)
	}
	if bind.Offset != 0x4000 {
		t.Errorf("bind offset = %#x, want 0x4000 (host_fp)", bind.Offset)
	}
	if s := img.Syms[bind.Sym]; !s.Undef || s.Name != "host_magic" {
		t.Errorf("bind sym = %q (undef=%v), want undefined host_magic", s.Name, s.Undef)
	}
}

// TestParseRejectsChainedFixups: LC_DYLD_CHAINED_FIXUPS is the ARM64e world
// (P5c) — a loud error, never a silent mis-load.
func TestParseRejectsChainedFixups(t *testing.T) {
	// Minimal valid Mach-O 64: header + one LC_DYLD_CHAINED_FIXUPS command.
	var hdr []byte
	u32 := func(v uint32) { hdr = append(hdr, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
	u32(0xfeedfacf) // magic
	u32(0x0100000c) // CPU_TYPE_ARM64
	u32(0)          // subtype
	u32(6)          // MH_DYLIB
	u32(1)          // ncmds
	u32(16)         // sizeofcmds
	u32(0)          // flags
	u32(0)          // reserved
	u32(0x34)       // LC_DYLD_CHAINED_FIXUPS
	u32(16)         // cmdsize
	u32(0)          // dataoff
	u32(0)          // datasize
	f, err := os.CreateTemp(t.TempDir(), "*.dylib")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(hdr); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Parse(f.Name()); err == nil {
		t.Fatal("chained-fixups image must be rejected")
	} else if got := err.Error(); !contains(got, "chained fixups") {
		t.Fatalf("error %q must name chained fixups", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestProtToELF pins the VM_PROT -> PF_* bit mapping.
func TestProtToELF(t *testing.T) {
	cases := []struct {
		vm   uint32
		want debugelf.ProgFlag
	}{
		{0, 0},
		{1, debugelf.PF_R},
		{2, debugelf.PF_W},
		{4, debugelf.PF_X},
		{5, debugelf.PF_R | debugelf.PF_X},
		{3, debugelf.PF_R | debugelf.PF_W},
		{7, debugelf.PF_R | debugelf.PF_W | debugelf.PF_X},
	}
	for _, tc := range cases {
		if got := protToELF(tc.vm); got != tc.want {
			t.Errorf("protToELF(%d) = %v, want %v", tc.vm, got, tc.want)
		}
	}
}

// TestUlebSleb pins the LEB128 decoders the opcode streams use.
func TestUlebSleb(t *testing.T) {
	u, n := uleb([]byte{0xe5, 0x8e, 0x26}, 0) // 624485
	if u != 624485 || n != 3 {
		t.Errorf("uleb = %d/%d, want 624485/3", u, n)
	}
	s, n := sleb([]byte{0x7f}, 0) // -1
	if s != -1 || n != 1 {
		t.Errorf("sleb = %d/%d, want -1/1", s, n)
	}
	s, _ = sleb([]byte{0x80, 0x7f}, 0) // low 7 bits 0, next byte 0x7f: sign extends to -128
	if s != -128 {
		t.Errorf("sleb = %d, want -128", s)
	}
}
