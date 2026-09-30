package emulator

import (
	"errors"
	"os"
	"testing"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform/android"
)

// PR-review hardening, pinned as tests: the wrap's public-API lifecycle,
// its runtime-rebind permission semantics, and the fixtures' relocation
// shape (the tests above only mean anything if the toolchain still emits
// the rebindable relocations they wrap through).

// TestWrapSymbolLifecycle: install → wrapped → stop → original, repeated —
// a StubManager leak, an un-restored binding slot, leftover frames or a
// stale registry entry all show up as drift across cycles.
func TestWrapSymbolLifecycle(t *testing.T) {
	e := newBootedOverride(t)
	p := e.WriteCStringAlloc("hello")
	call := func() uint64 {
		t.Helper()
		v, err := e.CallSymbol("slen", Words(p)...)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if got := call(); got != 5 {
		t.Fatalf("baseline = %d, want 5", got)
	}

	const cycles = 50
	for i := 0; i < cycles; i++ {
		stop, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
			rv, _ := h.ReturnValue()
			return rv.Raw + 1
		})
		if err != nil {
			t.Fatalf("cycle %d install: %v", i, err)
		}
		// While live: exactly one registry entry, no leftover frames from
		// previous cycles.
		if len(e.wraps) != 1 {
			t.Fatalf("cycle %d: %d live wraps, want 1", i, len(e.wraps))
		}
		if got := call(); got != 6 {
			t.Fatalf("cycle %d wrapped = %d, want 6", i, got)
		}
		stop()
		if got := call(); got != 5 {
			t.Fatalf("cycle %d restored = %d, want 5", i, got)
		}
		if len(e.wraps) != 0 || len(e.wrapStubs) != 0 {
			t.Fatalf("cycle %d: registry not clean (wraps=%d wrapStubs=%d)", i, len(e.wraps), len(e.wrapStubs))
		}
	}

	// Duplicate while live: the pinned v1 semantics — refused, and the first
	// wrap keeps working.
	stop, err := e.WrapSymbol("strlen", func(h *Hook) uint64 {
		rv, _ := h.ReturnValue()
		return rv.Raw + 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.WrapSymbol("strlen", func(h *Hook) uint64 { return 0 }); !errors.Is(err, ErrAlreadyWrapped) {
		t.Fatalf("duplicate wrap err = %v, want ErrAlreadyWrapped", err)
	}
	if got := call(); got != 6 {
		t.Fatalf("post-duplicate slen = %d, want 6 (first wrap unaffected)", got)
	}
	stop()
	if got := call(); got != 5 {
		t.Fatalf("after stop slen = %d, want 5", got)
	}
}

// TestRebindPermissionSemantics: what WrapSymbol's rebinding may rely on.
// Two facts are pinned here so neither can drift silently:
//
//  1. golem's loader applies ELF SEGMENT protections but NOT GNU_RELRO —
//     binding slots are writable by segment contract after FinalizeImage
//     (the honest current state; when RELRO lands, the write exception
//     must move into a loader-owned Rebind path).
//  2. Host-side writes bypass GUEST page protection (unicorn host-write
//     semantics — the known P7 backend leak). Pinned so WrapSymbol's v1
//     dependency on it is explicit, not accidental.
func TestRebindPermissionSemantics(t *testing.T) {
	e := newBootedOverride(t)

	// (1) The live binding slot (slen's GOT entry for strlen) is writable
	// post-FinalizeImage — WrapSymbol's rebind relies on exactly this.
	slot := findBindingSlot(t, e, "strlen")
	orig, err := e.ReadU64(slot)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteU64(slot, orig); err != nil {
		t.Fatalf("binding slot post-FinalizeImage is not host-writable (%v): RELRO semantics changed — WrapSymbol v1 must be re-examined", err)
	}

	// (2) A guest READ-ONLY page still accepts HOST writes: the rebind path
	// does not consult guest protection. This is the documented backend
	// leak the v1 wrap sits on — never present it as guest-visible RW.
	page, err := e.Alloc(0x1000, emu.ProtRead)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteU64(page, 0x41414141); err != nil {
		t.Fatalf("host write to a guest read-only page failed (%v) — host-write-bypass semantics changed, re-audit the rebind path", err)
	}
	if v, err := e.ReadU64(page); err != nil || v != 0x41414141 {
		t.Fatalf("host write to RO page did not stick: v=%#x err=%v", v, err)
	}
}

// readSlotPtr reads a binding slot at the TARGET's pointer width — the
// same predicate width WrapSymbol's scan uses (kept in lockstep on
// purpose: a U64 read on ARM32 compares in the neighbor slot's bits).
func readSlotPtr(e *Emulator, addr uint64) (uint64, error) {
	if uint64(e.arch.PtrSize()) == 4 {
		v, err := e.ReadU32(addr)
		return uint64(v), err
	}
	return e.ReadU64(addr)
}

// findBindingSlot returns the first relocation slot naming sym whose
// current value equals the symbol's raw address.
func findBindingSlot(t *testing.T, e *Emulator, sym string) uint64 {
	t.Helper()
	original, ok := e.Sym(sym)
	if !ok {
		t.Fatalf("Sym(%q) not found", sym)
	}
	for _, m := range e.Modules() {
		for _, r := range m.Img.Relocs {
			if int(r.Sym) >= len(m.Img.Syms) || m.Img.Syms[r.Sym].Name != sym {
				continue
			}
			slot := m.Base + r.Offset
			if cur, err := readSlotPtr(e, slot); err == nil && cur == original {
				return slot
			}
		}
	}
	t.Fatalf("no resolvable binding slot for %q", sym)
	return 0
}

// TestWrapFixtureBindings: the wrap tests are only interposition tests if
// the fixtures still CONTAIN the rebindable relocations they wrap through.
// C source alone guarantees nothing — a toolchain upgrade can fold an
// indirect call into a direct one (seen live with -O2 constant folding) or
// resolve a reference locally, and the wrap tests would silently degrade
// into refusals. Pin the shape.
func TestWrapFixtureBindings(t *testing.T) {
	t.Run("native.so (ARM64)", func(t *testing.T) {
		e := newBootedOverride(t)
		for _, sym := range []string{"strlen", "slen", "fact"} {
			assertRebindableBinding(t, e, sym)
		}
	})
	t.Run("hello_amd64.so (AMD64)", func(t *testing.T) {
		e := bootAmd64(t)
		assertRebindableBinding(t, e, "add") // fptr_table[1], R_X86_64_64
	})
	t.Run("hello_android_arm32.so (ARM32)", func(t *testing.T) {
		e := bootArm32(t)
		for _, sym := range []string{"add", "fact"} { // nest's ABS32 pointer
			assertRebindableBinding(t, e, sym)
		}
	})
}

func assertRebindableBinding(t *testing.T, e *Emulator, sym string) {
	t.Helper()
	original, ok := e.Sym(sym)
	if !ok {
		t.Fatalf("fixture no longer exports %q", sym)
	}
	for _, m := range e.Modules() {
		for _, r := range m.Img.Relocs {
			if int(r.Sym) >= len(m.Img.Syms) || m.Img.Syms[r.Sym].Name != sym {
				continue
			}
			slot := m.Base + r.Offset
			if cur, err := readSlotPtr(e, slot); err == nil && cur == original {
				return // a rebindable site exists
			}
		}
	}
	t.Fatalf("fixture no longer contains a rebindable relocation for symbol %q; the compiler/linker probably optimized the reference into a direct call or resolved it locally — the wrap tests are no longer exercising interposition", sym)
}

func bootAmd64(t *testing.T) *Emulator {
	t.Helper()
	const so = "../examples/native/hello_amd64.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 { return 42 },
		}),
	)))
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func bootArm32(t *testing.T) *Emulator {
	t.Helper()
	const so = "../examples/native/hello_android_arm32.so"
	const bionic = "../assets/android/sdk23/lib/libc.so"
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	if _, err := os.Stat(bionic); err != nil {
		t.Skipf("ARM32 bionic assets not fetched: %v (run scripts/fetch_bionic_arm32.sh)", err)
	}
	e, err := New(Config{
		SOPath:    so,
		AssetRoot: "../assets",
		Engine:    "unicorn",
		Pid:       4242,
	}, WithPlatformConfig(android.NewConfig(
		android.WithReplaceFns(map[string]interpose.HostFunc{
			"host_magic": func(ctx interpose.CallContext) uint64 { return 42 },
		}),
	)))
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}
