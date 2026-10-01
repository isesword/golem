package emulator

import (
	"os"
	"testing"

	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/platform/android"
)

func bootForHook(t *testing.T, so string) *Emulator {
	t.Helper()
	if _, err := os.Stat(so); err != nil {
		t.Skipf("fixture not present: %v", err)
	}
	cfg := Config{SOPath: so, AssetRoot: "../assets", Engine: "unicorn", Pid: 4242}
	var opts []Option
	if so == "../examples/native/hello_amd64.so" {
		opts = append(opts, WithPlatformConfig(android.NewConfig(
			android.WithReplaceFns(map[string]interpose.HostFunc{
				"host_magic": func(ctx interpose.CallContext) uint64 { return 42 },
			}),
		)))
	}
	e, err := New(cfg, opts...)
	if err != nil {
		t.Skipf("boot: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// HookCode contract acceptance through the FACADE, on real fixtures: the
// single-address boundary fires exactly at the entry (never at end), and a
// hook installed after the target was translated still fires — the
// installation-effect guarantee end to end.

func TestHookCodeSingleAddressExactLive(t *testing.T) {
	for _, tc := range []struct{ name, so, sym string }{
		{"ARM64", "../examples/native/native.so", "slen"},
		{"AMD64", "../examples/native/hello_amd64.so", "add"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := bootForHook(t, tc.so)
			entry, ok := e.Sym(tc.sym)
			if !ok {
				t.Fatalf("no %s", tc.sym)
			}
			ih := e.be.(emu.InstructionHooker)

			var fired []uint64
			// The ReplaceE-shaped single-address range: [entry, entry+4) on
			// ARM64 (fixed 4-byte encoding), [entry, entry+1) on AMD64 — the
			// instruction exactly at `end` must NOT fire.
			width := uint64(1)
			if tc.sym == "slen" {
				width = 4
			}
			h, err := ih.HookCode(emu.GuestAddr(entry), emu.GuestAddr(entry+width), func(b emu.Backend, a emu.GuestAddr, size uint32) {
				fired = append(fired, uint64(a))
			})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Remove()

			// The function may already have been translated (boot ran init);
			// the guarantee covers that too. Call it twice.
			for i := 0; i < 2; i++ {
				if tc.sym == "slen" {
					p := e.WriteCStringAlloc("hello")
					if _, err := e.CallSymbol("slen", Words(p)...); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := e.CallSymbol("add", Words(1, 2)...); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, a := range fired {
				if a != entry {
					t.Fatalf("hook fired at %#x, want only the entry %#x (boundary leak)", a, entry)
				}
			}
			if len(fired) != 2 {
				t.Fatalf("fired %d times for 2 calls, want 2 (fired=%v)", len(fired), fired)
			}
		})
	}
}

// HookAddr after translation: run the target first, THEN install — the next
// execution must fire (the bug class HookAddr used to have: no flush).
func TestHookAddrAfterTranslationLive(t *testing.T) {
	e := bootForHook(t, "../examples/native/native.so")
	p := e.WriteCStringAlloc("hello")
	if _, err := e.CallSymbol("slen", Words(p)...); err != nil {
		t.Fatal(err)
	}

	fired := 0
	stop, err := e.HookAddr(func() uint64 { a, _ := e.Sym("slen"); return a }(), func(h *Hook) {
		fired++
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	if _, err := e.CallSymbol("slen", Words(p)...); err != nil {
		t.Fatal(err)
	}
	if fired != 1 {
		t.Fatalf("HookAddr installed after translation fired %d times, want 1", fired)
	}
}
