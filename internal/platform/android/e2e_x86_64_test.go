//go:build unicorn && (darwin || linux)

// P5a acceptance chain, end to end on the real engine: an AMD64 ELF probe →
// Target quad resolution → AMD64 backend → AddressSpace (from the Android
// LayoutPolicy over AMD64 caps) → ELF map+reloc through SymbolResolver →
// FinalizeImage → Android StartupABI → SysV guest function calls → host
// interposition through the int3 stub channel (WriteResult + ReturnFromCall)
// → a real guest syscall through the UC_HOOK_INSN channel → normal returns
// with the stack fully restored.
//
// The chain is assembled COMPONENT-LEVEL here on purpose: emulator.New's boot
// flow is frozen in P5a (its call setup writes an LR register and its trap
// handler assumes ARM64's 4-byte svc — both ARM-shaped), so the AMD64
// combination is proven at the layer the architecture quad is defined at.
package android

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/arch/amd64"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/interpose"
	"github.com/isesword/golem/internal/kernel"
	"github.com/isesword/golem/internal/loader"
	_ "github.com/isesword/golem/internal/loader/elf"       // FormatELF parser
	_ "github.com/isesword/golem/internal/loader/elf/amd64" // (FormatELF, ArchAMD64) relocator
	"github.com/isesword/golem/internal/memory"
	"github.com/isesword/golem/internal/platform"
)

// helloSO is the committed zig-built x86-64 fixture (examples/native).
const helloSO = "../../../examples/native/hello_amd64.so"

// sentinel is the stop address pushed as the top-level return address (the
// same role the ARM64 emulator's LR sentinel plays): when the guest function
// rets, PC lands here and the engine stops.
const sentinel = 0xFFFFFF00

// TestAndroidAMD64AcceptanceChain assembles and runs the whole P5a chain.
func TestAndroidAMD64AcceptanceChain(t *testing.T) {
	if _, err := os.Stat(helloSO); err != nil {
		t.Skipf("fixture not present: %v", err)
	}

	// --- 1. ELF probe: header sniff + full parse --------------------------
	fh, err := os.Open(helloSO)
	if err != nil {
		t.Fatal(err)
	}
	format, id, variant, err := loader.Sniff(fh)
	fh.Close()
	if err != nil {
		t.Fatalf("Sniff: %v", err)
	}
	if format != loader.FormatELF || id != arch.IDAMD64 || variant != arch.VariantGeneric {
		t.Fatalf("probe = (%s, %d, %d), want (elf, %d, %d)", format, id, variant, arch.IDAMD64, arch.VariantGeneric)
	}
	img, err := loader.Parse(helloSO)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if img.Arch != emu.ArchAMD64 || img.Machine != arch.IDAMD64 {
		t.Fatalf("image arch = (%v, %d), want (amd64, EM_X86_64)", img.Arch, img.Machine)
	}
	for _, want := range []string{"add", "sum6", "call_host", "call_host_twice", "guest_getpid", "via_fptr_table"} {
		if _, ok := img.Exports[want]; !ok {
			t.Fatalf("fixture must export %s", want)
		}
	}
	hist := img.RelocHistogram()
	for _, want := range []uint32{8 /* RELATIVE */, 6 /* GLOB_DAT */, 7 /* JMP_SLOT */, 1 /* R_X86_64_64 */} {
		if hist[want] == 0 {
			t.Fatalf("fixture must carry reloc type %d, histogram %v", want, hist)
		}
	}

	// --- 2. Target quad: (IDAMD64, Generic) -> Arch/CallABI/Stubs/Features
	cpuArch, callABI, stubEnc, feats, err := arch.Resolve(arch.IDAMD64, arch.VariantGeneric)
	if err != nil {
		t.Fatalf("arch.Resolve: %v", err)
	}
	if cpuArch.EngineArch() != emu.ArchAMD64 {
		t.Fatalf("EngineArch = %v, want amd64", cpuArch.EngineArch())
	}

	// --- 3. AMD64 backend ---------------------------------------------------
	be, err := emu.NewNamed("unicorn", emu.ArchAMD64)
	if err != nil {
		t.Skipf("unicorn backend unavailable: %v", err)
	}
	defer be.Close()

	// --- 4. AddressSpace from the Android LayoutPolicy over AMD64 caps -----
	layout, err := (LayoutPolicy{}).Resolve(
		platform.TargetInfo{Platform: platform.Android, Caps: cpuArch.Caps()},
		platform.LayoutOverrides{})
	if err != nil {
		t.Fatalf("LayoutPolicy.Resolve with AMD64 caps: %v", err)
	}
	as := memory.NewAddressSpace(layout)
	// Back the AddressSpace-owned ranges with real engine mappings (the same
	// boot-step shape as the ARM64 composition root).
	if err := be.MemMap(emu.GuestAddr(layout.StubBase), layout.StubSize, emu.ProtAll); err != nil {
		t.Fatal(err)
	}
	if err := be.MemMap(emu.GuestAddr(layout.StackBase), layout.StackSize, emu.ProtRead|emu.ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := be.MemMap(emu.GuestAddr(layout.TLSBase), layout.TLSSize, emu.ProtRead|emu.ProtWrite); err != nil {
		t.Fatal(err)
	}

	// --- 5. map + relocate through the SymbolResolver chain ----------------
	stubMgr := interpose.NewStubManager(as, stubEnc, be)
	itab := interpose.NewInterposeTable()
	itab.BindSymbol("host_magic", func(ctx interpose.CallContext) uint64 {
		x, err := ctx.RegRead(callABI.Arg(0))
		if err != nil {
			t.Errorf("host_magic: read arg0: %v", err)
		}
		return x * 2
	})
	resolver := loader.ChainResolvers(
		interpose.NewHostResolver(itab, stubMgr),
		loader.NewDynamicLinker().GlobalResolver(),
		interpose.NewUnresolvedStubResolver(stubMgr),
	)
	span := (img.LoadSpan + 0xfff) &^ 0xfff
	baseAddr, err := as.Alloc(memory.PurposeModule, span+0x100000)
	if err != nil {
		t.Fatal(err)
	}
	base := uint64(baseAddr)
	plan, err := img.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(be, base, resolver); err != nil { // map + reloc + FinalizeImage
		t.Fatalf("plan.Apply: %v", err)
	}

	// The host-interposed import must have landed in the GOT as a STUB
	// GUEST ADDRESS inside the stub region (link-time interposition).
	gotSlot, err := be.MemRead(emu.GuestAddr(base+0x27c0), 8) // JMP_SLOT offset from the fixture's .rela.plt
	if err != nil {
		t.Fatal(err)
	}
	stubAddr := binary.LittleEndian.Uint64(gotSlot)
	if stubAddr < layout.StubBase || stubAddr >= layout.StubBase+layout.StubSize {
		t.Fatalf("host_magic GOT slot = %#x, want an address inside the stub region %#x..%#x",
			stubAddr, layout.StubBase, layout.StubBase+layout.StubSize)
	}

	// --- 6. Android StartupABI over the finalized image --------------------
	startup := &StartupABI{}
	if err := startup.BuildInitialState(&platform.StartupContext{
		Image: img, Base: emu.GuestAddr(base),
		AS:    as,
		Stack: memory.Region{Addr: layout.StackBase, Size: layout.StackSize},
		Mem:   be, Features: feats,
	}); err != nil {
		t.Fatalf("BuildInitialState: %v", err)
	}
	if got := startup.Lookup(atPhdr); got != base+img.PhdrAddr {
		t.Fatalf("AT_PHDR = %#x, want %#x", got, base+img.PhdrAddr)
	}
	if hw := startup.Lookup(atHwcap); hw != 0 {
		t.Fatalf("AT_HWCAP = %#x, want 0 (empty amd64 feature set)", hw)
	}
	rnd, err := be.MemRead(startup.ATRandom(), 16)
	if err != nil || len(rnd) != 16 {
		t.Fatalf("AT_RANDOM bytes must be materialized in guest memory: %v", err)
	}

	// --- 7. trap channels: host stubs (int3/UC_HOOK_INTR) + real syscall ---
	kctx := &kernel.Context{
		B: be, Pid: 4242,
		Transport: LinuxAMD64Transport{},
		Table:     NewAMD64SyscallTable(kernel.DefaultHandlers()),
		Codecs:    LinuxX8664Codecs{},
	}
	// Red-zone guard (P5a red line: the 128-byte red zone below RSP is not
	// emulated, and NO golem component — WriteResult / ReturnFromCall /
	// syscall Dispatch — may treat [RSP-128, RSP) as scratch). The band is
	// re-poisoned before EVERY call (in the call driver below): across calls
	// the stack legitimately holds popped-frame residue, so a once-poisoned
	// band cannot distinguish residue from misuse; within one call, the bytes
	// below the trap-time RSP are provably below every active frame.
	entryFrame := uint64(startup.blockAddr) - 8 // just below the auxv block
	checkRedZone := func(b emu.Backend, where string) {
		rsp, _ := b.RegRead(amd64.RSP)
		rz, err := b.MemRead(emu.GuestAddr(rsp-128), 128)
		if err != nil {
			t.Errorf("%s: red zone read below RSP %#x: %v", where, rsp, err)
			return
		}
		for i, by := range rz {
			if by != 0xA5 {
				t.Errorf("%s: red zone byte [%d] below RSP %#x clobbered (%#x)", where, i, rsp, by)
			}
		}
	}
	// Real guest syscalls: UC_HOOK_INSN(UC_X86_INS_SYSCALL) -> Decode ->
	// kernel.Dispatch -> EncodeResult. Dispatch is never invoked directly in
	// this test — only through the trap.
	scFired := 0
	if _, err := be.InstallTrap(emu.TrapSyscall, func(b emu.Backend, kind emu.TrapKind) {
		scFired++
		checkRedZone(b, "syscall trap")
		kctx.Dispatch()
	}); err != nil {
		t.Fatal(err)
	}
	// Host stubs: UC_HOOK_INTR (int3). Trap identity by ADDRESS (StubManager
	// metadata), never by bytes: RIP points one byte past the int3.
	hostFired := 0
	if _, err := be.InstallTrap(emu.TrapHostCall, func(b emu.Backend, kind emu.TrapKind) {
		checkRedZone(b, "host trap")
		pc, _ := b.RegRead(cpuArch.PC())
		desc, ok := stubMgr.Hit(emu.GuestAddr(pc - 1))
		if !ok {
			t.Errorf("trap at %#x-1 is not a known stub", pc)
			_ = b.Stop()
			return
		}
		name, cut := cutPrefix(desc.Name, "host:")
		if !cut {
			t.Errorf("stub %q is not a host binding", desc.Name)
			_ = b.Stop()
			return
		}
		hf, ok := itab.LookupSymbol(name)
		if !ok {
			t.Errorf("no host function bound for %q", name)
			_ = b.Stop()
			return
		}
		hostFired++
		// The documented interposition return path (DESIGN.md §3.8):
		// HostFunc -> WriteResult -> ReturnFromCall (pops the guest return
		// address; the stub's trailing ret never executes).
		if err := callABI.WriteResult(b, arch.CallResult{Value: hf(be)}); err != nil {
			t.Errorf("WriteResult: %v", err)
		}
		if err := callABI.ReturnFromCall(b); err != nil {
			t.Errorf("ReturnFromCall: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	// --- 8. SysV call driver: args in registers, return address on the ----
	// stack, 16-byte alignment honored (entry RSP ≡ 8 mod 16, i.e. RSP was
	// 16-aligned before the implicit `call`). The entry frame sits just below
	// the auxv block the StartupABI materialized (see step 7).
	entryRSP := entryFrame
	var sent [8]byte
	binary.LittleEndian.PutUint64(sent[:], sentinel)
	if err := be.MemWrite(emu.GuestAddr(entryRSP), sent[:]); err != nil { // the pushed return address
		t.Fatal(err)
	}
	if err := be.RegWrite(amd64.RSP, entryRSP); err != nil {
		t.Fatal(err)
	}

	call := func(name string, args ...uint64) uint64 {
		t.Helper()
		fn, ok := img.Exports[name]
		if !ok {
			t.Fatalf("export %s not found", name)
		}
		rspBefore, _ := be.RegRead(amd64.RSP)
		// Freshly poison this call's red-zone band (see step 7 for why the
		// poisoning is per-call).
		poison := make([]byte, 0x800)
		for i := range poison {
			poison[i] = 0xA5
		}
		if err := be.MemWrite(emu.GuestAddr(rspBefore-0x800), poison); err != nil {
			t.Fatal(err)
		}
		for i, a := range args {
			if err := be.RegWrite(callABI.Arg(i), a); err != nil {
				t.Fatalf("%s: write arg %d: %v", name, i, err)
			}
		}
		if err := be.Start(emu.GuestAddr(base+fn), emu.GuestAddr(sentinel)); err != nil {
			t.Fatalf("%s: run: %v", name, err)
		}
		ret, err := be.RegRead(callABI.Ret())
		if err != nil {
			t.Fatalf("%s: read result: %v", name, err)
		}
		// Stack fully restored: every frame (guest + interposed host) popped
		// exactly its own return address.
		rspAfter, _ := be.RegRead(amd64.RSP)
		if rspAfter != rspBefore+8 {
			t.Fatalf("%s: RSP %#x -> %#x, want %#x (one frame popped, nothing leaked)",
				name, rspBefore, rspAfter, rspBefore+8)
		}
		// The engine stops at the sentinel popped by the function's ret.
		pc, _ := be.RegRead(amd64.RIP)
		if pc != sentinel {
			t.Fatalf("%s: RIP = %#x, want the sentinel %#x (normal return)", name, pc, sentinel)
		}
		// Restore RSP for the next call (the popped sentinel slot is dead).
		if err := be.RegWrite(amd64.RSP, rspBefore); err != nil {
			t.Fatal(err)
		}
		return ret
	}

	// --- 9. the actual calls ------------------------------------------------
	if got := call("add", 2, 3); got != 5 {
		t.Fatalf("add(2,3) = %d, want 5", got)
	}
	if got := call("sum6", 1, 2, 3, 4, 5, 6); got != 21 {
		t.Fatalf("sum6(1..6) = %d, want 21 (RDI/RSI/RDX/RCX/R8/R9)", got)
	}
	if got := call("via_fptr_table"); got != 10 {
		t.Fatalf("via_fptr_table() = %d, want 10 (RELATIVE + R_X86_64_64 entries)", got)
	}
	if got := call("call_host", 41); got != 83 {
		t.Fatalf("call_host(41) = %d, want 83 (host_magic 41*2 + 1)", got)
	}
	if hostFired == 0 {
		t.Fatal("host interposition never fired")
	}
	if got := call("call_host_twice", 10); got != 42 {
		t.Fatalf("call_host_twice(10) = %d, want 42 (repeated interposition, stack intact)", got)
	}
	if got := call("guest_getpid"); got != 4242 {
		t.Fatalf("guest_getpid() = %d, want 4242 (real syscall through UC_HOOK_INSN -> kernel)", got)
	}
	if scFired != 1 {
		t.Fatalf("syscall trap fired %d times, want exactly 1", scFired)
	}
}

// cutPrefix is strings.CutPrefix restated (this package tests predate the
// helper being needed here; keep the test self-contained).
func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}
