package emulator

// P10-2a WrapSymbol — stub-driven function wrap on the INTERPOSABLE
// binding paths.
//
// Flow (persistent, per call that arrives through a redirected binding):
//
//	guest caller → GOT/data slot → WrapEntry stub (HostCall trap)
//	  pre: capture entry args + the caller's real return address,
//	       InstallReturnContinuation(post stub), PC ← original
//	original function runs (real code, real syscalls)
//	  its `ret` lands on the post stub (the continuation)
//	WrapPost stub (HostCall trap)
//	  post: ReturnValue() = the ORIGINAL's result (P9 exit slot),
//	        Arg(i) = the captured entry args; the callback's return
//	        value replaces the original's
//	  ReturnTo(real return address) → guest caller resumes
//
// Zero code hooks, zero text patching, zero TB-timing dependence: the entry
// interception IS the binding (data-slot redirect), and both continuations
// are ordinary HostCall traps (the SVC machinery golem already runs).
//
// Scope (v1): only calls that arrive through a redirected RESOLVED binding
// (ELF/GOT relocations and loader-resolved data pointers pointing at the
// original). Guest-internal direct branches to the function body do not
// pass through any binding and are NOT wrapped — WrapSymbol reports that
// honestly (no resolvable binding → error) instead of pretending.
//
// v1 limitations, stated so they can never harden into invisible assumptions:
//
//   - Binding discovery is RELOCATION-BACKED SCANNING: walk relocations
//     naming the symbol, keep slots whose current value equals the raw
//     symbol address (raw, never normalized — Thumb bit0 and other
//     guest-visible pointer bits must survive storage; normalization is
//     for identity checks only). Deliberately not the final abstraction:
//     slot values don't uniquely identify a binding once lazy PLTs,
//     addends, aliases, weak/preempted symbols, IFUNCs or Mach-O
//     chained fixups exist. Long-term shape: the loader records a
//     BindingSite index at bind time and WrapSymbol rebinds sites through
//     it — the scan is the v1 stopgap, not the architecture.
//   - The frame stack is EXECUTION-CONTEXT scoped: golem runs a single
//     guest execution context, so one []WrapFrame per wrapped symbol is
//     correct today. Concurrent guest threads sharing a wrap are NOT
//     supported — per-context frames are the prerequisite for that.
//   - Rebinding writes through HOST-side memory access: guest page
//     protection is not consulted (unicorn host-write semantics — the
//     known backend leak, P7 debt). Safe today only because golem's
//     loader applies ELF segment protections but NOT GNU_RELRO, so
//     binding slots are writable by segment contract. When RELRO lands,
//     the permission exception must move into a loader-owned Rebind
//     path — never a global host-write backdoor.

import (
	"errors"
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// ErrAlreadyWrapped: WrapSymbol refuses a symbol that already has a live
// wrap (v1 pins this — no implicit chaining; a future binding stack is the
// feature that would relax it).
var ErrAlreadyWrapped = errors.New("already wrapped")

type wrapStubKind uint8

const (
	wrapKindEntry wrapStubKind = iota
	wrapKindPost
)

// WrapFrame is one in-flight wrapped call (P10): recursion and nesting each
// push their own frame; the post continuation pops the innermost.
type WrapFrame struct {
	Original      uint64  // the wrapped function's entry
	ReturnAddress uint64  // where the REAL caller resumes
	Args          []Value // entry arguments (register portion, ≤ 8 words)
}

type wrapRuntime struct {
	kind      wrapStubKind
	symbol    string
	original  uint64
	entryStub uint64
	postStub  uint64
	post      func(h *Hook) uint64
	slots     []wrapSlot // redirected bindings (addr, original value) for stop()
	frames    []*WrapFrame
}

type wrapSlot struct {
	addr uint64
	orig uint64
}

func wrapEntryName(name string) string { return "__golem_wrap_entry_" + name }
func wrapPostName(name string) string  { return "__golem_wrap_post_" + name }

// WrapSymbol wraps an exported symbol on the INTERPOSABLE binding paths:
// every caller whose binding was resolved through the symbol resolver
// (imports, GOT/data relocations, loader-produced pointers recorded at load)
// is redirected to a WrapEntry HostCall stub. The original function runs
// unmodified; its result is observed through h.ReturnValue() in the post
// callback and may be REPLACED by the callback's return value.
//
// Not covered (v1, honest scope): guest-INTERNAL direct branches to the
// function body — they pass through no binding. If no resolvable binding
// exists, WrapSymbol errors instead of pretending.
//
// The wrap is persistent: every call through the redirected bindings wraps
// again. stop() restores the original bindings.
func (e *Emulator) WrapSymbol(name string, post func(h *Hook) uint64) (stop func(), err error) {
	if post == nil {
		return nil, errors.New("WrapSymbol: nil post callback")
	}
	if e.poisonErr != nil {
		return nil, fmt.Errorf("emulator poisoned: %w", e.poisonErr)
	}
	original, ok := e.Sym(name)
	if !ok {
		return nil, fmt.Errorf("WrapSymbol: symbol %q not found in any loaded module", name)
	}
	if _, dup := e.wraps[name]; dup {
		return nil, fmt.Errorf("WrapSymbol %q: %w", name, ErrAlreadyWrapped)
	}
	if e.wrapStubs == nil {
		e.wrapStubs = map[string]*wrapRuntime{}
	}

	entryStub, err := e.stubMgr.Allocate(arch.StubHostCall, wrapEntryName(name))
	if err != nil {
		return nil, fmt.Errorf("WrapSymbol %q: entry stub: %w", name, err)
	}
	postStub, err := e.stubMgr.Allocate(arch.StubHostCall, wrapPostName(name))
	if err != nil {
		return nil, fmt.Errorf("WrapSymbol %q: post stub: %w", name, err)
	}

	rt := &wrapRuntime{
		kind:      wrapKindEntry,
		symbol:    name,
		original:  original,
		entryStub: uint64(entryStub),
		postStub:  uint64(postStub),
		post:      post,
	}
	e.wrapStubs[wrapEntryName(name)] = rt
	e.wrapStubs[wrapPostName(name)] = rt // 同一 runtime 承载 entry+post：帧栈必须在两桩间共享（递归/嵌套正确弹栈的前提）

	// Redirect every resolvable binding of `name` to the entry stub. Only
	// slots that currently hold the ORIGINAL are touched — slots claimed by
	// other interpositions keep their precedence. Slots are read/written at
	// the TARGET's pointer width: a 4-byte ARM32 slot sits next to live data
	// (an 8-byte read compares in the neighbor's bits and never matches; an
	// 8-byte write clobbers it — both found live, P10-2d).
	ptrSize := uint64(e.arch.PtrSize())
	readSlot := func(addr uint64) (uint64, error) {
		if ptrSize == 4 {
			v, err := e.ReadU32(addr)
			return uint64(v), err
		}
		return e.ReadU64(addr)
	}
	writeSlot := func(addr uint64, v uint64) error {
		if ptrSize == 4 {
			return e.WriteU32(addr, uint32(v))
		}
		return e.WriteU64(addr, v)
	}
	for _, m := range e.Modules() {
		for _, r := range m.Img.Relocs {
			if int(r.Sym) >= len(m.Img.Syms) {
				continue
			}
			if m.Img.Syms[r.Sym].Name != name {
				continue
			}
			slot := m.Base + r.Offset
			cur, rerr := readSlot(slot)
			if rerr != nil || cur != original {
				continue
			}
			if werr := writeSlot(slot, uint64(entryStub)); werr == nil {
				rt.slots = append(rt.slots, wrapSlot{addr: slot, orig: original})
			}
		}
	}
	if len(rt.slots) == 0 {
		delete(e.wrapStubs, wrapEntryName(name))
		delete(e.wrapStubs, wrapPostName(name))
		// The two stubs allocated above are not freed (StubManager has no
		// Free): a failed attempt leaks its stub area — finite, bounded by
		// the number of failed attempts.
		return nil, fmt.Errorf("WrapSymbol %q: no resolvable binding found to redirect (guest-internal direct calls are not wrappable)", name)
	}
	e.wraps[name] = rt // live-wrap registry: backs the duplicate check above

	stop = func() {
		for _, s := range rt.slots {
			if ptrSize == 4 {
				_ = e.WriteU32(s.addr, uint32(s.orig))
			} else {
				_ = e.WriteU64(s.addr, s.orig)
			}
		}
		delete(e.wrapStubs, wrapEntryName(name))
		delete(e.wrapStubs, wrapPostName(name))
		delete(e.wraps, name)
	}
	return stop, nil
}

// onWrapTrap dispatches a wrap stub's HostCall trap (P10): the entry
// continuation captures the call and redirects to the original; the post
// continuation runs the callback on the original's live result and resumes
// the real caller.
func (e *Emulator) onWrapTrap(w *wrapRuntime, isPost bool, b emu.Backend) {
	if !isPost {
		realRet, err := e.callABI.ReadReturnAddress(b)
		if err != nil {
			// No answerable return address: run the original without a post
			// continuation rather than guessing.
			_ = e.callABI.ReturnTo(b, emu.GuestAddr(w.original))
			return
		}
		var args []Value
		if a, aerr := e.callABI.ReadArgs(b, 8); aerr == nil {
			for _, v := range a {
				args = append(args, Value{Kind: Word, Raw: v})
			}
		}
		if e.cfg.Verbose {
			x0, _ := b.RegRead(emu.Reg(0))
			fmt.Printf("[wrap-entry %s] X0=%#x realRet=%#x → original %#x (args captured=%d)\n", w.symbol, x0, uint64(realRet), w.original, len(args))
		}
		w.frames = append(w.frames, &WrapFrame{Original: w.original, ReturnAddress: uint64(realRet), Args: args})
		if err := e.callABI.InstallReturnContinuation(b, emu.GuestAddr(w.postStub)); err != nil {
			// Continuation unsupported: degrade — the original runs, no post.
			w.frames = w.frames[:len(w.frames)-1]
			_ = e.callABI.ReturnTo(b, emu.GuestAddr(w.original))
			return
		}
		_ = e.callABI.ReturnTo(b, emu.GuestAddr(w.original))
		return
	}
	// post continuation. A post trap with no frame (stale guest pointer after
	// stop(), framework bug) answers nothing — the engine resumes past the
	// SVC and the caller keeps the original's live result; no hang, no fake.
	if len(w.frames) == 0 {
		return
	}
	fr := w.frames[len(w.frames)-1]
	w.frames = w.frames[:len(w.frames)-1]
	if e.cfg.Verbose {
		a0 := uint64(0)
		if len(fr.Args) > 0 {
			a0 = fr.Args[0].Raw
		}
		fmt.Printf("[wrap-post %s] rv observed, resume %#x (frames left=%d, arg0=%#x)\n", w.symbol, fr.ReturnAddress, len(w.frames), a0)
	}
	h := &Hook{e: e, kind: HookFunctionExit, wrapArgs: frameWords(fr)}
	final := w.post(h) // may return fr-return via h.ReturnValue(); replaces it
	_ = e.callABI.WriteResult(b, arch.CallResult{Value: final})
	_ = e.callABI.ReturnTo(b, emu.GuestAddr(fr.ReturnAddress))
}

func frameWords(fr *WrapFrame) []uint64 {
	out := make([]uint64, len(fr.Args))
	for i, v := range fr.Args {
		out[i] = v.Raw
	}
	return out
}
