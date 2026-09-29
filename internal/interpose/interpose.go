// Package interpose implements guest-function interposition WITHOUT patching
// guest code (DESIGN.md §3.8, invariants 11/12): a StubManager that owns every
// guest trampoline (unresolved-import stubs, host-function stubs, JNI/JavaVM
// table slots) and an InterposeTable that binds host functions to guest
// symbols/entry addresses so a backend execution hook can intercept calls at
// the entry point.
//
// Dependency rule: interpose → {emu, arch, memory}. It must never import the
// emulator package; the emulator adapts its own callback context (Hook) to
// the CallContext interface defined here.
package interpose

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
	"github.com/isesword/golem/internal/memory"
)

// StubDescriptor describes one allocated guest trampoline.
type StubDescriptor struct {
	Kind arch.StubKind
	Name string // import name, "host:<name>", "JNIEnv[i]", ... (debug/profile identity)
}

// StubManager manages every guest trampoline (DESIGN.md §3.8, invariants
// 11/12):
// JNI/JavaVM table slots all come from here. Slots are bump-allocated from the
// AddressSpace's PurposeStub region (the single VA allocation entry), filled
// with arch.StubEncoder bytes, and tracked by address so a trap can be
// classified by its SOURCE ADDRESS — never by anything in the emitted bytes
// (see arch.StubEncoder).
type StubManager interface {
	// Allocate carves a fresh stub slot, writes the encoded trampoline into
	// guest memory, and records its descriptor.
	Allocate(kind arch.StubKind, name string) (emu.GuestAddr, error)
	// Lookup reports the descriptor of the stub at pc (the trap source
	// address), or false if pc is not a known stub.
	Lookup(pc emu.GuestAddr) (StubDescriptor, bool)
	// Hit records one trap hit on the stub at pc and returns its descriptor
	// (false if unknown). Hit counting continues the emulator's former
	// stubHits semantics: counts accumulate BY NAME, for debugging/profiling.
	Hit(pc emu.GuestAddr) (StubDescriptor, bool)
	// Hits returns the accumulated hit count for a stub name.
	Hits(name string) int
	// HitCounts returns a snapshot of all per-name hit counts (debug/profile).
	HitCounts() map[string]int
}

// stubManager is the StubManager implementation.
type stubManager struct {
	as   *memory.AddressSpace
	enc  arch.StubEncoder
	be   emu.Backend
	desc map[emu.GuestAddr]StubDescriptor
	hits map[string]int
}

// NewStubManager builds a StubManager over the address space's stub region.
// be is used only to write the trampoline bytes at Allocate time.
func NewStubManager(as *memory.AddressSpace, enc arch.StubEncoder, be emu.Backend) StubManager {
	return &stubManager{
		as:   as,
		enc:  enc,
		be:   be,
		desc: map[emu.GuestAddr]StubDescriptor{},
		hits: map[string]int{},
	}
}

// Allocate implements StubManager. The slot size is exactly the encoded
// trampoline length (AArch64: 8 bytes, the historical stub stride).
func (m *stubManager) Allocate(kind arch.StubKind, name string) (emu.GuestAddr, error) {
	code, err := m.enc.EmitStub(kind)
	if err != nil {
		return 0, fmt.Errorf("interpose: stub %q: %w", name, err)
	}
	addr, err := m.as.Alloc(memory.PurposeStub, uint64(len(code)))
	if err != nil {
		return 0, fmt.Errorf("interpose: stub %q: %w", name, err)
	}
	if err := m.be.MemWrite(addr, code); err != nil {
		return 0, fmt.Errorf("interpose: stub %q: write trampoline at %#x: %w", name, uint64(addr), err)
	}
	m.desc[addr] = StubDescriptor{Kind: kind, Name: name}
	return addr, nil
}

// Lookup implements StubManager.
func (m *stubManager) Lookup(pc emu.GuestAddr) (StubDescriptor, bool) {
	d, ok := m.desc[pc]
	return d, ok
}

// Hit implements StubManager.
func (m *stubManager) Hit(pc emu.GuestAddr) (StubDescriptor, bool) {
	d, ok := m.desc[pc]
	if ok {
		m.hits[d.Name]++
	}
	return d, ok
}

// Hits implements StubManager.
func (m *stubManager) Hits(name string) int { return m.hits[name] }

// HitCounts implements StubManager.
func (m *stubManager) HitCounts() map[string]int {
	out := make(map[string]int, len(m.hits))
	for k, v := range m.hits {
		out[k] = v
	}
	return out
}

// CallContext is the minimal guest-machine surface a host function sees when
// an interposed call fires: argument/result registers and guest memory. It is
// defined here — not in emu — because it is the interposition callback's
// contract; the emulator's Hook adapts to it (the dependency rule forbids
// interpose from importing emulator).
type CallContext interface {
	RegRead(r emu.Reg) (uint64, error)
	RegWrite(r emu.Reg, v uint64) error
	MemRead(addr emu.GuestAddr, size uint64) ([]byte, error)
	MemWrite(addr emu.GuestAddr, data []byte) error
}

// HostFunc is a host-side stand-in for a guest function; its return value
// becomes the call's integer result, written back via arch.CallABI.
type HostFunc func(ctx CallContext) uint64

// InterposeTable is patch-free function replacement (DESIGN.md §3.8,
// invariant 11 mechanism ③):
//
//	BindSymbol   — link-time binding, resolved through the symbol layer
//	               (wired to loader.SymbolResolver in P3.5).
//	BindAddress  — run-time binding of an existing code address; a backend
//	               execution hook at that entry intercepts the call:
//	               LookupAddress hit → run the HostFunc →
//	               CallABI.WriteResult → CallABI.ReturnFromCall.
type InterposeTable interface {
	// BindSymbol binds a host function to a symbol name (link-time path).
	BindSymbol(name string, h HostFunc)
	// LookupSymbol returns the host function bound to a symbol name.
	LookupSymbol(name string) (HostFunc, bool)
	// BindAddress binds a host function to a guest entry address. Binding an
	// already-bound address is an error: each interposed entry owns exactly
	// one execution hook, and silently stacking two would fire both.
	BindAddress(addr emu.GuestAddr, h HostFunc) error
	// LookupAddress returns the host function bound to a guest entry address.
	LookupAddress(addr emu.GuestAddr) (HostFunc, bool)
}

// interposeTable is the InterposeTable implementation: two plain maps, one
// per binding path. The run-time dispatch (entry hook, result write-back,
// return flow) lives in the composition root (emulator), which owns the
// backend and the CallABI.
type interposeTable struct {
	byName map[string]HostFunc
	byAddr map[emu.GuestAddr]HostFunc
}

// NewInterposeTable returns an empty InterposeTable.
func NewInterposeTable() InterposeTable {
	return &interposeTable{
		byName: map[string]HostFunc{},
		byAddr: map[emu.GuestAddr]HostFunc{},
	}
}

func (t *interposeTable) BindSymbol(name string, h HostFunc) { t.byName[name] = h }

func (t *interposeTable) LookupSymbol(name string) (HostFunc, bool) {
	h, ok := t.byName[name]
	return h, ok
}

func (t *interposeTable) BindAddress(addr emu.GuestAddr, h HostFunc) error {
	if _, dup := t.byAddr[addr]; dup {
		return fmt.Errorf("interpose: address %#x already interposed", uint64(addr))
	}
	t.byAddr[addr] = h
	return nil
}

func (t *interposeTable) LookupAddress(addr emu.GuestAddr) (HostFunc, bool) {
	h, ok := t.byAddr[addr]
	return h, ok
}
