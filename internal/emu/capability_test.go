package emu

import (
	"testing"
	"unsafe"
)

// P2.5a capability-probe tests (DESIGN.md invariant 14): consumers detect an
// optional engine ability by type-asserting the capability interface. A
// backend that implements only the Backend core must fail EVERY capability
// probe; one that implements a capability must pass exactly that probe.

// coreOnlyBE implements ONLY the Backend core interface — no capabilities.
type coreOnlyBE struct{}

func (coreOnlyBE) RegRead(Reg) (uint64, error)                            { return 0, nil }
func (coreOnlyBE) RegWrite(Reg, uint64) error                             { return nil }
func (coreOnlyBE) ReadGPRegs() ([34]uint64, error)                        { return [34]uint64{}, nil }
func (coreOnlyBE) MemMap(GuestAddr, uint64, int) error                    { return nil }
func (coreOnlyBE) MemUnmap(GuestAddr, uint64) error                       { return nil }
func (coreOnlyBE) MemProtect(GuestAddr, uint64, int) error                { return nil }
func (coreOnlyBE) MemWrite(GuestAddr, []byte) error                       { return nil }
func (coreOnlyBE) MemRead(GuestAddr, uint64) ([]byte, error)              { return nil, nil }
func (coreOnlyBE) MemMapPtr(GuestAddr, uint64, int, unsafe.Pointer) error { return nil }
func (coreOnlyBE) InstallTrap(TrapKind, TrapHandler) (HookHandle, error)  { return nil, nil }
func (coreOnlyBE) Start(GuestAddr, GuestAddr) error                       { return nil }
func (coreOnlyBE) StartCount(GuestAddr, GuestAddr, uint64) error          { return nil }
func (coreOnlyBE) Stop() error                                            { return nil }
func (coreOnlyBE) Close() error                                           { return nil }

// fullCapsBE additionally implements every capability interface defined today
// (mirroring the unicorn backend's fact set).
type fullCapsBE struct{ coreOnlyBE }

func (fullCapsBE) HookCode(GuestAddr, GuestAddr, CodeHookFunc) (HookHandle, error) {
	return nil, nil
}
func (fullCapsBE) HookInterrupt(InterruptHookFunc) (HookHandle, error)   { return nil, nil }
func (fullCapsBE) HookMemInvalid(MemInvalidHookFunc) (HookHandle, error) { return nil, nil }
func (fullCapsBE) HookMemRead(GuestAddr, GuestAddr, MemReadHookFunc) (HookHandle, error) {
	return nil, nil
}
func (fullCapsBE) HookMemWrite(GuestAddr, GuestAddr, MemWriteHookFunc) (HookHandle, error) {
	return nil, nil
}
func (fullCapsBE) SaveContext() (CPUContext, error) { return nil, nil }
func (fullCapsBE) RestoreContext(CPUContext) error  { return nil }
func (fullCapsBE) FlushCache() error                { return nil }

func TestCapabilityProbeCoreOnlyBackend(t *testing.T) {
	var be Backend = coreOnlyBE{}
	if _, ok := be.(InstructionHooker); ok {
		t.Error("core-only backend must NOT satisfy InstructionHooker")
	}
	if _, ok := be.(InterruptHooker); ok {
		t.Error("core-only backend must NOT satisfy InterruptHooker")
	}
	if _, ok := be.(InvalidMemHooker); ok {
		t.Error("core-only backend must NOT satisfy InvalidMemHooker")
	}
	if _, ok := be.(MemReadHooker); ok {
		t.Error("core-only backend must NOT satisfy MemReadHooker")
	}
	if _, ok := be.(MemWriteHooker); ok {
		t.Error("core-only backend must NOT satisfy MemWriteHooker")
	}
	if _, ok := be.(ContextManager); ok {
		t.Error("core-only backend must NOT satisfy ContextManager")
	}
	if _, ok := be.(CacheInvalidator); ok {
		t.Error("core-only backend must NOT satisfy CacheInvalidator")
	}
}

func TestCapabilityProbeFullCapsBackend(t *testing.T) {
	var be Backend = fullCapsBE{}
	for name, ok := range map[string]bool{
		"InstructionHooker": func() bool { _, ok := be.(InstructionHooker); return ok }(),
		"InterruptHooker":   func() bool { _, ok := be.(InterruptHooker); return ok }(),
		"InvalidMemHooker":  func() bool { _, ok := be.(InvalidMemHooker); return ok }(),
		"MemReadHooker":     func() bool { _, ok := be.(MemReadHooker); return ok }(),
		"MemWriteHooker":    func() bool { _, ok := be.(MemWriteHooker); return ok }(),
		"ContextManager":    func() bool { _, ok := be.(ContextManager); return ok }(),
		"CacheInvalidator":  func() bool { _, ok := be.(CacheInvalidator); return ok }(),
	} {
		if !ok {
			t.Errorf("full-caps backend must satisfy %s", name)
		}
	}
}

// TestGuestAddr pins the type split (invariant 15): GuestAddr is a distinct
// uint64-based type, so the migrated core-interface signatures take it — the
// compile-time assertions below are the actual test; the runtime body just
// keeps the values honest.
func TestGuestAddr(t *testing.T) {
	var a GuestAddr = 0x40000000
	if uint64(a) != 0x40000000 {
		t.Fatalf("GuestAddr round-trip: %#x", uint64(a))
	}
	// Signature migration check: these closures only compile against the
	// GuestAddr-based core interface.
	var _ func(Backend) error = func(b Backend) error { return b.MemMap(a, 0x1000, ProtAll) }
	var _ func(Backend) error = func(b Backend) error { return b.Start(a, a+0x100) }
	var _ func(Backend) ([]byte, error) = func(b Backend) ([]byte, error) { return b.MemRead(a, 8) }
	var _ CodeHookFunc = func(Backend, GuestAddr, uint32) {}
	var _ MemInvalidHookFunc = func(Backend, int, GuestAddr, int, int64) bool { return false }
	var _ MemReadHookFunc = func(Backend, GuestAddr, int) {}
	var _ MemWriteHookFunc = func(Backend, GuestAddr, int, int64) {}
}
