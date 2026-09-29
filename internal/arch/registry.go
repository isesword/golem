package arch

import "fmt"

// --- registry (same style as internal/emu/registry.go) -------------------

// regEntry is the full target triple registered under one (ID, Variant): the
// CPU properties, the calling convention, and the stub encoder (DESIGN.md
// §3.2 — a Target composes exactly one of each).
type regEntry struct {
	arch    Arch
	callABI CallABI
	stubEnc StubEncoder
}

type regKey struct {
	id ID
	v  Variant
}

var registry = map[regKey]regEntry{}

// Register makes an (Arch, CallABI, StubEncoder) triple available under
// (id, v); called from an implementation package's init(). As in
// emu.Register, a duplicate key overwrites — registration happens at init
// time, so the last linked implementation wins. A registration with any nil
// component is ignored: a partial triple can never serve a Target.
func Register(id ID, v Variant, a Arch, c CallABI, s StubEncoder) {
	if a == nil || c == nil || s == nil {
		return
	}
	registry[regKey{id, v}] = regEntry{arch: a, callABI: c, stubEnc: s}
}

// Resolve returns the (Arch, CallABI, StubEncoder) triple registered for
// (id, v). An unknown pair is an error naming the missing implementation —
// the fix is to import the relevant arch/<name> package for its init().
func Resolve(id ID, v Variant) (Arch, CallABI, StubEncoder, error) {
	if e, ok := registry[regKey{id, v}]; ok {
		return e.arch, e.callABI, e.stubEnc, nil
	}
	return nil, nil, nil, fmt.Errorf("arch: no target registered for id=%d variant=%d (import the arch/<name> package for its init())", id, v)
}
