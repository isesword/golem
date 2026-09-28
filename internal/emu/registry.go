package emu

import (
	"fmt"
	"os"
	"strings"
)

// This file is the engine-selection layer — the Go analogue of unidbg's
// backend factory registry (com.github.unidbg.arm.backend.BackendFactory),
// where you pick the CPU engine at VM creation. Each concrete backend lives in
// its own build-tag-gated file and registers itself from an init():
//
//	unicorn_purego.go (//go:build unicorn && darwin||linux) -> Register("unicorn", ...)
//	winengine/       (//go:build windows)    -> [PLANNED, not implemented —
//	                                           solution pending the Windows minimal repro; see
//	                                           ARCHITECTURE.md "待验证决策". Until it lands, a
//	                                               Windows build with -tags unicorn registers NO
//	                                               engine and New returns ErrNoBackend.]
//
// So which engines exist in a binary is decided at build time (`-tags`), and
// which one is used is decided at run time (arg / $GOLEM_ENGINE / default).
// A pure-Go build registers nothing; New then returns ErrNoBackend, exactly as
// the old stub backend did.

// Factory builds a fresh backend instance.
type Factory func() (Backend, error)

var (
	registry = map[string]Factory{}
	regOrder []string // registration order, for deterministic listing/fallback
)

// Register makes a backend available under name (called from a backend's
// init()). Duplicate names overwrite but keep their first position in the order.
func Register(name string, f Factory) {
	if f == nil {
		return
	}
	name = strings.ToLower(name)
	if _, dup := registry[name]; !dup {
		regOrder = append(regOrder, name)
	}
	registry[name] = f
}

// Available lists the engines compiled into this binary, in registration order.
func Available() []string { return append([]string(nil), regOrder...) }

// defaultPreference is the order tried when no engine is requested explicitly.
// Only one engine ships in this module; the slice keeps the selection machinery
// ready for future backends (first compiled-in preference wins).
var defaultPreference = []string{"unicorn"}

// New returns the default backend (NewNamed with an empty name).
func New() (Backend, error) { return NewNamed("") }

// Resolve reports which engine name NewNamed(name) would pick, without building
// it — handy for logging the active engine. Selection order:
//  1. the explicit name argument, if non-empty;
//  2. else $GOLEM_ENGINE;
//  3. else the first of defaultPreference that is compiled in;
//  4. else the first registered engine.
func Resolve(name string) (string, error) {
	if name == "" {
		name = strings.TrimSpace(os.Getenv("GOLEM_ENGINE"))
	}
	if name == "" {
		for _, p := range defaultPreference {
			if _, ok := registry[p]; ok {
				return p, nil
			}
		}
		if len(regOrder) > 0 {
			return regOrder[0], nil
		}
		return "", ErrNoBackend
	}
	name = strings.ToLower(name)
	if _, ok := registry[name]; !ok {
		if len(regOrder) == 0 {
			return "", fmt.Errorf("emu: engine %q requested but none compiled in; build with -tags unicorn", name)
		}
		return "", fmt.Errorf("emu: engine %q not compiled in (available: %s); rebuild with -tags %s",
			name, strings.Join(regOrder, ", "), name)
	}
	return name, nil
}

// NewNamed builds the engine selected by Resolve(name).
func NewNamed(name string) (Backend, error) {
	chosen, err := Resolve(name)
	if err != nil {
		return nil, err
	}
	return registry[chosen]()
}
