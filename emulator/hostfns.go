package emulator

import (
	"fmt"

	"github.com/isesword/golem/internal/arch"
	"github.com/isesword/golem/internal/emu"
)

// registerHostFns registers the libc functions the bound platform Runtime
// opts into (P5b.5 — pure feature tests on Runtime data, no platform
// dispatch): we implement them in Go because the guest libc's versions need
// a fully bootstrapped libc (which we don't run). They override the real
// exports during symbol resolution — since P3.5 by NAME, via
// InterposeTable.BindSymbol + the HostResolver element of the boot resolver
// chain. A Runtime carrying none of these features binds nothing at all
// (e.g. Darwin today).
func registerHostFns(e *Emulator) {
	rt := e.rt
	// getauxval exists exactly on platforms with an auxv: the lookup serves
	// the StartupABI-built vector (see hostGetauxval).
	if rt.AuxvLookup != nil {
		e.bindHostFn("getauxval", hostGetauxval)
	}
	// pthread_create can't run a real thread (we can't nest uc_emu_start),
	// so platforms that opt in model it as a cooperative scheduler fiber
	// and no-op join/detach as success. Threads the .so spawns (watchdogs /
	// bg init) are skipped; revisit if the call path needs a thread's
	// output.
	if rt.PthreadStubs {
		e.bindHostFn("pthread_create", hostPthreadCreate)
		e.bindHostFn("pthread_join", hostRet0)
		e.bindHostFn("pthread_detach", hostRet0)
	}
	// __system_property_get: only override (for the loaded .so) when the
	// host app supplies a provider through the platform config; otherwise
	// leave it to the bundled /dev/__properties__.
	if rt.Interop != nil && rt.Interop.PropertyProvider != nil {
		e.bindHostFn("__system_property_get", hostSystemPropertyGet)
	}
}

// hostArgs reads the first n integer arguments of the in-flight guest call
// through the CallABI (register portion + stack spill). A read failure has no
// error channel on the hostFn contract — return nil and let the caller bail
// with a zeroed result rather than panic across the backend trampoline.
func (e *Emulator) hostArgs(b emu.Backend, n int) []uint64 {
	args, err := e.callABI.ReadArgs(b, n)
	if err != nil {
		if e.cfg.Verbose {
			fmt.Printf("[hostfn] ReadArgs(%d): %v\n", n, err)
		}
		return nil
	}
	return args
}

// hostResult writes the hostFn's result back per the CallABI.
func (e *Emulator) hostResult(b emu.Backend, v uint64) {
	_ = e.callABI.WriteResult(b, arch.CallResult{Value: v})
}

// hostSystemPropertyGet implements __system_property_get(name, value) via
// the platform config's PropertyProvider: write the value (NUL-terminated,
// PROP_VALUE_MAX-1) and return its length, or 0 when the provider doesn't
// supply the key.
func hostSystemPropertyGet(e *Emulator, b emu.Backend) {
	args := e.hostArgs(b, 2)
	if args == nil {
		return
	}
	namePtr, buf := args[0], args[1]
	name, _ := e.ReadCStr(namePtr)
	v, ok := e.rt.Interop.PropertyProvider(name)
	if !ok {
		if buf != 0 {
			_ = e.be.MemWrite(emu.GuestAddr(buf), []byte{0})
		}
		e.hostResult(b, 0)
		return
	}
	if len(v) > 91 { // PROP_VALUE_MAX (92) minus the NUL
		v = v[:91]
	}
	if buf != 0 {
		_ = e.be.MemWrite(emu.GuestAddr(buf), append([]byte(v), 0))
	}
	e.hostResult(b, uint64(len(v)))
}

// hostPthreadCreate(thread*, attr, start, arg) registers the start routine as a
// scheduler fiber (its own stack + CPU context) and returns success with a fake
// tid. We can't run guest threads concurrently, so the fiber runs cooperatively
// later, when RunThreads drives the scheduler (see scheduler.go).
func hostPthreadCreate(e *Emulator, b emu.Backend) {
	args := e.hostArgs(b, 4)
	if args == nil {
		return
	}
	thr, routine, arg := args[0], args[2], args[3]
	f := e.newFiber(routine, arg)
	if e.cfg.Verbose {
		fmt.Printf("[pthread_create] fiber %d routine=0x%x (%s) arg=0x%x\n", f.id, routine, e.NearestSym(routine), arg)
	}
	if thr != 0 {
		_ = putU64(b, thr, uint64(0x7300|f.id)) // fake pthread_t (distinct per fiber)
	}
	e.hostResult(b, 0)
}

func hostRet0(e *Emulator, b emu.Backend) { e.hostResult(b, 0) }

// hostGetauxval implements getauxval(type) without bionic's __libc_auxv.
// Since P4d it has ZERO per-key knowledge: it serves the auxv vector the
// platform StartupABI built (ensureStartup), reached through the Runtime's
// AuxvLookup (P5b.5 — bound to the SAME StartupABI instance by the factory,
// so data block and query can never drift, and no type assertion is needed
// here). The vector's HWCAP bits derive from the Target's arch.CPUFeatures —
// auxv data block and CPU-feature query share one source of truth. In a
// bionic-only boot the first getauxval may precede any LoadLibrary; the
// vector is then built lazily without main-image metadata (AT_PHDR/
// AT_PHNUM/AT_ENTRY read as 0, the historical default). That lazy build is
// the deliberate P4e rule — see ensureStartup for the pinned ordering
// contract. Unknown keys answer 0, as before.
func hostGetauxval(e *Emulator, b emu.Backend) {
	args := e.hostArgs(b, 1)
	if args == nil {
		return
	}
	t := args[0]
	var v uint64
	if err := e.ensureStartup(nil, 0); err != nil {
		// No error channel on the hostFn contract: log and answer 0 rather
		// than panic across the backend trampoline.
		if e.cfg.Verbose {
			fmt.Printf("[getauxval] startup build failed: %v\n", err)
		}
	} else if e.auxvLookup != nil {
		v = e.auxvLookup(t)
	}
	// auxvLookup is non-nil by construction here: getauxval is bound
	// (registerHostFns) exactly when the platform Runtime carries an
	// AuxvLookup — a platform with no auxv (Darwin, P5b) never binds it.
	e.hostResult(b, v)
}
