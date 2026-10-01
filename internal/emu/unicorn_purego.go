//go:build unicorn

// Pure-Go Unicorn2 backend: emu.Backend over the STOCK libunicorn, loaded at
// runtime through purego (dlopen + assembly trampolines). No cgo, no C
// compiler, no shim library — the only runtime dependency is libunicorn itself,
// findable through $GOLEM_UNICORN or the platform loader's search path:
//
//	macOS:   libunicorn.2.dylib / libunicorn.dylib
//	Linux:   libunicorn.so.2    / libunicorn.so
//	Windows: unicorn.dll — MUST be built from unicorn dev with
//	         -DWIN32_ENABLE_VEH=OFF (PR #2364); stock releases rely on a
//	         process-global VEH that fights the Go runtime (ARCHITECTURE.md).
//
// Build (note CGO_ENABLED=0 — this file never imports "C"):
//
//	CGO_ENABLED=0 go build -tags unicorn ./...
//
// Hook callbacks cross C→Go through three static purego.NewCallback
// trampolines; per-hook dispatch data (cbid) travels in unicorn's user_data
// and is resolved through a registry, so the 2000-callback process budget is
// never touched. Engine calls run directly on the calling (Go) thread — safe
// on POSIX because unicorn services guest-memory faults in software (softmmu,
// no signal/VEH dependency). On Windows, newUnicornBackend sets
// UC_CTL_UC_PREALLOC=1 so unicorn commits its TCG buffer upfront and never
// installs a process-global VEH (PR #2364; the DLL must be the VEH-off
// build — see ARCHITECTURE.md).
//
// C signatures pinned against unicorn2 headers (uc_hook = size_t, ints are
// C int = int32); variadic uc_hook_add / uc_ctl are called through fixed-arity
// declarations — valid on arm64/amd64 SysV for integer-only argument lists,
// which is all this backend ever passes.
package emu

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ---- unicorn2 constants, pinned against unicorn.h / arm64.h -----------------

const (
	ucOK = 0 // UC_ERR_OK

	ucArchARM64 = 2 // UC_ARCH_ARM64
	ucModeARM   = 0 // UC_MODE_ARM

	// UC_HOOK_* kinds this backend registers.
	hkIntr      = 1 << 0  // UC_HOOK_INTR
	hkCode      = 1 << 2  // UC_HOOK_CODE
	hkMemUnmapR = 1 << 4  // UC_HOOK_MEM_READ_UNMAPPED
	hkMemUnmapW = 1 << 5  // UC_HOOK_MEM_WRITE_UNMAPPED
	hkMemUnmapF = 1 << 6  // UC_HOOK_MEM_FETCH_UNMAPPED
	hkMemProtR  = 1 << 7  // UC_HOOK_MEM_READ_PROT
	hkMemProtW  = 1 << 8  // UC_HOOK_MEM_WRITE_PROT
	hkMemProtF  = 1 << 9  // UC_HOOK_MEM_FETCH_PROT
	hkMemRead   = 1 << 10 // UC_HOOK_MEM_READ
	hkMemWrite  = 1 << 11 // UC_HOOK_MEM_WRITE

	hkMemUnmapped = hkMemUnmapR | hkMemUnmapW | hkMemUnmapF // UC_HOOK_MEM_UNMAPPED
	hkMemProt     = hkMemProtR | hkMemProtW | hkMemProtF    // UC_HOOK_MEM_PROT
	hkMemInvalid  = hkMemUnmapped | hkMemProt               // UC_HOOK_MEM_INVALID

	// UC_CTL_WRITE(UC_CTL_TB_FLUSH, 0): UC_CTL packs type | (nr<<26) | (rw<<30),
	// UC_CTL_TB_FLUSH = 10, UC_CTL_IO_WRITE = 1, no extra args.
	ctlTBFlush = uint32(10) | 0<<26 | 1<<30

	// UC_ERR_ARG in unicorn2's uc_err enum = 10 (OK0 NOMEM1 ARCH2 HANDLE3
	// MODE4 VERSION5 READ_UNMAPPED6 WRITE_UNMAPPED7 FETCH_UNMAPPED8 HOOK9
	// INSN_INVALID10, …ARG) — returned by UC_CTL_UC_PREALLOC on builds where
	// it does not apply. The old pin (4) was actually UC_ERR_MODE, which is
	// why the PREALLOC tolerance in applyWindowsDefaults never matched when
	// an engine answered ARG (found on the first Windows run of the
	// multi-arch refactor: uc_open(ARM) answered MODE(4) there, so the bug
	// hid twice over).
	ucErrArg = 10

	// UC_CTL_UC_PREALLOC: value 19 in unicorn dev's uc_control_type
	// (PR #2364 appends it after UC_CTL_INVALID_ADDR=18; verified against
	// include/unicorn/unicorn.h on the dev branch). The installed release
	// headers predate it — do NOT "fix" this from a local unicorn.h.
	ucCtlUcPrealloc = 19

	// UC_CTL_TCG_BUFFER_SIZE: value 13 in uc_control_type. Write takes a
	// uint32 (unicorn may round it); readable back with the READ form.
	ucCtlTcgBufferSize = 13
)

// UC_ARM64_REG_* values. X0..X28 are contiguous; X29/X30 are early aliases
// (FP=1, LR=2), as is NZCV=3, SP=4.
const (
	ucRegInvalid = 0
	ucRegFP      = 1 // X29
	ucRegLR      = 2 // X30
	ucRegNZCV    = 3
	ucRegSP      = 4
	ucRegX0      = 199
	ucRegPC      = 260
	ucRegTPIDR   = 262 // UC_ARM64_REG_TPIDR_EL0
)

func ucRegX(n int) int32 { return int32(ucRegX0 + n) } // X0..X28 only

// gpRegIDs is the register file order for ReadGPRegs: x0..x30, sp, pc, nzcv.
var gpRegIDs = func() (ids [34]int32) {
	for i := 0; i <= 28; i++ {
		ids[i] = ucRegX(i)
	}
	ids[29] = ucRegFP
	ids[30] = ucRegLR
	ids[31] = ucRegSP
	ids[32] = ucRegPC
	ids[33] = ucRegNZCV
	return ids
}()

// regMap translates an abstract emu.Reg to its UC_ARM64_REG_* id.
//
// known exception: the ARM64 register ids now live in internal/arch/arm64,
// but emu cannot import that package — arm64 imports emu (for emu.Reg), so
// importing it back would be an import cycle. The switch therefore keys on
// the id NUMBERS arch/arm64 assigns (X0..X10=0..10, X23=11, SP=12, PC=13,
// LR=14, NZCV=15, TPIDR_EL0=16, X16=17); arch/arm64's TestFrozenRegIDs pins
// those numbers, so any drift fails tests loudly instead of corrupting
// registers.
func regMap(r Reg) int32 {
	switch r {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10: // arm64.X0 .. arm64.X10
		return ucRegX(int(r))
	case 11: // arm64.X23
		return ucRegX(23)
	case 12: // arm64.SP
		return ucRegSP
	case 13: // arm64.PC
		return ucRegPC
	case 14: // arm64.LR
		return ucRegLR
	case 15: // arm64.NZCV
		return ucRegNZCV
	case 16: // arm64.TPIDR_EL0
		return ucRegTPIDR
	case 17: // arm64.X16 (Darwin syscall-number register)
		return ucRegX(16)
	default:
		return ucRegInvalid
	}
}

// ---- libunicorn bindings (resolved once via Dlsym) --------------------------
//
// Signatures mirror the C prototypes; uc_engine*/uc_context* are opaque
// unsafe.Pointer. uc_hook_add/uc_ctl are variadic in C; the fixed-arity forms
// below cover every call this backend makes (integer args only).

var (
	pOpen      func(arch int32, mode int32, out unsafe.Pointer) int32                               // uc_open
	pClose     func(uc unsafe.Pointer) int32                                                        // uc_close
	pRegRead   func(uc unsafe.Pointer, regid int32, val unsafe.Pointer) int32                       // uc_reg_read
	pRegWrite  func(uc unsafe.Pointer, regid int32, val unsafe.Pointer) int32                       // uc_reg_write
	pRegRdBat  func(uc unsafe.Pointer, regs unsafe.Pointer, vals unsafe.Pointer, count int32) int32 // uc_reg_read_batch (void** vals)
	pRegWrBat  func(uc unsafe.Pointer, regs unsafe.Pointer, vals unsafe.Pointer, count int32) int32 // uc_reg_write_batch (void** vals)
	pMemMap    func(uc unsafe.Pointer, addr uint64, size uint64, prot uint32) int32
	pMemMapPtr func(uc unsafe.Pointer, addr uint64, size uint64, prot uint32, ptr unsafe.Pointer) int32 // uc_mem_map_ptr
	pMemUnmap  func(uc unsafe.Pointer, addr uint64, size uint64) int32
	pMemProt   func(uc unsafe.Pointer, addr uint64, size uint64, prot uint32) int32
	pMemWrite  func(uc unsafe.Pointer, addr uint64, p unsafe.Pointer, size uint64) int32
	pMemRead   func(uc unsafe.Pointer, addr uint64, p unsafe.Pointer, size uint64) int32
	pStart     func(uc unsafe.Pointer, begin, until, timeout uint64, count uint64) int32                           // uc_emu_start
	pStop      func(uc unsafe.Pointer) int32                                                                       // uc_emu_stop
	pHookAdd   func(uc unsafe.Pointer, hh *uint64, htype int32, cb uintptr, user uintptr, begin, end uint64) int32 // uc_hook_add
	pHookDel   func(uc unsafe.Pointer, hook uint64) int32                                                          // uc_hook_del
	pStrerror  func(err int32) string                                                                              // uc_strerror

	pCtl        func(uc unsafe.Pointer, control uint32, args ...unsafe.Pointer) int32 // uc_ctl (optional); SysV expands the variadic args in order, which matches uc_ctl's C variadic for integer/pointer arguments
	pCtxAlloc   func(uc unsafe.Pointer, out unsafe.Pointer) int32                     // uc_context_alloc (optional)
	pCtxSave    func(uc unsafe.Pointer, ctx unsafe.Pointer) int32
	pCtxRestore func(uc unsafe.Pointer, ctx unsafe.Pointer) int32
	pCtxFree    func(ctx unsafe.Pointer) int32 // takes only the context (post-1.0.1rc5 API)
)

var loadOnce struct {
	sync.Once
	err error
}

func ensureLoaded() error {
	loadOnce.Do(func() { loadOnce.err = loadUnicorn() })
	return loadOnce.err
}

func loadUnicorn() error {
	handle, err := dlopenUnicorn()
	if err != nil {
		return err
	}

	// Required symbols — a clean load error, not a panic, when the library is
	// not the unicorn2 API this backend expects.
	required := map[string]any{
		"uc_open":           &pOpen,
		"uc_close":          &pClose,
		"uc_reg_read":       &pRegRead,
		"uc_reg_write":      &pRegWrite,
		"uc_reg_read_batch":  &pRegRdBat,
		"uc_reg_write_batch": &pRegWrBat,
		"uc_mem_map":        &pMemMap,
		"uc_mem_map_ptr":    &pMemMapPtr,
		"uc_mem_unmap":      &pMemUnmap,
		"uc_mem_protect":    &pMemProt,
		"uc_mem_write":      &pMemWrite,
		"uc_mem_read":       &pMemRead,
		"uc_emu_start":      &pStart,
		"uc_emu_stop":       &pStop,
		"uc_hook_add":       &pHookAdd,
		"uc_hook_del":       &pHookDel,
		"uc_strerror":       &pStrerror,
	}
	var missing []string
	for name, dst := range required {
		sym, err := findSymbol(handle, name)
		if err != nil {
			missing = append(missing, name)
			continue
		}
		purego.RegisterFunc(dst, sym)
	}
	if len(missing) > 0 {
		return fmt.Errorf("emu: libunicorn missing symbols %s (need unicorn2)",
			strings.Join(missing, ", "))
	}

	// Optional symbols — absent on very old unicorn builds; degrade to no-ops.
	tryRegister := func(name string, dst any) {
		if sym, err := findSymbol(handle, name); err == nil {
			purego.RegisterFunc(dst, sym)
		}
	}
	tryRegister("uc_ctl", &pCtl)
	tryRegister("uc_context_alloc", &pCtxAlloc)
	tryRegister("uc_context_save", &pCtxSave)
	tryRegister("uc_context_restore", &pCtxRestore)
	tryRegister("uc_context_free", &pCtxFree)

	// Static C→Go trampolines. Four, total, for the process lifetime — hook
	// identity rides in user_data (the cbid), never in the trampoline.
	codeTramp = purego.NewCallback(goCodeHook)
	intrTramp = purego.NewCallback(goIntrHook)
	memTramp = purego.NewCallback(goMemHook)
	insnTramp = purego.NewCallback(goInsnHook)

	// Fixed-arity declarations of uc_hook_add's variadic tail for UC_HOOK_INSN
	// (the instruction id). Both bind the same symbol; hookAddInsn picks the
	// host-ABI correct one (see unicorn_amd64.go).
	if sym, err := findSymbol(handle, "uc_hook_add"); err == nil {
		purego.RegisterFunc(&pHookAddInsn, sym)
		purego.RegisterFunc(&pHookAddInsnPad, sym)
	}
	return nil
}

func dlopenUnicorn() (uintptr, error) {
	var candidates []string
	if p := strings.TrimSpace(os.Getenv("GOLEM_UNICORN")); p != "" {
		candidates = append(candidates, p)
	}
	switch runtime.GOOS {
	case "windows":
		// MUST be the VEH-off build (see header comment); candidates start
		// with the bundled per-arch assets copy, then the loader search path.
		candidates = append(candidates,
			"unicorn.dll",
			filepath.Join("assets", "windows", runtime.GOARCH, "unicorn.dll"),
		)
	case "darwin":
		candidates = append(candidates,
			"libunicorn.2.dylib", "libunicorn.dylib", // loader search path
			"/opt/homebrew/opt/unicorn/lib/libunicorn.dylib", // homebrew (arm64)
			"/opt/homebrew/lib/libunicorn.dylib",
			"/usr/local/opt/unicorn/lib/libunicorn.dylib", // homebrew (x86-64)
			"/usr/local/lib/libunicorn.dylib",
		)
	default:
		candidates = append(candidates,
			"libunicorn.so.2", "libunicorn.so", // loader search path
			"/usr/lib/x86_64-linux-gnu/libunicorn.so.2",
			"/usr/lib/aarch64-linux-gnu/libunicorn.so.2",
			"/usr/local/lib/libunicorn.so.2",
		)
	}
	var lastErr error
	for _, c := range candidates {
		h, err := loadLibrary(c)
		if err == nil {
			return h, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("emu: cannot load libunicorn (tried %s; set GOLEM_UNICORN to its path): %w",
		strings.Join(candidates, ", "), lastErr)
}

// ---- C→Go hook trampolines ---------------------------------------------------
//
// Signatures match unicorn's callback typedefs (uc_cb_hookcode_t,
// uc_cb_hookintr_t, uc_cb_eventmem_t / uc_cb_hookmem_t). unicorn passes
// user_data back verbatim; it carries the cbid into the registry.

var (
	codeTramp uintptr
	intrTramp uintptr
	memTramp  uintptr
	insnTramp uintptr
)

func goCodeHook(uc uintptr, addr uint64, size uint64, user uintptr) uintptr {
	if e := lookupCB(uint64(user)); e != nil && e.code != nil {
		e.code(e.be, GuestAddr(addr), uint32(size)) // raw C addr → GuestAddr at the trampoline boundary
	}
	return 0
}

func goIntrHook(uc uintptr, intno uint64, user uintptr) uintptr {
	if e := lookupCB(uint64(user)); e != nil && e.intr != nil {
		e.intr(e.be, uint32(intno))
	}
	return 0
}

// goMemHook serves every memory hook kind. For UC_HOOK_MEM_INVALID (eventmem,
// bool return) it returns 1 to continue after the hook made the memory
// accessible; for valid read/write hooks (void return) the value is ignored.
func goMemHook(uc uintptr, typ uint64, addr uint64, size uint64, value int64, user uintptr) uintptr {
	e := lookupCB(uint64(user))
	if e == nil {
		return 0
	}
	if e.memrd != nil { // valid-read hook (ranged); return value ignored by unicorn
		e.memrd(e.be, GuestAddr(addr), int(int32(size))) // raw C addr → GuestAddr
		return 0
	}
	if e.memwr != nil { // valid-write hook (ranged); value = bytes being written
		e.memwr(e.be, GuestAddr(addr), int(int32(size)), value) // raw C addr → GuestAddr
		return 0
	}
	if e.mem == nil {
		return 0
	}
	if e.mem(e.be, int(int32(typ)), GuestAddr(addr), int(int32(size)), value) { // raw C addr → GuestAddr
		return 1
	}
	return 0
}

// ---- callback registry: cbid -> registration --------------------------------

var (
	cbMu  sync.Mutex
	cbSeq uint64
	cbReg = map[uint64]*hookReg{}
)

type hookReg struct {
	be    *unicornBackend
	code  CodeHookFunc
	intr  InterruptHookFunc
	insn  func(be Backend) // UC_HOOK_INSN (AMD64: the syscall instruction)
	mem   MemInvalidHookFunc
	memrd MemReadHookFunc
	memwr MemWriteHookFunc
}

func registerCB(h *hookReg) uint64 {
	cbMu.Lock()
	defer cbMu.Unlock()
	cbSeq++
	cbReg[cbSeq] = h
	return cbSeq
}
func unregisterCB(id uint64) { cbMu.Lock(); delete(cbReg, id); cbMu.Unlock() }
func lookupCB(id uint64) *hookReg {
	cbMu.Lock()
	defer cbMu.Unlock()
	return cbReg[id]
}

// ---- emu.Backend ------------------------------------------------------------

func init() { Register("unicorn", newUnicornBackend) }

// The unicorn backend implements the Backend core plus every capability
// interface defined today (DESIGN.md invariant 14: facts, not promises — a
// drift here fails the build).
var (
	_ Backend             = (*unicornBackend)(nil)
	_ InstructionHooker   = (*unicornBackend)(nil)
	_ InterruptHooker     = (*unicornBackend)(nil)
	_ InvalidMemHooker    = (*unicornBackend)(nil)
	_ MemReadHooker       = (*unicornBackend)(nil)
	_ MemWriteHooker      = (*unicornBackend)(nil)
	_ ContextManager      = (*unicornBackend)(nil)
	_ CacheInvalidator    = (*unicornBackend)(nil)
	_ CodeCacheController = (*unicornBackend)(nil)
)

type unicornBackend struct {
	uc       unsafe.Pointer
	cbs      []uint64
	arch     Arch   // the guest architecture this engine was created for
	pageSize uint64 // unicorn's guest page size (4 KiB on aarch64 — NOT the host page size)

	traps    []*trapReg // InstallTrap registrations, dispatched from trapHook
	trapHook HookHandle // lazily-installed UC_HOOK_INTR serving InstallTrap

	insnTraps []*trapReg // AMD64: TrapSyscall registrations served by UC_HOOK_INSN
	insnHook  HookHandle // lazily-installed UC_HOOK_INSN(UC_X86_INS_SYSCALL)
}

func newUnicornBackend(a Arch) (Backend, error) {
	var ucArch, ucMode int32
	switch a {
	case ArchARM64:
		ucArch, ucMode = ucArchARM64, ucModeARM
	case ArchARM:
		// UC_MODE_ARM is the RESET state; Thumb entry is by the start
		// address bit0 (unicorn_arm.go header) — no per-run mode needed here.
		ucArch, ucMode = ucArchARM, ucModeARM
	case ArchAMD64:
		ucArch, ucMode = ucArchX86, ucMode64
	default:
		return nil, fmt.Errorf("emu: unicorn backend: arch %s: %w", a, ErrUnsupported)
	}
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	var uc unsafe.Pointer
	if e := pOpen(ucArch, ucMode, unsafe.Pointer(&uc)); e != ucOK {
		return nil, ucErr("uc_open", e)
	}
	b := &unicornBackend{uc: uc, arch: a, pageSize: 4096}
	if a == ArchARM {
		// ARMv7 RESET leaves VFP/NEON disabled (cp10/cp11 inaccessible); a
		// real Linux kernel enables them lazily on first use, and bionic
		// assumes they are on. Without this, the first VLDR/NEON
		// instruction raises Undefined → UC_ERR_INSN_INVALID (exposed
		// by real third-party ARMv7 libraries — Termux libsqlite3 hit a
		// VLDR inside sqlite3_open→sqlite3_config's dispatch tail). Live
		// probe pinned the semantics: THIS unicorn build gates VFP on
		// FPEXC.EN (bit30), not CPACR — write both (CPACR = the
		// architectural switch, FPEXC = the one that actually works here),
		// engine-internal like the Windows PREALLOC default.
		var fpexc uint64 = 1 << 30
		if e := pRegWrite(uc, ucArmRegFPEXC, unsafe.Pointer(&fpexc)); e != ucOK {
			pClose(uc)
			return nil, ucErr("arm fpexc enable", e)
		}
		var cpacr uint64 = 0x00F00000
		if e := pRegWrite(uc, ucArmRegC1C02, unsafe.Pointer(&cpacr)); e != ucOK {
			pClose(uc)
			return nil, ucErr("arm cpacr enable", e)
		}
	}
	if runtime.GOOS == "windows" {
		if err := b.applyWindowsDefaults(); err != nil {
			pClose(uc)
			return nil, err
		}
	}
	return b, nil
}

// preallocWarnOnce makes the stock-DLL warning in applyWindowsDefaults print
// once per process, no matter how many engines the pool opens.
var preallocWarnOnce sync.Once

// applyWindowsDefaults applies the Windows-only engine setup, as
// belt-and-braces against unicorn's process-global VEH: commit the whole TCG
// buffer upfront so unicorn never installs it (PR #2364, UC_CTL_UC_PREALLOC;
// must run before the first uc_emu_start), then cap the buffer at a
// pool-friendly size.
func (b *unicornBackend) applyWindowsDefaults() error {
	if pCtl == nil {
		return nil
	}
	var preallocCtl uint32 = ucCtlUcPrealloc | 1<<26 | 1<<30 // UC_CTL_WRITE(UC_CTL_UC_PREALLOC, 1)
	var on int32 = 1
	switch e := pCtl(b.uc, preallocCtl, unsafe.Pointer(&on)); e {
	case ucOK:
	case ucErrArg:
		// Expected on the VEH-off build (preallocation is mandatory there,
		// so the ctl has nothing to do) — but also what a stock release DLL
		// returns because it predates #2364, in which case the VEH stays
		// active. Warn once so the second case is not silently "working".
		preallocWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "emu: warning: the loaded unicorn DLL does not support UC_CTL_UC_PREALLOC. "+
				"If this is the golem VEH-off build (assets/windows or $GOLEM_UNICORN), this is expected. "+
				"Otherwise it is likely a stock release build: unicorn's process-global VEH is active and "+
				"conflicts with the Go runtime (golang/go#56082) — use the VEH-off build from assets/windows "+
				"or point GOLEM_UNICORN at one.\n")
		})
	default:
		return ucErr(fmt.Sprintf("uc_ctl prealloc (%s)", b.arch), e)
	}
	// PREALLOC commits the whole TCG buffer upfront — the default 1 GiB
	// per instance would bill 10 GiB for a 10-engine pool. Sizing curve
	// (Windows, pool 10, native add workload): 8 MiB already hits 100% of
	// peak throughput (688K QPS top of the sweep); 256 MiB+ degraded 30-40%.
	// Larger-footprint guests may need more — measure with cmd/tcgsizing;
	// users override it via emulator.Config.TCGBufferMiB.
	var tcgMiB uint32 = 8
	var tcgCtl uint32 = ucCtlTcgBufferSize | 1<<26 | 1<<30 // UC_CTL_WRITE(UC_CTL_TCG_BUFFER_SIZE, 1)
	if e := pCtl(b.uc, tcgCtl, unsafe.Pointer(&tcgMiB)); e != ucOK {
		return ucErr("uc_ctl tcg buffer size", e)
	}
	return nil
}

func ucErr(op string, e int32) error {
	return fmt.Errorf("emu: %s: %s", op, pStrerror(e))
}

// SetTCGBufferSize caps the engine's translation-buffer size in bytes
// (unicorn may round the value; UC_CTL_TCG_BUFFER_SIZE). Must be called
// before the first Start. Primary use: Windows, where the buffer is
// committed upfront (PREALLOC) and its size is per-instance real memory.
func SetTCGBufferSize(b Backend, size uint32) error {
	ub, ok := b.(*unicornBackend)
	if !ok {
		return fmt.Errorf("emu: SetTCGBufferSize: backend is not the unicorn engine")
	}
	if ub.uc == nil {
		return fmt.Errorf("emu: SetTCGBufferSize: engine closed")
	}
	if pCtl == nil {
		return fmt.Errorf("emu: SetTCGBufferSize: libunicorn lacks uc_ctl")
	}
	sz := size
	if e := pCtl(ub.uc, ucCtlTcgBufferSize|1<<26|1<<30, unsafe.Pointer(&sz)); e != ucOK {
		return ucErr("set_tcg_buffer_size", e)
	}
	return nil
}

// toUCReg translates an abstract emu.Reg to this engine's UC register id,
// dispatching on the engine's guest architecture. The mappings key on the
// frozen id NUMBERS of internal/arch/arm64 (regMap), internal/arch/amd64
// (regMapAMD64) and internal/arch/arm32 (regMapARM32) — emu cannot import
// those packages (import cycle); their TestFrozenRegIDs pin the numbers on
// the other side.
func (b *unicornBackend) toUCReg(r Reg) int32 {
	switch b.arch {
	case ArchAMD64:
		return regMapAMD64(r)
	case ArchARM:
		return regMapARM32(r)
	}
	return regMap(r)
}

func (b *unicornBackend) RegRead(r Reg) (uint64, error) {
	var v uint64
	if e := pRegRead(b.uc, b.toUCReg(r), unsafe.Pointer(&v)); e != ucOK {
		return 0, ucErr("reg_read", e)
	}
	return v, nil
}

func (b *unicornBackend) RegWrite(r Reg, val uint64) error {
	if e := pRegWrite(b.uc, b.toUCReg(r), unsafe.Pointer(&val)); e != ucOK {
		return ucErr("reg_write", e)
	}
	return nil
}

// ReadGPRegs is the RegFileReader capability: AArch64 dumps x0..x30, sp, pc,
// nzcv; ARM32 dumps r0..r12, sp, lr, pc, cpsr (real-library validation);
// AMD64 answers ErrUnsupported loudly instead of borrowing either shape.
func (b *unicornBackend) ReadGPRegs() ([]uint64, error) {
	var ids []int32
	switch b.arch {
	case ArchARM64:
		ids = gpRegIDs[:]
	case ArchARM:
		ids = arm32RegIDs[:]
	default:
		return nil, errNoGPRegs(b.arch)
	}
	out := make([]uint64, len(ids))
	var ptrs [34]unsafe.Pointer
	for i := range out {
		ptrs[i] = unsafe.Pointer(&out[i])
	}
	if e := pRegRdBat(b.uc, unsafe.Pointer(&ids[0]), unsafe.Pointer(&ptrs[0]), int32(len(ids))); e != ucOK {
		return out, ucErr("read_gpregs", e)
	}
	return out, nil
}

func (b *unicornBackend) MemMap(addr GuestAddr, size uint64, prot int) error {
	if e := pMemMap(b.uc, uint64(addr), size, uint32(prot)); e != ucOK { // GuestAddr→raw at the purego boundary
		return ucErr("mem_map", e)
	}
	return nil
}

// MemMapPtr maps the caller-provided host buffer [host, host+size) as guest
// memory at addr (uc_mem_map_ptr) — zero-copy: guest reads/writes land directly
// in the host buffer, so engines mapping the same buffer share it. The caller
// must keep host valid and page-sized for the engine's lifetime; the buffer
// must stay host-readable/writable per the requested prot (unicorn reads guest
// code from the buffer as plain host data, so PROT_EXEC is never needed on it).
//
// Two different page sizes matter here and conflating them is a bug:
//   - guest addr/size align to unicorn's GUEST page size (4 KiB on aarch64,
//     queried via uc_ctl — the loader's segments are 4 KiB granular);
//   - the host pointer aligns to the HOST page size (16 KiB on darwin/arm64),
//     which syscall.Mmap allocations satisfy.
func (b *unicornBackend) MemMapPtr(addr GuestAddr, size uint64, prot int, host unsafe.Pointer) error {
	if host == nil {
		return fmt.Errorf("emu: mem_map_ptr: nil host pointer (use MemMap for engine-owned memory)")
	}
	gmask := b.pageSize - 1
	a := uint64(addr) // GuestAddr→raw for alignment math and the C call
	if b.pageSize == 0 || a&gmask != 0 || size == 0 || size&gmask != 0 {
		return fmt.Errorf("emu: mem_map_ptr: guest addr %#x and size %#x must be aligned to the unicorn page size %d", a, size, b.pageSize)
	}
	hmask := uintptr(os.Getpagesize() - 1)
	if uintptr(host)&hmask != 0 {
		return fmt.Errorf("emu: mem_map_ptr: host pointer %p is not page-aligned (host page size %d)", host, os.Getpagesize())
	}
	if e := pMemMapPtr(b.uc, a, size, uint32(prot), host); e != ucOK {
		return ucErr("mem_map_ptr", e)
	}
	return nil
}

func (b *unicornBackend) MemUnmap(addr GuestAddr, size uint64) error {
	if e := pMemUnmap(b.uc, uint64(addr), size); e != ucOK { // GuestAddr→raw at the purego boundary
		return ucErr("mem_unmap", e)
	}
	return nil
}

func (b *unicornBackend) MemProtect(addr GuestAddr, size uint64, prot int) error {
	if e := pMemProt(b.uc, uint64(addr), size, uint32(prot)); e != ucOK { // GuestAddr→raw at the purego boundary
		return ucErr("mem_protect", e)
	}
	return nil
}

func (b *unicornBackend) MemWrite(addr GuestAddr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if e := pMemWrite(b.uc, uint64(addr), unsafe.Pointer(&data[0]), uint64(len(data))); e != ucOK { // GuestAddr→raw
		return ucErr("mem_write", e)
	}
	return nil
}

func (b *unicornBackend) MemRead(addr GuestAddr, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if e := pMemRead(b.uc, uint64(addr), unsafe.Pointer(&buf[0]), size); e != ucOK { // GuestAddr→raw
		return nil, ucErr("mem_read", e)
	}
	return buf, nil
}

func (b *unicornBackend) addHook(htype int32, begin, end GuestAddr, fn *hookReg) (HookHandle, error) {
	id := registerCB(fn)
	var hh uint64
	if e := pHookAdd(b.uc, &hh, htype, trampFor(htype), uintptr(id), uint64(begin), uint64(end)); e != ucOK { // GuestAddr→raw
		unregisterCB(id)
		return nil, ucErr("hook_add", e)
	}
	b.cbs = append(b.cbs, id)
	return &ucHook{b: b, hh: hh, id: id}, nil
}

// trampFor picks the C→Go trampoline matching unicorn's callback typedef for
// the hook kind (code/intr take a void callback; invalid-mem takes the bool
// eventmem callback; valid read/write take the void mem callback — the shared
// mem trampoline serves all three).
func trampFor(htype int32) uintptr {
	switch {
	case htype == hkCode:
		return codeTramp
	case htype == hkIntr:
		return intrTramp
	default:
		return memTramp
	}
}

// HookCode registers a code hook over [start, end].
//
// range normalization: unicorn2 quantizes hook range ENDS down to the
// target's instruction size, so [addr, addr] collapses to an EMPTY range on
// aarch64 (end addr+1 aligns back to addr) and never fires — while firing
// fine on x86_64 (1-byte granularity). This backend adapter normalizes a
// single-address hook to at least one instruction slot per target, so the
// PUBLIC semantic ("fire at this address") holds everywhere:
//
//	ARM64: end ← addr+4 (fixed 4-byte encoding)
//	ARM end ← addr+4 (ARM state; a Thumb entry may co-fire the
//	           following 2-byte instruction — documented, tolerated)
//	AMD64: end ← addr+1 (1-byte granularity)
func (b *unicornBackend) HookCode(start, end GuestAddr, fn CodeHookFunc) (HookHandle, error) {
	if start == end {
		switch b.arch {
		case ArchARM64, ArchARM:
			end = start + 4
		case ArchAMD64:
			end = start + 1
		}
	}
	return b.addHook(hkCode, start, end, &hookReg{be: b, code: fn})
}

func (b *unicornBackend) HookInterrupt(fn InterruptHookFunc) (HookHandle, error) {
	// begin=1,end=0 = whole address space (unicorn's begin>end convention).
	return b.addHook(hkIntr, 1, 0, &hookReg{be: b, intr: fn})
}

// ---- InstallTrap: generic trap dispatch over the single interrupt hook ------

// trapReg is one InstallTrap registration.
type trapReg struct {
	kind TrapKind
	h    TrapHandler
}

// InstallTrap adapts the generic trap interface onto the engine's trap
// channels. Runtime kind discrimination is deliberately NOT done via stub
// instruction bytes (design decision: not a cross-arch contract).
// Trampoline identity is decided by address — PC in the stub region resolves
// via interpose.StubManager metadata; anything else is a guest syscall.
//
// Channel selection is an engine+arch implementation detail (the Backend
// contract stays arch-neutral):
//   - ARM64: every SVC fires UC_HOOK_INTR; all kinds share that hook
//     (installed lazily on first use), each handler receiving the kind it was
//     REGISTERED under — behavior identical to HookInterrupt registrations.
//   - AMD64: host stubs (`int3`) fire UC_HOOK_INTR and take the same path;
//     the guest `syscall` instruction is NOT an interrupt, so TrapSyscall is
//     served by UC_HOOK_INSN(UC_X86_INS_SYSCALL) instead (unicorn_amd64.go) —
//     the real guest-syscall channel, kept strictly separate from host stubs.
func (b *unicornBackend) InstallTrap(kind TrapKind, h TrapHandler) (HookHandle, error) {
	if b.arch == ArchAMD64 && kind == TrapSyscall {
		return b.installInsnTrap(kind, h)
	}
	if b.trapHook == nil {
		hh, err := b.HookInterrupt(func(bk Backend, _ uint32) {
			for _, tr := range b.traps {
				tr.h(bk, tr.kind)
			}
		})
		if err != nil {
			return nil, err
		}
		b.trapHook = hh
	}
	tr := &trapReg{kind: kind, h: h}
	b.traps = append(b.traps, tr)
	return &trapHandle{b: b, tr: tr}, nil
}

// trapHandle removes one InstallTrap registration. The underlying interrupt
// hook stays (inert once traps is empty) — Close releases it via b.cbs.
type trapHandle struct {
	b  *unicornBackend
	tr *trapReg
}

func (h *trapHandle) Remove() error {
	for i, tr := range h.b.traps {
		if tr == h.tr {
			h.b.traps = append(h.b.traps[:i], h.b.traps[i+1:]...)
			break
		}
	}
	return nil
}

func (b *unicornBackend) HookMemInvalid(fn MemInvalidHookFunc) (HookHandle, error) {
	return b.addHook(hkMemInvalid, 1, 0, &hookReg{be: b, mem: fn})
}

func (b *unicornBackend) HookMemRead(start, end GuestAddr, fn MemReadHookFunc) (HookHandle, error) {
	return b.addHook(hkMemRead, start, end, &hookReg{be: b, memrd: fn})
}

func (b *unicornBackend) HookMemWrite(start, end GuestAddr, fn MemWriteHookFunc) (HookHandle, error) {
	return b.addHook(hkMemWrite, start, end, &hookReg{be: b, memwr: fn})
}

func (b *unicornBackend) Start(begin, until GuestAddr) error {
	if e := pStart(b.uc, uint64(begin), uint64(until), 0, 0); e != ucOK { // GuestAddr→raw
		return ucErr("emu_start", e)
	}
	return nil
}

func (b *unicornBackend) StartCount(begin, until GuestAddr, count uint64) error {
	if e := pStart(b.uc, uint64(begin), uint64(until), 0, count); e != ucOK { // GuestAddr→raw
		return ucErr("emu_start", e)
	}
	return nil
}

func (b *unicornBackend) Stop() error {
	if e := pStop(b.uc); e != ucOK {
		return ucErr("emu_stop", e)
	}
	return nil
}

// ucContext wraps a uc_context* (engine-allocated full CPU snapshot).
type ucContext struct {
	b   *unicornBackend
	ptr unsafe.Pointer
}

func (c *ucContext) Free() error {
	if c.ptr != nil && pCtxFree != nil {
		pCtxFree(c.ptr)
		c.ptr = nil
	}
	return nil
}

func (b *unicornBackend) SaveContext() (CPUContext, error) {
	if pCtxAlloc == nil || pCtxSave == nil {
		return nil, fmt.Errorf("emu: libunicorn lacks uc_context_* API")
	}
	var ctx unsafe.Pointer
	if e := pCtxAlloc(b.uc, unsafe.Pointer(&ctx)); e != ucOK {
		return nil, ucErr("context_alloc", e)
	}
	if e := pCtxSave(b.uc, ctx); e != ucOK {
		pCtxFree(ctx)
		return nil, ucErr("context_save", e)
	}
	return &ucContext{b: b, ptr: ctx}, nil
}

func (b *unicornBackend) RestoreContext(ctx CPUContext) error {
	if pCtxRestore == nil {
		return fmt.Errorf("emu: libunicorn lacks uc_context_* API")
	}
	c, ok := ctx.(*ucContext)
	if !ok || c.ptr == nil {
		return fmt.Errorf("emu: invalid CPU context")
	}
	if e := pCtxRestore(b.uc, c.ptr); e != ucOK {
		return ucErr("context_restore", e)
	}
	return nil
}

func (b *unicornBackend) FlushCache() error {
	if pCtl == nil {
		return nil // optional symbol; nothing to invalidate on old builds
	}
	if e := pCtl(b.uc, ctlTBFlush); e != ucOK {
		return ucErr("flush_tb", e)
	}
	return nil
}

// FlushCodeCache implements CodeCacheController . Unicorn exposes only
// a WHOLE-cache TB flush (UC_CTL_TB_FLUSH has no ranged form), so the range
// is accepted for the contract and the entire cache is invalidated — correct
// (a superset of the affected range), just coarser than the caller's hint.
func (b *unicornBackend) FlushCodeCache(start, end GuestAddr) error {
	return b.FlushCache()
}

func (b *unicornBackend) Close() error {
	for _, id := range b.cbs {
		unregisterCB(id)
	}
	b.cbs = nil
	if b.uc != nil {
		pClose(b.uc)
		b.uc = nil
	}
	return nil
}

type ucHook struct {
	b  *unicornBackend
	hh uint64
	id uint64
}

func (h *ucHook) Remove() error {
	unregisterCB(h.id)
	if e := pHookDel(h.b.uc, h.hh); e != ucOK {
		return ucErr("hook_del", e)
	}
	return nil
}

// WriteRegs implements the RegBatchWriter capability one
// host↔engine crossing for the whole write set. On engines whose unicorn
// build lacks uc_reg_write_batch (the binding stays nil) it degrades
// internally to a per-register loop — bit-for-bit the same writes, just
// slower.
func (b *unicornBackend) WriteRegs(writes []RegWrite) error {
	if len(writes) == 0 {
		return nil
	}
	if len(writes) > 16 || pRegWrBat == nil {
		// Oversized batches and engines whose unicorn lacks the symbol: the
		// identical per-register loop — zero new allocations, bit-for-bit
		// the same writes, just slower.
		for _, w := range writes {
			if err := b.RegWrite(w.Reg, w.Value); err != nil {
				return err
			}
		}
		return nil
	}
	// Stack arrays: the batch path adds NO heap allocation. The arrays do
	// escape to C (unavoidable), but as one escape-set instead of one
	// escaping value per register.
	var ids [16]int32
	var vals [16]uint64
	var ptrs [16]unsafe.Pointer
	for i, w := range writes {
		ids[i] = b.toUCReg(w.Reg)
		vals[i] = w.Value
		ptrs[i] = unsafe.Pointer(&vals[i])
	}
	if e := pRegWrBat(b.uc, unsafe.Pointer(&ids[0]), unsafe.Pointer(&ptrs[0]), int32(len(writes))); e != ucOK {
		return ucErr("reg_write_batch", e)
	}
	return nil
}
