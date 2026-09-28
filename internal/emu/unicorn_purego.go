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

	// UC_ERR_ARG in unicorn2's uc_err enum — returned by UC_CTL_UC_PREALLOC
	// on POSIX builds where it does not apply.
	ucErrArg = 4

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

func regMap(r Reg) int32 {
	switch r {
	case RegX0, RegX1, RegX2, RegX3, RegX4, RegX5, RegX6, RegX7, RegX8, RegX9, RegX10:
		return ucRegX(int(r))
	case RegX23:
		return ucRegX(23)
	case RegSP:
		return ucRegSP
	case RegPC:
		return ucRegPC
	case RegLR:
		return ucRegLR
	case RegNZCV:
		return ucRegNZCV
	case RegTPIDR_EL0:
		return ucRegTPIDR
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
		"uc_reg_read_batch": &pRegRdBat,
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

	// Static C→Go trampolines. Three, total, for the process lifetime — hook
	// identity rides in user_data (the cbid), never in the trampoline.
	codeTramp = purego.NewCallback(goCodeHook)
	intrTramp = purego.NewCallback(goIntrHook)
	memTramp = purego.NewCallback(goMemHook)
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
)

func goCodeHook(uc uintptr, addr uint64, size uint64, user uintptr) uintptr {
	if e := lookupCB(uint64(user)); e != nil && e.code != nil {
		e.code(e.be, addr, uint32(size))
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
		e.memrd(e.be, addr, int(int32(size)))
		return 0
	}
	if e.memwr != nil { // valid-write hook (ranged); value = bytes being written
		e.memwr(e.be, addr, int(int32(size)), value)
		return 0
	}
	if e.mem == nil {
		return 0
	}
	if e.mem(e.be, int(int32(typ)), addr, int(int32(size)), value) {
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
	mem   func(Backend, int, uint64, int, int64) bool
	memrd func(Backend, uint64, int)
	memwr func(Backend, uint64, int, int64)
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

type unicornBackend struct {
	uc       unsafe.Pointer
	cbs      []uint64
	pageSize uint64 // unicorn's guest page size (4 KiB on aarch64 — NOT the host page size)
}

func newUnicornBackend() (Backend, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	var uc unsafe.Pointer
	if e := pOpen(ucArchARM64, ucModeARM, unsafe.Pointer(&uc)); e != ucOK {
		return nil, ucErr("uc_open", e)
	}
	b := &unicornBackend{uc: uc, pageSize: 4096}
	// Windows belt-and-braces: commit the whole TCG buffer upfront so unicorn
	// never installs its process-global VEH (PR #2364, UC_CTL_UC_PREALLOC;
	// must run before the first uc_emu_start). Ignored on POSIX (UC_ERR_ARG)
	// and on VEH-less Windows builds, where preallocation is mandatory.
	if runtime.GOOS == "windows" && pCtl != nil {
		var preallocCtl uint32 = ucCtlUcPrealloc | 1<<26 | 1<<30 // UC_CTL_WRITE(UC_CTL_UC_PREALLOC, 1)
		var on int32 = 1
		if e := pCtl(uc, preallocCtl, unsafe.Pointer(&on)); e != ucOK && e != ucErrArg {
			pClose(uc)
			return nil, ucErr("uc_ctl prealloc", e)
		}
		// PREALLOC commits the whole TCG buffer upfront — the default 1 GiB
		// per instance would bill 10 GiB for a 10-engine pool. Sizing curve
		// (Windows, pool 10, native add workload): 16 MiB reaches 100% of
		// peak throughput; 256 MiB+ degrades 30-40%. 16 MiB default, and
		// unicorn rounds as it sees fit.
		var tcgMiB uint32 = 16
		var tcgCtl uint32 = ucCtlTcgBufferSize | 1<<26 | 1<<30 // UC_CTL_WRITE(UC_CTL_TCG_BUFFER_SIZE, 1)
		if e := pCtl(uc, tcgCtl, unsafe.Pointer(&tcgMiB)); e != ucOK {
			pClose(uc)
			return nil, ucErr("uc_ctl tcg buffer size", e)
		}
	}
	return b, nil
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

func (b *unicornBackend) RegRead(r Reg) (uint64, error) {
	var v uint64
	if e := pRegRead(b.uc, regMap(r), unsafe.Pointer(&v)); e != ucOK {
		return 0, ucErr("reg_read", e)
	}
	return v, nil
}

func (b *unicornBackend) RegWrite(r Reg, val uint64) error {
	if e := pRegWrite(b.uc, regMap(r), unsafe.Pointer(&val)); e != ucOK {
		return ucErr("reg_write", e)
	}
	return nil
}

func (b *unicornBackend) ReadGPRegs() ([34]uint64, error) {
	var out [34]uint64
	var ptrs [34]unsafe.Pointer
	for i := range out {
		ptrs[i] = unsafe.Pointer(&out[i])
	}
	if e := pRegRdBat(b.uc, unsafe.Pointer(&gpRegIDs[0]), unsafe.Pointer(&ptrs[0]), int32(34)); e != ucOK {
		return out, ucErr("read_gpregs", e)
	}
	return out, nil
}

func (b *unicornBackend) MemMap(addr, size uint64, prot int) error {
	if e := pMemMap(b.uc, addr, size, uint32(prot)); e != ucOK {
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
func (b *unicornBackend) MemMapPtr(addr, size uint64, prot int, host unsafe.Pointer) error {
	if host == nil {
		return fmt.Errorf("emu: mem_map_ptr: nil host pointer (use MemMap for engine-owned memory)")
	}
	gmask := b.pageSize - 1
	if b.pageSize == 0 || addr&gmask != 0 || size == 0 || size&gmask != 0 {
		return fmt.Errorf("emu: mem_map_ptr: guest addr %#x and size %#x must be aligned to the unicorn page size %d", addr, size, b.pageSize)
	}
	hmask := uintptr(os.Getpagesize() - 1)
	if uintptr(host)&hmask != 0 {
		return fmt.Errorf("emu: mem_map_ptr: host pointer %p is not page-aligned (host page size %d)", host, os.Getpagesize())
	}
	if e := pMemMapPtr(b.uc, addr, size, uint32(prot), host); e != ucOK {
		return ucErr("mem_map_ptr", e)
	}
	return nil
}

func (b *unicornBackend) MemUnmap(addr, size uint64) error {
	if e := pMemUnmap(b.uc, addr, size); e != ucOK {
		return ucErr("mem_unmap", e)
	}
	return nil
}

func (b *unicornBackend) MemProtect(addr, size uint64, prot int) error {
	if e := pMemProt(b.uc, addr, size, uint32(prot)); e != ucOK {
		return ucErr("mem_protect", e)
	}
	return nil
}

func (b *unicornBackend) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if e := pMemWrite(b.uc, addr, unsafe.Pointer(&data[0]), uint64(len(data))); e != ucOK {
		return ucErr("mem_write", e)
	}
	return nil
}

func (b *unicornBackend) MemRead(addr uint64, size uint64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if e := pMemRead(b.uc, addr, unsafe.Pointer(&buf[0]), size); e != ucOK {
		return nil, ucErr("mem_read", e)
	}
	return buf, nil
}

func (b *unicornBackend) addHook(htype int32, begin, end uint64, fn *hookReg) (HookHandle, error) {
	id := registerCB(fn)
	var hh uint64
	if e := pHookAdd(b.uc, &hh, htype, trampFor(htype), uintptr(id), begin, end); e != ucOK {
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

func (b *unicornBackend) HookCode(start, end uint64, fn CodeHookFunc) (HookHandle, error) {
	return b.addHook(hkCode, start, end, &hookReg{be: b, code: fn})
}

func (b *unicornBackend) HookInterrupt(fn InterruptHookFunc) (HookHandle, error) {
	// begin=1,end=0 = whole address space (unicorn's begin>end convention).
	return b.addHook(hkIntr, 1, 0, &hookReg{be: b, intr: fn})
}

func (b *unicornBackend) HookMemInvalid(fn func(Backend, int, uint64, int, int64) bool) (HookHandle, error) {
	return b.addHook(hkMemInvalid, 1, 0, &hookReg{be: b, mem: fn})
}

func (b *unicornBackend) HookMemRead(start, end uint64, fn func(Backend, uint64, int)) (HookHandle, error) {
	return b.addHook(hkMemRead, start, end, &hookReg{be: b, memrd: fn})
}

func (b *unicornBackend) HookMemWrite(start, end uint64, fn func(Backend, uint64, int, int64)) (HookHandle, error) {
	return b.addHook(hkMemWrite, start, end, &hookReg{be: b, memwr: fn})
}

func (b *unicornBackend) Start(begin, until uint64) error {
	if e := pStart(b.uc, begin, until, 0, 0); e != ucOK {
		return ucErr("emu_start", e)
	}
	return nil
}

func (b *unicornBackend) StartCount(begin, until, count uint64) error {
	if e := pStart(b.uc, begin, until, 0, count); e != ucOK {
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
