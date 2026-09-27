package loader

import (
	"debug/elf"
	"fmt"
	"os"
	"sort"
	"sync"
	"unsafe"

	"github.com/isesword/golem/internal/emu"
)

// Plan is the compile-time instantiation plan for one Image at one load
// layout: which ranges to map (and which of them are SHAREABLE read-only
// pages), and which relocations to apply. Everything in it is engine-
// independent — relocations stay symbolic and segment addresses stay
// image-relative — so ONE Plan is shared by every engine instantiating the
// same .so, along with its page-aligned host buffers backing the shareable
// ranges (uc_mem_map_ptr maps those zero-copy into each engine).
type Plan struct {
	// Maps are the segment mappings. Shareable ones are read-only, hold no
	// relocation target, and are backed by page-aligned host buffers in
	// shared (below): every engine maps the SAME host memory, so the pages
	// exist once in RAM no matter how many engines load the module.
	Maps []MapOp
	// Relocs are the dynamic relocations in absolute-form fields that are
	// still engine-independent: Target/SymIdx/Addend are image-relative, and
	// Apply(base, resolve) computes the final addresses per engine.
	Relocs []RelocOp

	img    *Image   // symbol table for per-engine resolution; keeps raw alive
	shared [][]byte // backing buffers for shareable maps (keeps them alive)
}

// MapOp is one segment mapping.
type MapOp struct {
	Addr      uint64 // guest address, base-relative (image-relative + bias)
	Size      uint64 // page-aligned span
	Prot      int    // final protection
	Shareable bool   // read-only, no reloc target: map via MemMapPtr from shared
	Content   []byte // file image placed at the map start (zero tail for .bss); nil = pure anon
}

// RelocOp is one relocation, kept symbolic until Apply.
type RelocOp struct {
	Target uint64 // image-relative address to patch
	Type   elf.R_AARCH64
	SymIdx uint32
	Addend int64
}

// Apply executes the plan against a backend: maps segments (shareable ones
// via MemMapPtr from the plan's shared host buffers), applies every
// relocation with per-engine symbol resolution, and re-protects segments to
// their final permissions.
func (p *Plan) Apply(be emu.Backend, base uint64, resolve Resolver) error {
	return p.apply(be, base, resolve, true)
}

// ApplyPrivate is the opt-out path: everything anonymous, per-engine memory
// exactly like pre-sharing semantics (Config.NoSharedModules).
func (p *Plan) ApplyPrivate(be emu.Backend, base uint64, resolve Resolver) error {
	return p.apply(be, base, resolve, false)
}

func (p *Plan) apply(be emu.Backend, base uint64, resolve Resolver, share bool) error {
	for i := range p.Maps {
		m := &p.Maps[i]
		if m.Shareable && share {
			buf := p.shared[i]
			if err := be.MemMapPtr(base+m.Addr, m.Size, m.Prot, unsafe.Pointer(&buf[0])); err != nil {
				return fmt.Errorf("map shared seg @0x%x: %w", base+m.Addr, err)
			}
			continue
		}
		if err := be.MemMap(base+m.Addr, m.Size, emu.ProtRead|emu.ProtWrite|emu.ProtExec); err != nil {
			return fmt.Errorf("map seg @0x%x: %w", base+m.Addr, err)
		}
		if len(m.Content) > 0 {
			if err := be.MemWrite(base+m.Addr, m.Content); err != nil {
				return fmt.Errorf("write seg @0x%x: %w", base+m.Addr, err)
			}
		}
	}
	for i := range p.Relocs {
		r := &p.Relocs[i]
		target := base + r.Target
		switch r.Type {
		case elf.R_AARCH64_RELATIVE:
			if err := put64(be, target, base+uint64(r.Addend)); err != nil {
				return err
			}
		case elf.R_AARCH64_GLOB_DAT, elf.R_AARCH64_JUMP_SLOT, elf.R_AARCH64_ABS64:
			val, err := p.symValue(r.SymIdx, base, resolve)
			if err != nil {
				return err
			}
			if err := put64(be, target, val+uint64(r.Addend)); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unhandled reloc type %s at 0x%x", r.Type, r.Target)
		}
	}
	// Re-protect to declared permissions. Shareable maps created via
	// MemMapPtr were already at their final protection (nothing wrote them).
	for i := range p.Maps {
		m := &p.Maps[i]
		if m.Shareable && share {
			continue
		}
		if err := be.MemProtect(base+m.Addr, m.Size, m.Prot); err != nil {
			return fmt.Errorf("protect seg @0x%x: %w", base+m.Addr, err)
		}
	}
	return nil
}

// Plan computes the instantiation plan for the image. The image layout is
// deterministic (fixed load bases assigned by the emulator), so the returned
// Plan — including its shared host buffers — is reusable across engines.
func (img *Image) Plan() (*Plan, error) {
	img.planMu.Lock()
	defer img.planMu.Unlock()
	if img.plan != nil {
		return img.plan, nil
	}
	if img.raw == nil {
		return nil, fmt.Errorf("loader: image %s has no captured file bytes (re-Parse required)", img.Path)
	}
	p := &Plan{}

	// Relocation targets (image-relative), for the shareability audit.
	targets := make([]uint64, 0, len(img.Relocs))
	for _, r := range img.Relocs {
		targets = append(targets, r.Offset)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	touches := func(lo, hi uint64) bool {
		// any target in [lo, hi)
		k := sort.Search(len(targets), func(i int) bool { return targets[i] >= lo })
		return k < len(targets) && targets[k] < hi
	}

	for _, s := range img.Segments {
		lo := pageDown(s.Vaddr)
		hi := pageUp(s.Vaddr + s.MemSz)
		writable := s.Flags&elf.PF_W != 0
		shareable := !writable && !touches(lo, hi)

		m := MapOp{Addr: lo, Size: hi - lo, Prot: protOf(s.Flags), Shareable: shareable}
		if s.FileSz > 0 {
			content := make([]byte, m.Size)
			off := s.Vaddr - lo
			copy(content[off:], img.raw[s.Off:s.Off+s.FileSz])
			m.Content = content
		}
		if shareable {
			// Page-aligned host buffer for uc_mem_map_ptr (zero-copy, shared
			// across all engines instantiating this plan).
			buf, err := allocSharedBuffer(int(m.Size))
			if err != nil {
				return nil, fmt.Errorf("shared buffer %#x: %w", m.Addr, err)
			}
			copy(buf, m.Content)
			m.Content = buf
			p.shared = append(p.shared, buf)
		}
		p.Maps = append(p.Maps, m)
	}
	for _, r := range img.Relocs {
		p.Relocs = append(p.Relocs, RelocOp{Target: r.Offset, Type: r.Type, SymIdx: r.Sym, Addend: r.Addend})
	}
	p.img = img
	img.plan = p
	return p, nil
}

// SharedBuffer returns the page-aligned host buffer backing shareable map i.
// Used by the emulator to re-map the ORIGINAL shared pages when a privatize
// attempt must be rolled back.
func (p *Plan) SharedBuffer(i int) (unsafe.Pointer, uint64, error) {
	if i < 0 || i >= len(p.Maps) || !p.Maps[i].Shareable {
		return nil, 0, fmt.Errorf("loader: map %d is not shareable", i)
	}
	if i < len(p.shared) {
		buf := p.shared[i]
		return unsafe.Pointer(&buf[0]), uint64(len(buf)), nil
	}
	// Plans constructed outside Plan() (tests): the Content IS the shared
	// buffer in that case.
	if p.Maps[i].Content != nil {
		return unsafe.Pointer(&p.Maps[i].Content[0]), uint64(len(p.Maps[i].Content)), nil
	}
	return nil, 0, fmt.Errorf("loader: map %d has no shared buffer or content", i)
}

// symValue resolves a relocation's symbol per engine: defined symbols =>
// base+value, imported (undef) => via the resolver.
func (p *Plan) symValue(sym uint32, base uint64, resolve Resolver) (uint64, error) {
	return p.img.symValue(sym, base, resolve)
}

// CompileOnce returns a cached, immutable Image for path (keyed by
// path+size+mtime), so a pool of engines parses each .so exactly once. The
// mutex serializes construction: pool engines boot in parallel, and without
// the single-flight each one would parse its own copy of the file and pin it
// for the engine's lifetime. Entries are never evicted (module sets are
// small and process-lifetime).
var (
	compileMu    sync.Mutex
	compileCache sync.Map // key/path -> *Image
)

func CompileOnce(path string) (*Image, error) {
	compileMu.Lock()
	defer compileMu.Unlock()
	if v, ok := compileCache.Load(path); ok {
		return v.(*Image), nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%s:%d:%d", path, st.Size(), st.ModTime().UnixNano())
	if v, ok := compileCache.Load(key); ok {
		compileCache.Store(path, v)
		return v.(*Image), nil
	}
	img, err := Parse(path)
	if err != nil {
		return nil, err
	}
	compileCache.Store(key, img)
	compileCache.Store(path, img)
	return img, nil
}
