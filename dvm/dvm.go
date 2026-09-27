// Package dvm is the fake Dalvik/ART runtime: the JavaVM + JNIEnv the native
// library talks to. It is unidbg's single biggest value-add and the bulk of a
// Go port's hand-written code.
//
// How it works (same shape as unidbg):
//   - A JNIEnv struct lives in guest memory; each of its ~232 function-pointer
//     slots points at an SVC trampoline. When the .so calls e.g.
//     CallStaticObjectMethodV, the SVC traps to the host, we read the args from
//     registers/varargs, look up the target by its "class->method(sig)" string,
//     and invoke a Jni callback (below). The return value is boxed back into a
//     guest jobject handle.
//   - Objects never live in guest memory; they are Go values held in a
//     registry and referenced by opaque integer handles (jobject/jclass/jstring
//     are just those handles). This is exactly unidbg's DvmObject model.
package dvm

import (
	"fmt"
	"sync"
)

// Ref is an opaque guest-side handle (jobject/jclass/jstring/jarray).
type Ref int32

// Object is any boxed Java value.
type Object struct {
	Class *Class
	Value any // Go-side payload: string, []byte, int64, *Class, or arbitrary
}

// Class is a resolved Java class plus its registered methods/fields.
type Class struct {
	Name    string
	Super   *Class
	methods map[string]*Method // key: "name(sig)"
	fields  map[string]*Field
}

type Method struct {
	ID        Ref
	Name, Sig string
	Static    bool
}

type Field struct {
	ID        Ref
	Name, Sig string
	Static    bool
}

// Jni is the host callback surface, mirroring unidbg's AbstractJni. The host app
// overrides a handful of these; everything else falls through to defaults
// (embed AbstractJni so you only implement what your .so actually calls).
//
// The "...V" suffix is unidbg's: it is the variadic dispatch path (Call*MethodV
// with a decoded VaList), which is what the JNIEnv trampoline routes to.
type Jni interface {
	// AcceptMethod decides whether a RegisterNatives entry is accepted. Return
	// false to make the emulator treat that native method as unresolved (it then
	// can't be invoked) — used to force specific methods to fall through. Default
	// (AbstractJni) returns true.
	AcceptMethod(vm *VM, cls *Class, sig string, static bool) bool

	// Call<Type>MethodV — instance method dispatch.
	CallObjectMethodV(vm *VM, obj *Object, sig string, args *VaList) *Object
	CallBooleanMethodV(vm *VM, obj *Object, sig string, args *VaList) bool
	CallIntMethodV(vm *VM, obj *Object, sig string, args *VaList) int32
	CallLongMethodV(vm *VM, obj *Object, sig string, args *VaList) int64
	CallVoidMethodV(vm *VM, obj *Object, sig string, args *VaList)

	// CallStatic<Type>MethodV — static method dispatch.
	CallStaticObjectMethodV(vm *VM, cls *Class, sig string, args *VaList) *Object
	CallStaticIntMethodV(vm *VM, cls *Class, sig string, args *VaList) int32
	CallStaticVoidMethodV(vm *VM, cls *Class, sig string, args *VaList)
	CallStaticBooleanMethodV(vm *VM, cls *Class, sig string, args *VaList) bool
	CallStaticLongMethodV(vm *VM, cls *Class, sig string, args *VaList) int64

	// Field access.
	GetObjectField(vm *VM, obj *Object, sig string) *Object
	GetIntField(vm *VM, obj *Object, sig string) int32
	SetObjectField(vm *VM, obj *Object, sig string, val *Object)
	GetStaticObjectField(vm *VM, cls *Class, sig string) *Object
	GetStaticIntField(vm *VM, cls *Class, sig string) int32

	// NewObjectV constructs an instance (jobject) — return a boxed Object to
	// override the default (an empty instance of cls).
	NewObjectV(vm *VM, cls *Class, sig string, args *VaList) *Object
}

// VM is the JavaVM: class registry + JNI reference tables.
//
// Reference lifecycle follows the JNI specification — the environment this
// framework promises the guest is ART, and ART enforces exactly these rules:
//
//   - Local refs live in frames. A frame opens when the first ref is boxed for
//     a host-initiated native call and EndCall seals every frame the call
//     touched; the next boxed ref (or next call) recycles them. Steady-state
//     memory is O(one call's worth of objects), never O(everything boxed).
//     Sealed frames stay resolvable for one beat so the host can read return
//     values through NativeObject after the call returned.
//   - Global refs are explicit (NewGlobalRef), keep their handle value for the
//     VM's lifetime, and are the only thing VMState snapshots preserve — some
//     native anti-tamper code is sensitive to handle stability.
//   - Handles are monotonic and never reused, so a stale handle dereferences
//     to nil and is reported, never silently aliased to a newer object.
//
// A VM is NOT safe for concurrent use: it belongs to the single goroutine that
// owns its Emulator. Share emulators across goroutines via emulator.Pool.
type VM struct {
	classes map[string]*Class
	globals map[Ref]*Object
	frames  []*refFrame // stack: index 0 oldest, last is current
	nextRef Ref
	nextID  Ref
	jni     Jni
}

// refFrame is one JNI local-reference frame: the refs boxed within a single
// host-initiated native call, plus any guest PushLocalFrame nesting. Frames
// are pooled — the hot path allocates no map, it reuses the slice buffers.
type refFrame struct {
	refs   []Ref
	objs   []*Object // parallel to refs
	sealed bool
}

var framePool = sync.Pool{New: func() any { return new(refFrame) }}

// handleLimit keeps object handles below the method/field ID range (nextID
// starts at 0x7000_0001) and far away from int32 wraparound; exhaustion is a
// loud panic instead of silent handle aliasing.
const handleLimit = Ref(0x7000_0000)

func (f *refFrame) reset() {
	f.refs = f.refs[:0]
	// clear the full capacity: stale *Object pointers beyond len would pin
	// last-beat objects for as long as the pooled frame sits in the pool
	clear(f.objs[:cap(f.objs)])
	f.objs = f.objs[:0]
	f.sealed = false
}

func (f *refFrame) find(r Ref) int {
	for i := range f.refs {
		if f.refs[i] == r {
			return i
		}
	}
	return -1
}

func (f *refFrame) removeAt(i int) {
	last := len(f.refs) - 1
	f.refs[i], f.refs[last] = f.refs[last], f.refs[i]
	f.objs[i], f.objs[last] = f.objs[last], f.objs[i]
	f.refs = f.refs[:last]
	f.objs = f.objs[:last]
}

func NewVM() *VM {
	return &VM{
		classes: map[string]*Class{},
		globals: map[Ref]*Object{},
		nextRef: 0x100, // start handles away from 0/low ints
		nextID:  0x7000_0001,
	}
}

func (vm *VM) SetJni(j Jni) { vm.jni = j }
func (vm *VM) Jni() Jni     { return vm.jni }

// ResolveClass registers (or returns) a class by JNI name ("a/b/C").
func (vm *VM) ResolveClass(name string, super ...*Class) *Class {
	if c, ok := vm.classes[name]; ok {
		return c
	}
	c := &Class{Name: name, methods: map[string]*Method{}, fields: map[string]*Field{}}
	if len(super) > 0 {
		c.Super = super[0]
	}
	vm.classes[name] = c
	return c
}

// openFrame recycles every sealed frame into the pool and pushes a fresh one.
func (vm *VM) openFrame() {
	kept := vm.frames[:0]
	for _, f := range vm.frames {
		if f.sealed {
			f.reset()
			framePool.Put(f)
			continue
		}
		kept = append(kept, f)
	}
	vm.frames = kept
	vm.frames = append(vm.frames, framePool.Get().(*refFrame))
}

// boxInto pins o in the current frame (opening one if needed) under a fresh
// monotonic handle.
func (vm *VM) boxInto(o *Object) Ref {
	if n := len(vm.frames); n == 0 || vm.frames[n-1].sealed {
		vm.openFrame()
	}
	f := vm.frames[len(vm.frames)-1]
	if vm.nextRef >= handleLimit {
		panic("dvm: JNI handle space exhausted (int32 Ref); recycle or rebuild the emulator")
	}
	r := vm.nextRef
	vm.nextRef++
	f.refs = append(f.refs, r)
	f.objs = append(f.objs, o)
	return r
}

// NewObject boxes a Go value as an instance of cls and returns a local handle.
func (vm *VM) NewObject(cls *Class, value any) Ref {
	return vm.boxInto(&Object{Class: cls, Value: value})
}

// Box registers an already-constructed Object and returns a local handle.
func (vm *VM) Box(o *Object) Ref { return vm.boxInto(o) }

// EndCall seals every frame the finished native call touched. Sealed frames
// stay resolvable for exactly one beat (the host reading return values) and
// are recycled when the next ref is boxed. Call it (via defer) when a
// host-initiated native invocation returns.
func (vm *VM) EndCall() {
	for _, f := range vm.frames {
		f.sealed = true
	}
}

// NewGlobalRef registers r's object in the global table and returns a global
// handle for it (same numeric value; handles are monotonic and unique per
// object). Spec semantics: the ORIGINAL local stays valid — the global is an
// additional reference, not a move. Returns 0 for a stale/zero handle.
func (vm *VM) NewGlobalRef(r Ref) Ref {
	if r == 0 {
		return 0
	}
	if _, ok := vm.globals[r]; ok {
		return r // already global
	}
	if o := vm.Deref(r); o != nil {
		vm.globals[r] = o
		return r
	}
	return 0
}

// DeleteGlobalRef releases a global ref (no-op for unknown handles — the
// ART-lenient resolution of the spec's UB on double delete).
func (vm *VM) DeleteGlobalRef(r Ref) { delete(vm.globals, r) }

// DeleteLocalRef removes r from the innermost frame holding it; unknown
// handles are a no-op (spec UB, resolved leniently like ART).
func (vm *VM) DeleteLocalRef(r Ref) {
	for i := len(vm.frames) - 1; i >= 0; i-- {
		if j := vm.frames[i].find(r); j >= 0 {
			vm.frames[i].removeAt(j)
			return
		}
	}
}

// NewLocalRef returns a fresh local handle for r's object (spec: usable to
// re-create a local from a global). Returns 0 for a stale/zero handle.
func (vm *VM) NewLocalRef(r Ref) Ref {
	if o := vm.Deref(r); o != nil {
		return vm.boxInto(o)
	}
	return 0
}

// PushLocalFrame opens a nested local frame (spec: locals created after this
// die together at PopLocalFrame). Returns JNI_OK (0).
func (vm *VM) PushLocalFrame() int {
	vm.frames = append(vm.frames, framePool.Get().(*refFrame))
	return 0
}

// PopLocalFrame discards the current frame; if result is non-zero its object
// is re-boxed as a local of the parent frame and that handle is returned
// (spec: "the result object is a local reference in the previous frame").
// Lenient resolutions of spec UB: popping the last frame is a no-op, and a
// result that resolves outside the popped frame (parent/global) is accepted.
func (vm *VM) PopLocalFrame(result Ref) Ref {
	if len(vm.frames) <= 1 {
		return result
	}
	var o *Object
	if result != 0 {
		o = vm.Deref(result)
		if o == nil {
			return 0
		}
	}
	top := vm.frames[len(vm.frames)-1]
	vm.frames = vm.frames[:len(vm.frames)-1]
	top.reset()
	framePool.Put(top)
	if result != 0 {
		return vm.boxInto(o)
	}
	return 0
}

// Deref resolves a handle back to its object (nil for 0/stale/unknown — a
// stale handle is reported as nil, never aliased to a newer object).
func (vm *VM) Deref(r Ref) *Object {
	if r == 0 {
		return nil
	}
	for i := len(vm.frames) - 1; i >= 0; i-- {
		if j := vm.frames[i].find(r); j >= 0 {
			return vm.frames[i].objs[j]
		}
	}
	return vm.globals[r]
}

// RefStats reports reference-table occupancy: global refs, frame count, and
// total live local refs. Diagnostic aid for long-lived emulators — flat
// numbers across calls mean the lifecycle is working.
func (vm *VM) RefStats() (globals, frames, locals int) {
	for _, f := range vm.frames {
		locals += len(f.refs)
	}
	return len(vm.globals), len(vm.frames), locals
}

// VMState snapshots the global-reference table so a reused VM hands out the
// same global handles on every call (some native anti-tamper code is sensitive
// to handle values). Class/method/field interning is deliberately left
// untouched: those IDs are stable, deterministic caches and resetting the
// counter without the caches would risk ID collisions.
type VMState struct {
	nextRef Ref
	globals map[Ref]*Object
}

// Snapshot captures the global-reference table (and the handle counter, so
// post-restore handles never collide with pre-snapshot ones). Local frames
// are transient by design and are not preserved: after Restore the next
// boxed ref opens a fresh frame, exactly like a fresh call.
func (vm *VM) Snapshot() VMState {
	globals := make(map[Ref]*Object, len(vm.globals))
	for k, v := range vm.globals {
		globals[k] = v
	}
	return VMState{nextRef: vm.nextRef, globals: globals}
}

// Restore rewinds the global table and handle counter to a prior Snapshot and
// recycles any local frames.
func (vm *VM) Restore(st VMState) {
	for _, f := range vm.frames {
		f.reset()
		framePool.Put(f)
	}
	vm.frames = vm.frames[:0]
	vm.globals = make(map[Ref]*Object, len(st.globals))
	for k, v := range st.globals {
		vm.globals[k] = v
	}
	vm.nextRef = st.nextRef
}

// MethodID / FieldID interning, keyed by "name(sig)".
func (c *Class) MethodID(vm *VM, name, sig string, static bool) *Method {
	key := name + sig
	if m, ok := c.methods[key]; ok {
		return m
	}
	id := vm.nextID
	vm.nextID++
	m := &Method{ID: id, Name: name, Sig: sig, Static: static}
	c.methods[key] = m
	return m
}

// FieldID interns a field by name + type descriptor (e.g. "Ljava/lang/String;").
func (c *Class) FieldID(vm *VM, name, sig string, static bool) *Field {
	key := name + ":" + sig
	if f, ok := c.fields[key]; ok {
		return f
	}
	id := vm.nextID
	vm.nextID++
	f := &Field{ID: id, Name: name, Sig: sig, Static: static}
	c.fields[key] = f
	return f
}

// Methods returns the class's registered methods (e.g. after LoadDex).
func (c *Class) Methods() []*Method {
	out := make([]*Method, 0, len(c.methods))
	for _, m := range c.methods {
		out = append(out, m)
	}
	return out
}

// Fields returns the class's registered fields.
func (c *Class) Fields() []*Field {
	out := make([]*Field, 0, len(c.fields))
	for _, f := range c.fields {
		out = append(out, f)
	}
	return out
}

// LookupClass returns an already-registered class (without creating one).
func (vm *VM) LookupClass(name string) (*Class, bool) {
	c, ok := vm.classes[name]
	return c, ok
}

// Classes returns every registered class (e.g. all classes loaded from a DEX).
func (vm *VM) Classes() []*Class {
	out := make([]*Class, 0, len(vm.classes))
	for _, c := range vm.classes {
		out = append(out, c)
	}
	return out
}

func (c *Class) String() string { return c.Name }

// Helpers to build common boxed values, matching the host app's usage.
func NewString(vm *VM, s string) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/String"), s)
}
func NewByteArray(vm *VM, b []byte) Ref {
	return vm.NewObject(vm.ResolveClass("[B"), b)
}
func NewLong(vm *VM, v int64) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/Long"), v)
}
func NewInteger(vm *VM, v int32) Ref {
	return vm.NewObject(vm.ResolveClass("java/lang/Integer"), v)
}

// MethodSig formats the "class->method(sig)" key the way unidbg dispatches and
// the host app's switch statements expect.
func MethodSig(cls *Class, nameSig string) string {
	return fmt.Sprintf("%s->%s", cls.Name, nameSig)
}
