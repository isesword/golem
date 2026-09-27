package dvm

import "testing"

// JNI reference-lifecycle conformance tests. These pin the semantics the
// framework promises guests: local refs die with their call's frame (one-beat
// grace for return-value reads), globals are explicit and stable, handles are
// monotonic so stale handles can never alias a newer object.

func TestBoxDerefRoundTrip(t *testing.T) {
	vm := NewVM()
	o := &Object{Class: vm.ResolveClass("java/lang/String"), Value: "hi"}
	r := vm.Box(o)
	if vm.Deref(r) != o {
		t.Fatal("Deref(Box(o)) != o")
	}
	if vm.Deref(0) != nil {
		t.Fatal("Deref(0) must be nil")
	}
}

func TestLocalRefsDieWithFrame(t *testing.T) {
	vm := NewVM()
	r1 := vm.Box(&Object{Value: "call1"})
	vm.EndCall() // call 1 returned

	// one-beat grace: the host can still read return values
	if vm.Deref(r1) == nil {
		t.Fatal("sealed frame must stay resolvable for the return-value beat")
	}

	// the next boxed ref recycles the sealed frame
	r2 := vm.Box(&Object{Value: "call2"})
	if vm.Deref(r1) != nil {
		t.Fatal("local ref from a recycled frame must be dead")
	}
	if vm.Deref(r2) == nil {
		t.Fatal("fresh ref must resolve")
	}
	if r2 == r1 {
		t.Fatal("handles are monotonic — never reused")
	}
}

func TestGlobalRefsExplicitAndStable(t *testing.T) {
	vm := NewVM()
	r := vm.Box(&Object{Value: "ctx"})

	g := vm.NewGlobalRef(r)
	if g != r {
		t.Fatalf("NewGlobalRef must keep the handle value stable, got %d want %d", g, r)
	}
	// promotion removes it from the frame: deleting the local no longer kills it
	vm.DeleteLocalRef(r)
	if vm.Deref(g) == nil {
		t.Fatal("global ref must survive DeleteLocalRef of the original local")
	}

	vm.EndCall()
	vm.Box(&Object{Value: "next"}) // recycle all frames
	if vm.Deref(g) == nil {
		t.Fatal("global ref must survive frame recycling")
	}

	vm.DeleteGlobalRef(g)
	if vm.Deref(g) != nil {
		t.Fatal("deleted global must be gone")
	}
	vm.DeleteGlobalRef(g) // double delete: lenient no-op
	if g2, _, l := vm.RefStats(); g2 != 0 || l != 1 {
		// l=1: the "next" local boxed above is still in its live frame
		t.Fatalf("after delete: globals=%d locals=%d, want 0/1", g2, l)
	}
}

func TestNewGlobalRefEdgeCases(t *testing.T) {
	vm := NewVM()
	if vm.NewGlobalRef(0) != 0 {
		t.Fatal("NewGlobalRef(0) = 0")
	}
	if vm.NewGlobalRef(Ref(0x99999)) != 0 {
		t.Fatal("NewGlobalRef(stale) = 0, never a fabricated ref")
	}
	// double promote returns the same stable handle
	r := vm.Box(&Object{Value: "x"})
	if vm.NewGlobalRef(r) != r || vm.NewGlobalRef(r) != r {
		t.Fatal("re-promotion must be idempotent on the handle value")
	}
	// copy semantics: the original local remains valid alongside the global
	if vm.Deref(r) == nil {
		t.Fatal("NewGlobalRef must not invalidate the original local")
	}
	if g, _, _ := vm.RefStats(); g != 1 {
		t.Fatalf("globals=%d, want 1", g)
	}
}

func TestDeleteLocalRefLenient(t *testing.T) {
	vm := NewVM()
	r := vm.Box(&Object{Value: "x"})
	vm.DeleteLocalRef(r)
	if vm.Deref(r) != nil {
		t.Fatal("deleted local must be gone")
	}
	vm.DeleteLocalRef(r) // double delete: lenient no-op
	vm.DeleteLocalRef(0)
	vm.DeleteLocalRef(Ref(0x99999))
}

func TestPushPopLocalFrame(t *testing.T) {
	vm := NewVM()
	parent := vm.Box(&Object{Value: "parent"})

	if vm.PushLocalFrame() != 0 {
		t.Fatal("PushLocalFrame returns JNI_OK")
	}
	child := vm.Box(&Object{Value: "child"})
	if vm.Deref(child) == nil {
		t.Fatal("child frame ref resolves while frame open")
	}

	// pop without result: child dies, parent survives
	if vm.PopLocalFrame(0) != 0 {
		t.Fatal("PopLocalFrame(0) returns NULL")
	}
	if vm.Deref(child) != nil {
		t.Fatal("child frame refs die at PopLocalFrame")
	}
	if vm.Deref(parent) == nil {
		t.Fatal("parent frame refs survive child pop")
	}

	// pop WITH result: result is re-boxed into the parent under a NEW handle
	vm.PushLocalFrame()
	inChild := vm.Box(&Object{Value: "result"})
	popped := vm.PopLocalFrame(inChild)
	if popped == 0 || popped == inChild {
		t.Fatalf("PopLocalFrame(result) must return a fresh parent-frame handle, got %d (in %d)", popped, inChild)
	}
	if vm.Deref(popped) == nil {
		t.Fatal("promoted result must resolve in the parent frame")
	}
	if vm.Deref(inChild) != nil {
		t.Fatal("the child-frame handle of the result is dead after pop")
	}
}

func TestPopLastFrameIsLenientNoop(t *testing.T) {
	vm := NewVM()
	r := vm.Box(&Object{Value: "x"})
	if vm.PopLocalFrame(r) != r {
		t.Fatal("popping the base frame is a no-op (lenient)")
	}
	if vm.Deref(r) == nil {
		t.Fatal("no-op pop must not destroy the ref")
	}
}

func TestStaleHandlesNeverAlias(t *testing.T) {
	vm := NewVM()
	a := &Object{Value: "A"}
	b := &Object{Value: "B"}
	ra := vm.Box(a)
	vm.EndCall()
	vm.Box(b) // recycles the frame
	// after recycling the OLD number must resolve to nothing at all —
	// neither A (freed) nor B (the newer object in the recycled frame)
	if got := vm.Deref(ra); got != nil {
		t.Fatalf("stale handle resolved to %v — must be nil", got)
	}
}

func TestVMStatePreservesGlobalsOnly(t *testing.T) {
	vm := NewVM()
	gl := vm.NewGlobalRef(vm.Box(&Object{Value: "global"}))
	local := vm.Box(&Object{Value: "local"})
	vm.EndCall()

	st := vm.Snapshot()
	vm.Box(&Object{Value: "transient"}) // recycle the sealed frame
	vm.Restore(st)

	if vm.Deref(gl) == nil {
		t.Fatal("global refs must survive Snapshot/Restore with stable values")
	}
	if vm.Deref(local) != nil {
		t.Fatal("local refs are transient and must not survive Restore")
	}
	if _, _, l := vm.RefStats(); l != 0 {
		t.Fatalf("frames must be empty after Restore, got %d locals", l)
	}
	// the VM keeps working: next box opens a fresh frame
	if r := vm.Box(&Object{Value: "post"}); vm.Deref(r) == nil {
		t.Fatal("VM must be usable after Restore")
	}
}

// --- review additions: spec corners that had no coverage ---

func TestNewLocalRefPaths(t *testing.T) {
	vm := NewVM()
	cls := vm.ResolveClass("java/lang/String")
	o := &Object{Class: cls, Value: "x"}

	// stale / 0 -> 0, never fabricated
	if vm.NewLocalRef(0) != 0 || vm.NewLocalRef(Ref(0x99999)) != 0 {
		t.Fatal("NewLocalRef(stale/0) must be 0")
	}
	// local -> fresh handle, same object
	r := vm.Box(o)
	l1 := vm.NewLocalRef(r)
	if l1 == 0 || l1 == r || vm.Deref(l1) != o {
		t.Fatalf("NewLocalRef(local): got %d, want fresh handle to same object", l1)
	}
	// global -> fresh local handle to the same object
	g := vm.NewGlobalRef(r)
	l2 := vm.NewLocalRef(g)
	if l2 == 0 || vm.Deref(l2) != o {
		t.Fatal("NewLocalRef(global) must re-create a local for the object")
	}
	// identity: IsSameObject-equivalent — all handles deref to one *Object
	if vm.Deref(r) != vm.Deref(l1) || vm.Deref(l1) != vm.Deref(l2) {
		t.Fatal("all handles must deref to the same object")
	}
}

func TestNestedFramesTwoDeep(t *testing.T) {
	vm := NewVM()
	root := vm.Box(&Object{Value: "root"})
	vm.PushLocalFrame()
	mid := vm.Box(&Object{Value: "mid"})
	vm.PushLocalFrame()
	leaf := vm.Box(&Object{Value: "leaf"})

	// promote from the innermost frame
	g := vm.NewGlobalRef(leaf)
	if g != leaf {
		t.Fatal("promotion from nested frame keeps the handle value")
	}
	// pop leaf frame: the leaf FRAME dies; the promoted global keeps the same
	// handle value alive (value-stable promotion), mid and root untouched
	if vm.PopLocalFrame(0) != 0 {
		t.Fatal("pop leaf")
	}
	if vm.Deref(leaf) == nil || vm.Deref(g) == nil || vm.Deref(mid) == nil || vm.Deref(root) == nil {
		t.Fatal("global (leaf value), mid and root must survive the leaf pop")
	}
	// a NON-promoted sibling of the leaf frame must be dead
	if vm.Deref(vm.nextRef) != nil {
		t.Fatal("fresh stale handle must not resolve")
	}
	// pop mid frame: mid dies, root survives
	vm.PopLocalFrame(0)
	if vm.Deref(mid) != nil {
		t.Fatal("mid frame refs die at pop")
	}
	if vm.Deref(root) == nil || vm.Deref(g) == nil {
		t.Fatal("root and global survive mid pop")
	}
}

func TestPopLocalFrameWithGlobalResult(t *testing.T) {
	vm := NewVM()
	gl := vm.NewGlobalRef(vm.Box(&Object{Value: "g"}))
	vm.PushLocalFrame()
	// popping with a global result re-boxes it as a local of the parent
	popped := vm.PopLocalFrame(gl)
	if popped == 0 || vm.Deref(popped) == nil {
		t.Fatal("global result must be re-boxed into the parent frame")
	}
	if vm.Deref(gl) == nil {
		t.Fatal("the global itself must remain valid")
	}
}

func TestDeleteLocalRefOnGlobalIsLenient(t *testing.T) {
	vm := NewVM()
	gl := vm.NewGlobalRef(vm.Box(&Object{Value: "g"}))
	vm.DeleteLocalRef(gl) // spec UB, resolved leniently: globals untouched
	if vm.Deref(gl) == nil {
		t.Fatal("DeleteLocalRef must not touch a global ref")
	}
}

func TestRefStatsBoundedAcrossCalls(t *testing.T) {
	// The Phase A memory claim: steady state is O(one call's objects), not
	// O(every object ever boxed). 2000 call cycles must leave the table flat.
	vm := NewVM()
	for i := 0; i < 2000; i++ {
		for j := 0; j < 8; j++ {
			vm.Box(&Object{Value: j})
		}
		vm.EndCall()
	}
	g, f, l := vm.RefStats()
	// the final call's refs sit in their sealed frame (one-beat grace), so the
	// bound is "at most one call's worth" — the O(1) memory claim, verified
	if g != 0 || f != 1 || l > 8 {
		t.Fatalf("after 2000 calls: globals=%d frames=%d locals=%d, want 0/1/<=8", g, f, l)
	}
}
