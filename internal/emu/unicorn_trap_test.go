//go:build unicorn && (darwin || linux)

package emu

import "testing"

// TestInstallTrapAdapter exercises the P0 InstallTrap adapter on a real
// engine: two handlers registered under different kinds both fire on SVC,
// each receiving the kind it was REGISTERED under (no runtime discrimination
// yet), and Remove detaches a registration.
func TestInstallTrapAdapter(t *testing.T) {
	be, err := NewNamed("", ArchARM64)
	if err != nil {
		t.Skipf("no backend: %v", err)
	}
	defer be.Close()

	const base = 0x100000
	if err := be.MemMap(base, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	// svc #0 (0xD4000001) twice.
	code := []byte{0x01, 0x00, 0x00, 0xd4, 0x01, 0x00, 0x00, 0xd4}
	if err := be.MemWrite(base, code); err != nil {
		t.Fatal(err)
	}

	var gotHost, gotSyscall []TrapKind
	h1, err := be.InstallTrap(TrapHostCall, func(_ Backend, k TrapKind) { gotHost = append(gotHost, k) })
	if err != nil {
		t.Fatal(err)
	}
	defer h1.Remove()
	h2, err := be.InstallTrap(TrapSyscall, func(_ Backend, k TrapKind) { gotSyscall = append(gotSyscall, k) })
	if err != nil {
		t.Fatal(err)
	}

	if err := be.Start(base, base+8); err != nil {
		t.Fatal(err)
	}
	// 2 SVCs × 1 handler each; kind is the registration kind, verbatim.
	if len(gotHost) != 2 || gotHost[0] != TrapHostCall || gotHost[1] != TrapHostCall {
		t.Errorf("host-call handler got %v, want 2× TrapHostCall", gotHost)
	}
	if len(gotSyscall) != 2 || gotSyscall[0] != TrapSyscall || gotSyscall[1] != TrapSyscall {
		t.Errorf("syscall handler got %v, want 2× TrapSyscall", gotSyscall)
	}

	// After Remove, only the remaining handler fires.
	if err := h2.Remove(); err != nil {
		t.Fatal(err)
	}
	gotHost, gotSyscall = nil, nil
	if err := be.Start(base, base+4); err != nil {
		t.Fatal(err)
	}
	if len(gotHost) != 1 {
		t.Errorf("after Remove: host-call handler fired %d times, want 1", len(gotHost))
	}
	if len(gotSyscall) != 0 {
		t.Errorf("after Remove: syscall handler fired %d times, want 0", len(gotSyscall))
	}
}
