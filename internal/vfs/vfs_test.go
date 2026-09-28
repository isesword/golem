package vfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAsset materializes a host asset file under root, creating parents.
func writeAsset(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostPathStaticMapping(t *testing.T) {
	root := t.TempDir()
	v := New(root, 1234, "app")
	sdk := filepath.Join(root, "android", "sdk23")
	cases := []struct {
		guest string
		want  string // "" means no static mapping
	}{
		{"/system/lib64/libc.so", filepath.Join(sdk, "lib64", "libc.so")},
		{"/system/lib64/libm.so", filepath.Join(sdk, "lib64", "libm.so")},
		{"/apex/com.android.runtime/lib64/libc.so", filepath.Join(sdk, "lib64", "libc.so")},
		{"/dev/__properties__", filepath.Join(sdk, "dev", "__properties__")},
		{"/proc/stat", filepath.Join(sdk, "proc", "stat")},
		{"/system/usr/share/zoneinfo/Asia/Shanghai", filepath.Join(sdk, "system", "usr", "share", "zoneinfo", "Shanghai")},
		{"/system/lib64/sub/dir/libx.so", filepath.Join(sdk, "lib64", "libx.so")}, // flattened to basename
		{"/system/lib/libc.so", ""},  // 32-bit path not mapped
		{"/data/app/libfoo.so", ""},  // unmapped subtree
		{"/proc/self/cmdline", ""},   // synthetic, not a static asset
		{"/etc/passwd", ""},          // host path, never mapped
		{"system/lib64/libc.so", ""}, // relative guest path
	}
	for _, c := range cases {
		if got := v.hostPath(c.guest); got != c.want {
			t.Errorf("hostPath(%q) = %q, want %q", c.guest, got, c.want)
		}
	}
}

// Traversal attempts must never resolve to a host path outside assetRoot.
func TestHostPathTraversalBlocked(t *testing.T) {
	root := t.TempDir()
	v := New(root, 1234, "app")
	adversarial := []string{
		"/system/lib64/../../etc/passwd",
		"/system/lib64/../../../../../../etc/passwd",
		"/system/lib64/..",
		"/system/lib64/../lib/libc.so",
		"/apex/com.android.runtime/lib64/../../lib/libc.so",
		"/system/usr/share/zoneinfo/../../../build.prop",
		"/system/usr/share/zoneinfo/../../../../etc/hosts",
		"/dev/../../etc/passwd",
	}
	for _, g := range adversarial {
		hp := v.hostPath(g)
		if hp == "" {
			continue // rejected outright: good
		}
		rel, err := filepath.Rel(root, hp)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			t.Errorf("hostPath(%q) = %q escapes assetRoot %q", g, hp, root)
		}
	}
	// A traversal that escapes any mapped prefix must also fail to Read.
	if _, err := v.Read("/system/lib64/../../etc/passwd"); err == nil {
		t.Error("Read of traversal path should fail")
	}
}

func TestReadAssetFile(t *testing.T) {
	root := t.TempDir()
	writeAsset(t, root, filepath.Join("android", "sdk23", "lib64", "libc.so"), "fake libc bytes")
	writeAsset(t, root, filepath.Join("android", "sdk23", "proc", "stat"), "cpu 1 2 3")

	v := New(root, 1234, "app")
	got, err := v.Read("/system/lib64/libc.so")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake libc bytes" {
		t.Fatalf("Read(/system/lib64/libc.so) = %q", got)
	}
	if !v.Exists("/system/lib64/libc.so") {
		t.Error("Exists(/system/lib64/libc.so) = false, want true")
	}
	if got, err := v.Read("/proc/stat"); err != nil || string(got) != "cpu 1 2 3" {
		t.Errorf("Read(/proc/stat) = %q, %v", got, err)
	}

	// Mapped prefix but missing backing file: Read errors, Exists is false.
	if _, err := v.Read("/system/lib64/libmissing.so"); err == nil {
		t.Error("Read of missing asset should fail")
	}
	if v.Exists("/system/lib64/libmissing.so") {
		t.Error("Exists of missing asset = true, want false")
	}

	// Unmapped path: Read reports "no such file".
	if _, err := v.Read("/data/app/libfoo.so"); err == nil ||
		!strings.Contains(err.Error(), "vfs: no such file") {
		t.Errorf("Read of unmapped path err = %v, want 'vfs: no such file'", err)
	}
}

// Read consults fallback BEFORE synth and assets, so the host resolver wins
// (mirrors unidbg's IOResolver running before the built-in /proc generators).
func TestReadPriorityFallbackFirst(t *testing.T) {
	root := t.TempDir()
	writeAsset(t, root, filepath.Join("android", "sdk23", "lib64", "libc.so"), "asset libc")
	v := New(root, 4321, "com.test.app")

	// Baseline, no fallback: synth serves cmdline, asset serves libc.so.
	if got, _ := v.Read("/proc/self/cmdline"); string(got) != "com.test.app\x00" {
		t.Fatalf("baseline cmdline = %q", got)
	}
	if got, _ := v.Read("/system/lib64/libc.so"); string(got) != "asset libc" {
		t.Fatalf("baseline libc = %q", got)
	}

	// Fallback supplying both paths overrides synth AND asset content.
	v.SetFallback(func(guest string) ([]byte, bool, error) {
		return []byte("fallback:" + guest), true, nil
	})
	if got, _ := v.Read("/proc/self/cmdline"); string(got) != "fallback:/proc/self/cmdline" {
		t.Errorf("fallback should win over synth, got %q", got)
	}
	if got, _ := v.Read("/system/lib64/libc.so"); string(got) != "fallback:/system/lib64/libc.so" {
		t.Errorf("fallback should win over asset, got %q", got)
	}

	// Fall-through (nil, false, nil) hands control back to synth/assets.
	v.SetFallback(func(guest string) ([]byte, bool, error) { return nil, false, nil })
	if got, _ := v.Read("/proc/self/cmdline"); string(got) != "com.test.app\x00" {
		t.Errorf("after fall-through cmdline = %q", got)
	}
	if got, _ := v.Read("/system/lib64/libc.so"); string(got) != "asset libc" {
		t.Errorf("after fall-through libc = %q", got)
	}
}

func TestFallbackThreeWay(t *testing.T) {
	v := New(t.TempDir(), 4321, "app")
	sentinel := errors.New("denied by resolver")

	// (content, true, nil): supplies the file.
	v.SetFallback(func(string) ([]byte, bool, error) { return []byte("blob"), true, nil })
	if got, err := v.Read("/vendor/lib/libx.so"); err != nil || string(got) != "blob" {
		t.Errorf("supply: Read = %q, %v", got, err)
	}
	if !v.Exists("/vendor/lib/libx.so") {
		t.Error("supply: Exists = false, want true")
	}

	// (nil, true, err): forces an error; Read must surface that exact error.
	v.SetFallback(func(string) ([]byte, bool, error) { return nil, true, sentinel })
	if _, err := v.Read("/vendor/lib/libx.so"); !errors.Is(err, sentinel) {
		t.Errorf("deny: Read err = %v, want sentinel", err)
	}
	if v.Exists("/vendor/lib/libx.so") {
		t.Error("deny: Exists = true, want false")
	}

	// (nil, false, nil): falls through to the default "no such file".
	v.SetFallback(func(string) ([]byte, bool, error) { return nil, false, nil })
	if _, err := v.Read("/vendor/lib/libx.so"); err == nil ||
		!strings.Contains(err.Error(), "vfs: no such file") {
		t.Errorf("fall-through: Read err = %v, want 'vfs: no such file'", err)
	}
	if v.Exists("/vendor/lib/libx.so") {
		t.Error("fall-through: Exists = true, want false")
	}
}

func TestSyntheticProcFiles(t *testing.T) {
	v := New(t.TempDir(), 4321, "com.example.testapp")

	cmd, err := v.Read("/proc/self/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if string(cmd) != "com.example.testapp\x00" {
		t.Errorf("cmdline = %q, want NUL-terminated procName", cmd)
	}

	st, err := v.Read("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	// Non-default pid must appear: proves the pid argument is used.
	if !strings.Contains(string(st), "Pid:\t4321\n") {
		t.Errorf("status missing Pid 4321:\n%s", st)
	}
	// comm is capped at 15 chars (implementation keeps the LAST 15).
	if !strings.Contains(string(st), "Name:\texample.testapp\n") {
		t.Errorf("status missing truncated Name:\n%s", st)
	}
	if !strings.Contains(string(st), "PPid:\t1\n") || !strings.Contains(string(st), "TracerPid:\t0\n") {
		t.Errorf("status missing PPid/TracerPid:\n%s", st)
	}

	id, err := v.Read("/proc/sys/kernel/random/boot_id")
	if err != nil || string(id) != "00000000-0000-0000-0000-000000000000\n" {
		t.Errorf("boot_id = %q, %v", id, err)
	}

	// Early stubs: present but empty until the loader publishes real content.
	for _, g := range []string{"/proc/self/maps", "/proc/self/auxv"} {
		got, err := v.Read(g)
		if err != nil || len(got) != 0 {
			t.Errorf("Read(%q) = %q, %v; want empty stub", g, got, err)
		}
	}

	// All synthetic paths must report Exists.
	for _, g := range []string{
		"/proc/self/cmdline", "/proc/self/status", "/proc/self/maps",
		"/proc/self/auxv", "/proc/sys/kernel/random/boot_id",
	} {
		if !v.Exists(g) {
			t.Errorf("Exists(%q) = false, want true", g)
		}
	}
}

func TestSyntheticDefaultProcName(t *testing.T) {
	v := New(t.TempDir(), 7, "")
	got, err := v.Read("/proc/self/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "com.golem.app\x00" {
		t.Errorf("default cmdline = %q", got)
	}
	if st, _ := v.Read("/proc/self/status"); !strings.Contains(string(st), "Pid:\t7\n") {
		t.Errorf("default status missing Pid 7:\n%s", st)
	}
}

func TestSetMaps(t *testing.T) {
	v := New(t.TempDir(), 4321, "app")
	if got, _ := v.Read("/proc/self/maps"); len(got) != 0 {
		t.Fatalf("initial maps = %q, want empty stub", got)
	}
	const maps = "7f0000-7f1000 r-xp 00000000 fd:00 1 /system/lib64/libc.so\n"
	v.SetMaps(maps)
	got, err := v.Read("/proc/self/maps")
	if err != nil || string(got) != maps {
		t.Errorf("after SetMaps, Read = %q, %v", got, err)
	}
	if !v.Exists("/proc/self/maps") {
		t.Error("Exists(/proc/self/maps) = false after SetMaps")
	}
}

// Guest paths are path.Clean'd before lookup, so // and /./ and infix /../
// all resolve to the canonical entry.
func TestReadCleansGuestPath(t *testing.T) {
	v := New(t.TempDir(), 4321, "cleanme")
	for _, g := range []string{
		"/proc/self/../self/cmdline",
		"/proc//self/./cmdline",
		"/proc/self/sub/../../self/cmdline",
	} {
		got, err := v.Read(g)
		if err != nil || string(got) != "cleanme\x00" {
			t.Errorf("Read(%q) = %q, %v", g, got, err)
		}
	}
}

// An empty assetRoot still serves synthetic files; asset reads fail with the
// host OS error (locating a real asset dir is the caller's job).
func TestEmptyAssetRoot(t *testing.T) {
	v := New("", 4321, "app")
	if got, err := v.Read("/proc/self/cmdline"); err != nil || string(got) != "app\x00" {
		t.Errorf("synthetic read with empty root = %q, %v", got, err)
	}
	if _, err := v.Read("/system/lib64/libc.so"); err == nil {
		t.Error("asset read with empty root should fail")
	}
	if v.Exists("/system/lib64/libc.so") {
		t.Error("Exists with empty root = true, want false")
	}
}
