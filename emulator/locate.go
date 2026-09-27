package emulator

import (
	"os"
	"path/filepath"
	"runtime"
)

// Locate finds a data directory named `name` (e.g. "assets") by checking, in
// order: the cwd, the parent of cwd, and the executable's dir / its parents.
// This lets binaries find their data wherever it's reasonably placed (next to
// the exe or up a level) without a hardcoded path. Returns `name` unchanged if
// nothing matches (caller can still error clearly).
func Locate(name string) string {
	cands := []string{name, filepath.Join("..", name)}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(d, name),
			filepath.Join(d, "..", name),
			filepath.Join(d, "..", "..", name),
		)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return name
}

// LocateFile is like Locate but for a file searched inside a located
// directory `dir` (e.g. LocateFile("libs", "libfoo.so")).
func LocateFile(dir, file string) string {
	return filepath.Join(Locate(dir), file)
}

// AssetsDir returns the directory of the bionic sysroot bundled with this
// module (assets/android/sdk23/...). It resolves relative to this source
// file's compiled-in path, so it works for local replace directives and for
// module-cache builds alike. Override with $GOLEM_ASSETS.
func AssetsDir() string {
	if p := os.Getenv("GOLEM_ASSETS"); p != "" {
		return p
	}
	_, file, _, ok := runtime.Caller(0)
	if ok {
		root := filepath.Dir(filepath.Dir(file)) // emulator/ -> module root
		c := filepath.Join(root, "assets")
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return "assets"
}
