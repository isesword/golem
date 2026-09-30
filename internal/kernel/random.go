package kernel

// DeterministicRandom fills buf from golem's deterministic entropy stream — a
// splitmix64-style mixer over seed. It is the single generator behind both
// consumers of deterministic randomness:
//
//   - SysGetrandom (default, non-TrueRandom mode) derives a per-call seed
//     from ALL syscall arguments plus a call counter, then streams from here;
//   - platform StartupABI builds the auxv AT_RANDOM 16 bytes from here with a
//     fixed seed (P4d — the initial stack's random canary shares the syscall
//     path's deterministic source instead of carrying its own ad-hoc bytes).
//
// Deterministic so runs stay reproducible — and trivially distinguishable
// from real entropy: guests that sample it for anti-emulation checks will
// see through it (kernel.Context.TrueRandom opts the syscall path into
// crypto/rand for those). Byte-identical output for a given seed is part of
// the contract; do not change the mixer.
func DeterministicRandom(seed uint64, buf []byte) {
	x := seed
	for i := range buf {
		x += 0x9E3779B97F4A7C15
		x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
		x = (x ^ (x >> 27)) * 0x94D049BB133111EB
		x ^= x >> 31
		buf[i] = byte(x >> 56)
	}
}
