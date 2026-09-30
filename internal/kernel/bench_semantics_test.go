package kernel

import "testing"

// Benchmarks for the hot syscalls touched by the semantics round (close/lseek/
// writev/getrandom). Run before/after semantic changes to prove zero
// regression: go test -bench BenchmarkSem -benchmem ./internal/kernel/
func BenchmarkSemClose(b *testing.B) {
	k := newKernelCtxt(b)
	fd := k.openTestFile()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.call(nrClose, uint64(fd))
		k.call(nrOpenat, 0, k.putStr(scratch, "/data/local/bench.bin"), oWRONLY|oCREAT)
	}
}

func BenchmarkSemCloseUnknown(b *testing.B) {
	k := newKernelCtxt(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.call(nrClose, 0xdead) // EBADF path
	}
}

func BenchmarkSemLseek(b *testing.B) {
	k := newKernelCtxt(b)
	fd := k.openTestFile()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.call(nrLseek, uint64(fd), uint64(i%64), 0) // SEEK_SET
	}
}

func BenchmarkSemGetrandomDeterministic(b *testing.B) {
	k := newKernelCtxt(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.call(nrGetrandom, scratch, 64, 0)
	}
}

func BenchmarkSemWritev(b *testing.B) {
	k := newKernelCtxt(b)
	const wpath = "/data/local/benchiov.bin"
	fd := k.call(nrOpenat, 0, k.putStr(scratch+0x800, wpath), oWRONLY|oCREAT)
	k.be.MemWrite(scratch+0x1000, []byte("ABCD"))
	var iov [32]byte
	binaryLittleEndianPutUint64(iov[0:], scratch+0x1000)
	binaryLittleEndianPutUint64(iov[8:], 4)
	k.be.MemWrite(scratch+0x1200, iov[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k.call(nrWritev, uint64(fd), scratch+0x1200, 1)
	}
}

func binaryLittleEndianPutUint64(dst []byte, v uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}
