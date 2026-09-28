//go:build !windows

package main

import (
	"runtime"
	"syscall"
)

// peakRSS returns ru_maxrss (peak resident set) via getrusage.
func peakRSS() uint64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	rss := uint64(ru.Maxrss)
	if runtime.GOOS == "linux" {
		rss *= 1024 // Linux reports KB, darwin reports bytes
	}
	return rss
}
