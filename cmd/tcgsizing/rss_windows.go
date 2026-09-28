//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// peakRSS returns the process peak working set via
// GetProcessMemoryInfo (psapi.dll) — Windows has no getrusage.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uint64
	workingSetSize             uint64
	quotaPeakPagedPoolUsage    uint64
	quotaPagedPoolUsage        uint64
	quotaPeakNonPagedPoolUsage uint64
	quotaNonPagedPoolUsage     uint64
	pagefileUsage              uint64
	peakPagefileUsage          uint64
}

func peakRSS() uint64 {
	mod := windows.NewLazySystemDLL("psapi.dll")
	proc := mod.NewProc("GetProcessMemoryInfo")
	h, _ := windows.GetCurrentProcess()
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	r1, _, _ := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb))
	if r1 == 0 {
		return 0
	}
	return pmc.peakWorkingSetSize
}

var _ = syscall.GetCurrentProcess
