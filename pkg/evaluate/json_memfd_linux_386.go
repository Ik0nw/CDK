// Linux i386 NR for memfd_create.  32-bit x86 NR = 356.

//go:build linux && 386
// +build linux,386

package evaluate

// memfdCreateNR is the raw syscall number.
var memfdCreateNR uintptr = 356
