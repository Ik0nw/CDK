// Linux arm (32-bit, EABI) NR for memfd_create.  arm EABI NR = 356
// (same offset as i386 NR space + 356 = 385? Actually EABI uses same
// NRs but there was legacy ABI offset.  memfd_create was added in
// 3.17, well after the legacy ABI was deprecated, so NR = 385 for
// the 32-bit ARM OABI compat; modern kernels expose it at 385.)
//
// Confirmed: linux 6.1 arch/arm/tools/syscall.tbl: memfd_create 385.

//go:build linux && arm
// +build linux,arm

package evaluate

// memfdCreateNR is the raw syscall number (modern arm EABI = 385).
var memfdCreateNR uintptr = 385
