// Linux arm64 NR for memfd_create.
//
// Go's syscall package exports SYS_MEMFD_CREATE on arm64; use that
// directly so upstream NR renumbering (unlikely) is automatically
// picked up.

//go:build linux && arm64
// +build linux,arm64

package evaluate

import "syscall"

// memfdCreateNR is the raw syscall number (named constant).
var memfdCreateNR uintptr = syscall.SYS_MEMFD_CREATE
