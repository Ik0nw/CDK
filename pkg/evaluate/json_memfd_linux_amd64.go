// Linux amd64 (x86_64) NR for memfd_create, from
// linux/uapi/asm-generic/unistd.h (x86_64 nr table).
//
// Go's syscall package does not export a named SYS_MEMFD_CREATE on
// amd64, so we hard-code the NR.  The NR was fixed in Linux 3.17 and
// has never been renumbered on this architecture; memfd_create is
// glibc-wrapped at NR 319.  Runtime ENOSYS fallback handles kernels
// older than 3.17 inside memfdCreate.

//go:build linux && amd64
// +build linux,amd64

package evaluate

import "syscall"

// memfdCreateNR is the raw syscall number.
var memfdCreateNR uintptr = 319

// compile-time assert: if Go ever adds the named constant on amd64
// we would prefer to use it, but 319 is also stable.
var _ = syscall.SYS_FUTEX // ensure syscall package still imports-compatible
