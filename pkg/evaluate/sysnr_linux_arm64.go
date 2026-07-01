// +build linux,arm64

package evaluate

import "syscall"

// syscall NRs for linux/arm64.  arm64 is the only arch where Go exposes
// SYS_SECCOMP.  Landlock_create_ruleset is not exposed on any arch, so we
// still need a manual definition.  Values from
// linux/arch/arm64/tools/syscall_64.tbl.
const (
	nr_seccomp               uintptr = syscall.SYS_SECCOMP
	nr_landlock_create_ruleset uintptr = 442
	nr_io_uring_setup        uintptr = 426
	nr_process_vm_readv      uintptr = 270
	nr_process_vm_writev     uintptr = 271
	nr_bpf                   uintptr = 280
)

// Reference sanity check (SYS_PRCTL on arm64 = 167; the named constant exists).
var _ = syscall.SYS_PRCTL
