// +build linux,386

package evaluate

import "syscall"

// syscall NRs for linux/i386 (x86_32).  Values from
// linux/arch/x86/entry/syscalls/syscall_32.tbl.
const (
	nr_seccomp               uintptr = 354
	nr_landlock_create_ruleset uintptr = 443
	nr_io_uring_setup        uintptr = 425
	nr_process_vm_readv      uintptr = 347
	nr_process_vm_writev     uintptr = 348
	nr_bpf                   uintptr = 357
)

var _ = syscall.SYS_PRCTL
