// +build linux,arm

package evaluate

import "syscall"

// syscall NRs for linux/arm (32-bit EABI, OABI deprecated).  Values from
// linux/arch/arm/tools/syscall.tbl.
const (
	nr_seccomp               uintptr = 383
	nr_landlock_create_ruleset uintptr = 445
	nr_io_uring_setup        uintptr = 427
	nr_process_vm_readv      uintptr = 377
	nr_process_vm_writev     uintptr = 378
	nr_bpf                   uintptr = 386
)

var _ = syscall.SYS_PRCTL
