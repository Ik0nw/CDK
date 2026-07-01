// +build linux,amd64

package evaluate

import "syscall"

// syscall NRs for linux/amd64 where Go's syscall package does not expose
// named constants (NR 300+ syscalls generally missing from the legacy pkg).
// Values are from linux/arch/x86/entry/syscalls/syscall_64.tbl (ABI stable,
// never renumbered on x86_64).
const (
	nr_seccomp               uintptr = 317
	nr_landlock_create_ruleset uintptr = 444
	nr_io_uring_setup        uintptr = 425
	nr_process_vm_readv      uintptr = 310
	nr_process_vm_writev     uintptr = 311
	nr_bpf                   uintptr = 321
)

// Reference sanity: assert these match the named constant where it DOES exist
// (SYS_PRCTL on amd64 is exposed with value 157; compare indirectly).
var _ = syscall.SYS_PRCTL
