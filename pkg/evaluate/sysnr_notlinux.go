// +build !linux

package evaluate

// Non-Linux placeholder values.  These constants are never used on non-Linux
// targets — the *_linux.go call sites are build-tag gated.  Declarations here
// exist only so `go vet` / IDE tooling on darwin / windows does not complain
// about undefined identifiers inside the evaluate package.
const (
	nr_seccomp               uintptr = 0
	nr_landlock_create_ruleset uintptr = 0
	nr_io_uring_setup        uintptr = 0
	nr_process_vm_readv      uintptr = 0
	nr_process_vm_writev     uintptr = 0
	nr_bpf                   uintptr = 0
)
