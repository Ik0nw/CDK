//go:build !linux
// +build !linux

// Non-Linux fallback for security.selinux_deep (T53).
//
// On darwin / windows / wasm the selinuxfs + /proc/self/attr paths do
// not exist.  We register the check ID with a no-op body so the
// evaluate engine (profile resolution, prereq flag lookup, go vet on
// the host) works identically across platforms.  At runtime the check
// prints a single "N/A on non-Linux" line and returns — no file I/O,
// no false positives.

package evaluate

import (
	"fmt"
	"os"
)

func selinuxOut() *os.File { return os.Stdout }

// EnumerateSELinuxDeep is a no-op on non-Linux.
func EnumerateSELinuxDeep() {
	fmt.Fprintf(selinuxOut(), "security.selinux_deep — N/A on non-Linux platforms (SELinux is Linux-only).\n")
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.selinux_deep",
		"SELinux: current process context (container_t vs spc_t vs unconfined), enforce mode, policy version [F11]",
		[]string{"InContainer"},
		func() { EnumerateSELinuxDeep() },
	)
}
