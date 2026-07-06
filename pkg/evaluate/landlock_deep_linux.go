//go:build linux
// +build linux

/*
Copyright 2022 The Authors of https://github.com/CDK-TEAM/CDK .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package evaluate

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cdk-team/CDK/pkg/util"
)

// T47: security.landlock_deep — probe Landlock ABI version + per-process
// Landlocked bit + feature implications.
//
// Unlike lsm_enumerate's crude loaded/active boolean (Landlock is always
// "loaded" if compiled in regardless of whether THIS process is confined),
// this check answers the attacker question: "is the container I'm in
// actually confined by a Landlock ruleset, and which escape paths does it
// close?"
//
// Landlock ABIs (from linux/landlock.h and kernel documentation):
//   ABI 1 (5.13):  exec + truncate + FS basic ops
//   ABI 2 (5.19):  + ioctl on block devices (blocks /dev/sda rw primitive)
//   ABI 3 (6.2):   + TCP bind() restriction (blocks bind-to-privileged-port
//                   primitive used in container→host service squat attacks)
//   ABI 4 (6.7):   + mount tree / refer link (blocks overlay-style escape)
//
// Probes (read-only, zero side-effects):
//   1. landlock_create_ruleset(0, 0, LANDLOCK_CREATE_RULESET_VERSION)
//      → returns ABI version if available; ENOSYS if not compiled in.
//      (op = 1, flags=0, version request uses attr=NULL, size=0)
//   2. Read /proc/self/status "Landlocked:" field (exists since 5.19).
//      "1" = current process is restricted by a ruleset.
//      "0" or absent = no ruleset applied to THIS process.

const (
	// landlock_create_ruleset(2) operation values (linux/landlock.h):
	LANDLOCK_CREATE_RULESET_VERSION_OP = 1 // op number for syscall
)

// Landlock ABI → blocked primitive table.
type landlockABI struct {
	Version    int
	MinKernel  string
	BlockedOps []string
}

var landlockABIs = []landlockABI{
	{1, "5.13", []string{
		"FS exec/truncate",
		"directory read/write/list",
		"file basic rwx",
	}},
	{2, "5.19", []string{
		"ioctl on block devices (→ /dev/sda raw rw primitive)",
	}},
	{3, "6.2", []string{
		"TCP bind() (→ privileged-port squat escape vector)",
	}},
	{4, "6.7", []string{
		"mount tree changes + refer links (→ overlay-style escape)",
	}},
}

func landlockOut() *os.File { return os.Stdout }

// landlock_create_ruleset wraps the NR.  Returns ABI version, errno.
func landlockCreateRuleset(attr unsafe.Pointer, size uintptr, flags uint32) (int, syscall.Errno) {
	// syscall layout: (NR, op, attr_ptr, attr_size, flags, 0, 0, 0)
	// Per Linux landlock_create_ruleset(2) — arguments:
	//   ruleset_attr, size, flags  → but underlying uses 7-arg syscall layout
	//   for extended ops.  The LANDLOCK_CREATE_RULESET_VERSION operation (1)
	//   ignores attr_ptr/size, so we pass NULL/0.
	r1, _, errno := syscall.RawSyscall6(
		nr_landlock_create_ruleset,
		uintptr(LANDLOCK_CREATE_RULESET_VERSION_OP),
		uintptr(attr),
		size,
		uintptr(flags),
		0, 0,
	)
	return int(r1), errno
}

// ReadLandlockedBit returns 0/1 from /proc/self/status:Landlocked.
// Returns -1 if field absent (kernel < 5.19 or field not compiled in).
func readLandlockedBit() int {
	data, err := util.StealthReadFile(util.ProcSelfStatusPath())
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Landlocked:") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == "1" {
				return 1
			}
			return 0
		}
	}
	return -1
}

// ProbeLandlockDeep implements T47.
func ProbeLandlockDeep() {
	fmt.Fprintln(landlockOut(), "security.landlock_deep — Landlock ABI version + per-process Landlocked status:")

	// Probe 1: version via landlock_create_ruleset(op=VERSION).
	abiVer, errno := landlockCreateRuleset(nil, 0, 0)
	switch {
	case errno == 0:
		fmt.Fprintf(landlockOut(), "\t[GREEN] landlock_create_ruleset available — kernel reports ABI=%d (supports %s)\n",
			abiVer, kernelMinForABI(abiVer))
	case errno == syscall.ENOSYS:
		fmt.Fprintln(landlockOut(), "\t[  ?  ] landlock_create_ruleset = ENOSYS — kernel < 5.13 or CONFIG_SECURITY_LANDLOCK=n")
		fmt.Fprintln(landlockOut(), "\t  Verdict: AMBIGUOUS (kernel too old to probe; Landlock not an active gate)")
		return
	case errno == syscall.EOPNOTSUPP:
		fmt.Fprintln(landlockOut(), "\t[  ?  ] landlock_create_ruleset = EOPNOTSUPP (kernel supports Landlock but LSM disabled at boot)")
		// LSM compiled in but not in lsm= boot param: still effectively NOT a gate for this process
		fmt.Fprintln(landlockOut(), "\t  Verdict: NOT confined by Landlock (compiled in but disabled at boot)")
		return
	default:
		fmt.Fprintf(landlockOut(), "\t[  ?  ] landlock_create_ruleset unexpected errno=%v\n", errno)
		fmt.Fprintln(landlockOut(), "\t  Verdict: AMBIGUOUS")
		return
	}

	// Probe 2: Landlocked bit in /proc/self/status
	landlockedBit := readLandlockedBit()
	switch landlockedBit {
	case -1:
		fmt.Fprintln(landlockOut(), "\t[  ?  ] /proc/self/status:Landlocked absent (kernel < 5.19)")
	case 0:
		fmt.Fprintln(landlockOut(), "\t[GREEN] /proc/self/status:Landlocked = 0 — THIS process is NOT confined by Landlock")
	case 1:
		fmt.Fprintln(landlockOut(), "\t[AMBER] /proc/self/status:Landlocked = 1 — process confined by a Landlock ruleset")
	}

	// ABI→feature breakdown
	fmt.Fprintln(landlockOut(), "\t  ABI→blocked-escape-primitive map:")
	for _, a := range landlockABIs {
		present := ""
		if abiVer >= a.Version {
			present = " [SUPPORTED]"
		} else {
			present = " (kernel below ABI)"
		}
		for _, blocked := range a.BlockedOps {
			colour := "  ?  "
			if abiVer >= a.Version && landlockedBit == 1 {
				colour = "AMBER"
			} else if abiVer >= a.Version {
				colour = "GREEN" // supported by kernel but not applied to THIS process
			}
			fmt.Fprintf(landlockOut(), "\t\t[%s] ABI %d (≥%s): blocks %s%s\n",
				colour, a.Version, a.MinKernel, blocked, present)
		}
	}

	// Verdicts — strictly by 宁漏勿 flag (only make ISOLATED call when BOTH signals agree):
	fmt.Fprint(landlockOut(), "\t  Verdict: ")
	switch {
	case abiVer >= 3 && landlockedBit == 1:
		fmt.Fprintln(landlockOut(), "ISOLATED by Landlock ABI≥3 + Landlocked=1.")
		fmt.Fprintln(landlockOut(), "\t            (bind + ioctl-bdev + FS primitives all gated)")
	case abiVer > 0 && landlockedBit == 1:
		fmt.Fprintln(landlockOut(), "PARTIALLY ISOLATED (Landlock applied; low ABI — check block table above)")
	case abiVer > 0 && landlockedBit == 0:
		fmt.Fprintln(landlockOut(), "NOT confined by Landlock (ABI available but THIS process has no ruleset applied).")
		fmt.Fprintln(landlockOut(), "\t            Container runtime did not enforce a ruleset.")
	case abiVer > 0 && landlockedBit == -1:
		fmt.Fprintln(landlockOut(), "AMBIGUOUS (Landlock compiled in; kernel < 5.19 — cannot read Landlocked bit reliably)")
	default:
		fmt.Fprintln(landlockOut(), "AMBIGUOUS (kernel missing Landlock support)")
	}
}

func kernelMinForABI(ver int) string {
	for _, a := range landlockABIs {
		if a.Version == ver {
			return "kernel ≥ " + a.MinKernel
		}
	}
	return fmt.Sprintf("kernel >=? (unknown ABI %d)", ver)
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.landlock_deep",
		"Probe Landlock ABI version (1-4) via syscall + /proc/self/status:Landlocked bit [F8]",
		[]string{"InContainer"},
		func() { ProbeLandlockDeep() },
	)
}
