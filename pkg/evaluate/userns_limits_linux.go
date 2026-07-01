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
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// T50: system.userns_limits — user-namespace limits + current-userns level +
// UNPRIV_USERNS sysctl gates.
//
// Answers: "Am I already inside a user namespace (i.e., UID 0 in container
// maps to non-zero real UID on host)? How many levels deep? Are the
// unprivileged-userns gates on the host set to permissive values that
// let unprivileged processes build arbitrary USERNS+CLONE_NEWUSER stacks
// (CVE-2022-0492 / CVE-2022-0185 / CVE-2021-4154 family)?"
//
// Probes (all file reads — no syscalls, no side effects):
//   /proc/sys/kernel/unprivileged_userns_clone
//   /proc/sys/user/max_user_namespaces
//   /proc/self/{uid_map,gid_map,setgroups}
//   /proc/self/status:Uid / Gid / NStgid levels
//   /proc/sys/kernel/overflowuid / overflowgid
//   userns clone capability via setns() test? → skip (requires state change)

func usernsOut() *os.File { return os.Stdout }

func readInt(path string) int {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return v
}

// parseNLevels parses the "Uid:" or "Gid:" /proc/self/status line's four
// numeric fields and returns (real, effective, saved, fs).
// Additionally, the number of colon-separated groups in NStgid / NSpid
// indicates nesting depth.
func parseSpaceQuad(line string) []int {
	f := strings.Fields(line)
	out := []int{}
	for _, tok := range f[1:] {
		n, err := strconv.Atoi(tok)
		if err == nil {
			out = append(out, n)
		}
	}
	return out
}

func statusField(path, key string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, key+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+":"))
		}
	}
	return ""
}

// nsLevels counts depth in NStgid line (each space-separated number is one
// ancestor NS level).  Returns -1 if unreadable.
func nsLevels() int {
	field := statusField("/proc/self/status", "NStgid")
	if field == "" {
		return -1
	}
	return len(strings.Fields(field))
}

// firstLine returns first line of a file trimmed.
func firstLine(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.SplitN(string(data), "\n", 2)
	return strings.TrimSpace(lines[0])
}

// EnumerateUserNsLimits implements T50.
func EnumerateUserNsLimits() {
	fmt.Fprintln(usernsOut(), "system.userns_limits — user-namespace limits, nesting depth, UID mapping:")

	unprivClone := readInt("/proc/sys/kernel/unprivileged_userns_clone")
	maxNS := readInt("/proc/sys/user/max_user_namespaces")
	overflowUID := readInt("/proc/sys/kernel/overflowuid")
	overflowGID := readInt("/proc/sys/kernel/overflowgid")
	uidMap := firstLine("/proc/self/uid_map")
	gidMap := firstLine("/proc/self/gid_map")
	setgroups := firstLine("/proc/self/setgroups")
	depth := nsLevels()
	uidFields := parseSpaceQuad("Uid: " + statusField("/proc/self/status", "Uid"))
	gidFields := parseSpaceQuad("Gid: " + statusField("/proc/self/status", "Gid"))

	// --- Table 1: host-wide sysctl gates --------------------------------
	fmt.Fprintln(usernsOut(), "\tHost-wide user-namespace sysctl gates:")
	c1 := "  ?  "
	if unprivClone == 1 {
		c1 = "GREEN"
	} else if unprivClone == 0 {
		c1 = "AMBER"
	}
	note1 := ""
	switch unprivClone {
	case -1:
		note1 = "(file absent — kernel < 3.9 / !CONFIG_USER_NS or Debian/Ubuntu gate)"
	case 0:
		note1 = "DISABLED — unprivileged USERNS blocked (Debian patch default; blocks 2021-2022 userns LPEs)"
	case 1:
		note1 = "ENABLED — any user can CLONE_NEWUSER (major prerequisite for CVE-2022-0492/0185/4154 etc.)"
	}
	fmt.Fprintf(usernsOut(), "\t\t[%s] unprivileged_userns_clone   = %-3v  %s\n", c1, unprivClone, note1)

	c2 := "  ?  "
	switch {
	case maxNS > 0 && maxNS < 100:
		c2 = "AMBER"
	case maxNS >= 100:
		c2 = "GREEN"
	case maxNS == 0:
		c2 = "AMBER"
	case maxNS == -1:
		c2 = "  ?  "
	}
	note2 := ""
	switch maxNS {
	case -1:
		note2 = "(file unreadable)"
	case 0:
		note2 = "ZERO — user-ns creation fully blocked at user_ns sysctls (equivalent to unpriv=0)"
	default:
		note2 = fmt.Sprintf("(per-user USERNS cap — higher = easier to trigger exhaustion / exploit chaining)")
	}
	fmt.Fprintf(usernsOut(), "\t\t[%s] max_user_namespaces           = %-5v  %s\n", c2, maxNS, note2)

	// --- Table 2: inside-container mapping / depth ---------------------
	fmt.Fprintln(usernsOut(), "\tPer-process (inside-container) state:")
	// inside a real container, uid_map is usually "0 <host-uid> <range>"
	// not "0 0 4294967295" (host or unshifted)
	isShifted := false
	uidMapHasZeroEntry := false
	if uidMap != "" {
		// parse first line: "container_start host_start len"
		f := strings.Fields(uidMap)
		if len(f) >= 3 && f[0] == "0" && f[1] != "0" {
			isShifted = true
		}
		if len(f) >= 3 && f[0] == "0" {
			uidMapHasZeroEntry = true
		}
	}
	fmt.Fprintf(usernsOut(), "\t\tuid_map = %s\n", nonEmpty(uidMap))
	fmt.Fprintf(usernsOut(), "\t\tgid_map = %s\n", nonEmpty(gidMap))
	fmt.Fprintf(usernsOut(), "\t\tsetgroups = %s\n", nonEmpty(setgroups))
	if len(uidFields) >= 1 {
		fmt.Fprintf(usernsOut(), "\t\t/proc/self/status:Uid  = R:%d E:%d S:%d F:%d\n",
			atOrNeg(uidFields, 0), atOrNeg(uidFields, 1), atOrNeg(uidFields, 2), atOrNeg(uidFields, 3))
	}
	if len(gidFields) >= 1 {
		fmt.Fprintf(usernsOut(), "\t\t/proc/self/status:Gid  = R:%d E:%d S:%d F:%d\n",
			atOrNeg(gidFields, 0), atOrNeg(gidFields, 1), atOrNeg(gidFields, 2), atOrNeg(gidFields, 3))
	}

	// --- Table 3: verdicts ---------------------------------------------
	fmt.Fprintln(usernsOut(), "\tVerdicts:")
	// 1. Are we in a user namespace?
	colour := "  ?  "
	verdict := ""
	advice := ""
	switch {
	case !uidMapHasZeroEntry && depth > 1:
		colour = "GREEN"
		verdict = "IN USERNS (U0-host ≠ 0 & NStgid depth > 1)"
		advice = "UID 0 inside container maps to non-zero host uid — classic container userns setup."
	case isShifted:
		colour = "GREEN"
		verdict = "IN USERNS (uid_map shifted)"
		advice = "Container user-0 → host non-0; reduces kernel LPE impact but doesn't block userns-chaining exploits."
	case depth == 1 && isSameMap(uidMap):
		colour = "AMBER"
		verdict = "NOT in a user namespace (host-level identity)"
		advice = "Container ran with --userns=host (or equivalent) — full host UID 0 visible to kernel; severe escape risk."
	default:
		verdict = "AMBIGUOUS"
	}
	fmt.Fprintf(usernsOut(), "\t\t[%s] %s — %s\n", colour, verdict, advice)

	// 2. Nesting depth
	if depth > 1 {
		colour2 := "  ?  "
		switch {
		case depth >= 32:
			colour2 = "AMBER"
		case depth > 4:
			colour2 = "GREEN"
		default:
			colour2 = "  ?  "
		}
		fmt.Fprintf(usernsOut(), "\t\t[%s] NStgid depth = %d  (≤32 = normal; ≥32 = max depth approached)\n", colour2, depth)
	}

	// 3. overflow ids
	if overflowUID != -1 || overflowGID != -1 {
		fmt.Fprintf(usernsOut(), "\t\t[  ?  ] overflowuid=%d overflowgid=%d (host-level defaults for unmapped IDs)\n",
			atOrNeg2(overflowUID), atOrNeg2(overflowGID))
	}

	// 4. Summary attack-surface call
	fmt.Fprintln(usernsOut(), "\t  ---")
	switch {
	case unprivClone == 1 && maxNS > 0 && !isShifted:
		fmt.Fprintln(usernsOut(), "\t  [GREEN] HIGH PRIORITY: host allows unpriv userns clone AND container has HOST-level UID 0.")
		fmt.Fprintln(usernsOut(), "\t             Classic USERNS-based container LPE playbook (2021-2025) fully applicable.")
	case unprivClone == 1 && maxNS > 0:
		fmt.Fprintln(usernsOut(), "\t  [GREEN] MODERATE: host allows unpriv userns clone; container is UID-shifted.")
		fmt.Fprintln(usernsOut(), "\t             Still enables USERNS+chaining kernel LPEs — UID shift doesn't protect kernel.")
	case unprivClone == 0 || maxNS == 0:
		fmt.Fprintln(usernsOut(), "\t  [AMBER] LOW: host blocks unpriv userns clone.")
		fmt.Fprintln(usernsOut(), "\t             User-ns-based exploit paths are closed. Evaluate native kernel attack surface instead.")
	default:
		fmt.Fprintln(usernsOut(), "\t  [  ?  ] AMBIGUOUS: missing some gates — combine with capabilities and kernel_hardening check.")
	}
}

func nonEmpty(s string) string {
	if s == "" {
		return "(absent / unreadable)"
	}
	return s
}

func atOrNeg(a []int, i int) int {
	if i < len(a) {
		return a[i]
	}
	return -1
}

func atOrNeg2(v int) int {
	if v == -1 {
		return -1
	}
	return v
}

// isSameMap returns true when uid_map indicates "0 0 <full-range>" identity map.
func isSameMap(m string) bool {
	f := strings.Fields(m)
	return len(f) >= 3 && f[0] == f[1] && (f[2] == "4294967295" || f[2] == "65536")
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySystemInfo,
		"system.userns_limits",
		"user-namespace gates (unpriv clone / max_ns) + inside-container UID map + NStgid depth [F10]",
		[]string{"InContainer"},
		func() { EnumerateUserNsLimits() },
	)
}
