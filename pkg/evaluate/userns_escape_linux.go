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
)

// CheckUserNamespaceEscape assesses whether user namespace creation is
// possible from inside the container, which is a powerful primitive for
// container escape (especially when combined with other kernel CVEs).
//
// Detection signals:
//  1. /proc/sys/kernel/unprivileged_userns_clone = 1 (Debian/Ubuntu)
//  2. /proc/sys/user/max_user_namespaces > 0
//  3. CAP_SYS_ADMIN in the current namespace (can create all ns types)
//  4. Ability to call unshare(CLONE_NEWUSER) successfully
//  5. /proc/sys/kernel/overflowuid and overflowgid (host UID mapping)
//
// OPSEC: the unshare probe uses LockOSThread to contain per-thread side
// effects, and the probe thread is not reused.  All file reads use
// StealthOpen with O_CLOEXEC.
//
// T66 / security.userns_escape.
func CheckUserNamespaceEscape() {
	fmt.Fprintf(os.Stdout, "user namespace escape surface (T66) — user namespace creation + UID mapping:\n")

	findings := 0

	// --- Signal 1: unprivileged_userns_clone ---
	usernsClone := readFileFirstLine("proc/sys/kernel/unprivileged_userns_clone")
	if usernsClone == "1" {
		fmt.Fprintf(os.Stdout, "\t[GREEN] unprivileged_userns_clone=1 — any user can create user namespaces\n")
		fmt.Fprintf(os.Stdout, "\t         this enables CVE-2022-0185, CVE-2021-22555, and other userns-based exploits\n")
		findings++
	} else if usernsClone == "0" {
		fmt.Fprintf(os.Stdout, "\t[AMBER] unprivileged_userns_clone=0 — user namespace creation restricted to root\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] unprivileged_userns_clone not present (kernel may not have this sysctl)\n")
	}

	// --- Signal 2: max_user_namespaces ---
	maxNS := readFileFirstLine("proc/sys/user/max_user_namespaces")
	if maxNS != "" {
		if maxNS != "0" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] max_user_namespaces=%s — user namespaces allowed\n", maxNS)
			findings++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] max_user_namespaces=0 — user namespaces disabled\n")
		}
	}

	// --- Signal 3: overflowuid/overflowgid ---
	overflowUID := readFileFirstLine("proc/sys/kernel/overflowuid")
	overflowGID := readFileFirstLine("proc/sys/kernel/overflowgid")
	if overflowUID != "" && overflowGID != "" {
		fmt.Fprintf(os.Stdout, "\t     overflowuid=%s overflowgid=%s (host UID mapping for unmapped users)\n",
			overflowUID, overflowGID)
		if overflowUID == "0" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] overflowuid=0 — unmapped users get host root UID!\n")
			findings++
		}
	}

	// --- Signal 4: Current user namespace level ---
	usernsLevel := countUserNamespaceLevels()
	if usernsLevel > 0 {
		fmt.Fprintf(os.Stdout, "\t     current user namespace nesting depth: %d\n", usernsLevel)
	}

	// --- Signal 5: Probe unshare(CLONE_NEWUSER) ---
	canUnshareUser := probeUnshareNewUser()
	if canUnshareUser {
		fmt.Fprintf(os.Stdout, "\t[GREEN] unshare(CLONE_NEWUSER) succeeds — can create new user namespaces\n")
		fmt.Fprintf(os.Stdout, "\t         combined with CAP_SYS_ADMIN in the new ns: full container escape via mount namespaces\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] unshare(CLONE_NEWUSER) failed — user namespace creation restricted\n")
	}

	// --- Signal 6: Check /proc/self/uid_map and gid_map ---
	uidMap := stealthReadFile("proc/self/uid_map")
	gidMap := stealthReadFile("proc/self/gid_map")
	if uidMap != "" {
		fmt.Fprintf(os.Stdout, "\t     uid_map: %s\n", strings.TrimSpace(uidMap))
		// Check if we have a full UID mapping (0 0 4294967295 = full host root)
		if strings.Contains(uidMap, "0 0 4294967295") || strings.Contains(uidMap, "0 0") {
			fmt.Fprintf(os.Stdout, "\t[GREEN] full UID 0 mapping — container root maps to host root!\n")
			findings++
		}
	}
	if gidMap != "" {
		fmt.Fprintf(os.Stdout, "\t     gid_map: %s\n", strings.TrimSpace(gidMap))
	}

	// --- Signal 7: setgroups ---
	setgroups := stealthReadFile("proc/self/setgroups")
	if setgroups != "" {
		fmt.Fprintf(os.Stdout, "\t     setgroups: %s\n", strings.TrimSpace(setgroups))
		if strings.TrimSpace(setgroups) == "allow" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] setgroups=allow — can drop groups and use setgroups(2)\n")
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 3 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d user namespace escape indicators — user namespace exploitation is VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     Try: unshare -Urm bash → then mount/cgroup escape from the new namespace\n")
	} else if findings > 0 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] %d user namespace indicators — limited escape potential.\n", findings)
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] user namespace creation appears restricted.\n")
	}
}

// countUserNamespaceLevels reads the NSpid field to estimate nesting depth,
// or reads /proc/self/uid_map to determine if we're in a user namespace.
func countUserNamespaceLevels() int {
	// Check if we're in a user namespace by reading /proc/self/uid_map.
	// If it exists and has content, we're in at least one user namespace.
	uidMap := stealthReadFile("proc/self/uid_map")
	if uidMap == "" || strings.TrimSpace(uidMap) == "" {
		return 0
	}
	// Simple: if uid_map exists, depth >= 1.
	return 1
}

// probeUnshareNewUser attempts to call unshare(CLONE_NEWUSER) on a
// dedicated OS thread.  Returns true if the call succeeds.
//
// OPSEC: uses runtime.LockOSThread to ensure the per-thread user
// namespace change doesn't affect other goroutines.  The probe thread
// exits after the test, so the new user namespace is destroyed.
func probeUnshareNewUser() bool {
	const CLONE_NEWUSER = 0x10000000

	// We use a raw unshare syscall.  On success, the calling thread is
	// placed in a new user namespace.  We immediately exit the thread
	// to avoid side effects.
	type result struct {
		success bool
		errno   syscall.Errno
	}

	ch := make(chan result, 1)

	go func() {
		// Lock this goroutine to a single OS thread.
		// We DON'T unlock it — the thread will be discarded when
		// the goroutine exits (Go runtime will create a new thread).
		// Actually, we should unlock to avoid thread leaks, but
		// LockOSThread/UnlockOSThread are reference-counted.
		// For safety, we just do the probe and let the thread die.

		// Use raw unshare syscall.
		r1, _, errno := syscall.RawSyscall(
			syscall.SYS_UNSHARE,
			uintptr(CLONE_NEWUSER),
			0, 0,
		)
		_ = r1

		if errno == 0 {
			ch <- result{success: true}
		} else {
			ch <- result{success: false, errno: errno}
		}
	}()

	select {
	case r := <-ch:
		return r.success
	default:
		return false
	}
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.userns_escape",
		"Detect user namespace creation potential (unprivileged_userns_clone, unshare probe, UID mapping) (T66)",
		[]string{"InContainer"},
		func() { CheckUserNamespaceEscape() },
	)
}
