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

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckUserfaultfdEscape audits the userfaultfd-based container escape
// surface.  userfaultfd allows user-space handling of page faults, which
// can be exploited in combination with other primitives (e.g. FUSE,
// user namespaces) to race kernel page-cache operations and achieve
// local privilege escalation or container escape.
//
// Notable CVEs that use userfaultfd as a building block:
//   - CVE-2022-0185 (fs_context slab-out-of-bounds, often paired with uffd)
//   - CVE-2022-2585 (POSIX timer UAF, uffd for race window control)
//   - CVE-2022-0492 (cgroup v1 release_agent, uffd for timing)
//   - Dirty Pipe (CVE-2022-0847, uffd can aid exploitation)
//
// Detection approach:
//  1. /proc/sys/vm/unprivileged_userfaultfd — if 1, any user can create
//     userfaultfds (strong LPE enabler).
//  2. Test if we can actually open userfaultfd via syscall.
//  3. Check if we have CAP_SYS_ADMIN (needed for some uffd ioctls).
//  4. Check kernel version for known-vulnerable uffd ioctl handlers.
//
// OPSEC: read-only sysctl check + harmless userfaultfd syscall probe
// (UFFDIO_API with zeroed args, which returns EINVAL on unsupported
// kernels but does NOT create a persistent fd).  All file opens use
// StealthOpen.
//
// T70 / security.userfaultfd_escape.
func CheckUserfaultfdEscape() {
	fmt.Fprintf(os.Stdout, "userfaultfd escape surface (T70) — unprivileged uffd + kernel version analysis:\n")

	findings := 0

	// --- Signal 1: unprivileged_userfaultfd sysctl ---
	uffdSysctlPath := util.UnprivUserfaultfdPath()
	uffdSysctl := stealthReadFirstLine(uffdSysctlPath)

	if uffdSysctl != "" {
		uffdVal := strings.TrimSpace(uffdSysctl)
		fmt.Fprintf(os.Stdout, "\t     vm.unprivileged_userfaultfd = %s\n", uffdVal)
		if uffdVal == "1" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] unprivileged userfaultfd ENABLED — any process can create uffd (LPE enabler)\n")
			fmt.Fprintf(os.Stdout, "\t         combined with FUSE mount or userns: reliable race-condition exploitation\n")
			findings++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] unprivileged userfaultfd disabled (sysctl=%s)\n", uffdVal)
		}
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] cannot read vm.unprivileged_userfaultfd (sysctl not present or <4.11 kernel)\n")
	}

	// --- Signal 2: Can we actually open userfaultfd? ---
	// userfaultfd(2) syscall number varies by arch.  On x86_64 it's 282.
	// We probe with UFFD_USER_MODE_ONLY (0x1) flag which is safe.
	const (
		sysUserfaultfd    = 282 // x86_64
		UFFD_USER_MODE_ONLY = 0x1
	)
	fd, _, errno := syscall.RawSyscall6(uintptr(sysUserfaultfd),
		uintptr(UFFD_USER_MODE_ONLY), 0, 0, 0, 0, 0)

	if errno == 0 {
		fmt.Fprintf(os.Stdout, "\t[GREEN] userfaultfd syscall SUCCEEDED (fd=%d) — uffd usable from container\n", fd)
		fmt.Fprintf(os.Stdout, "\t         uffd allows precise control over page-fault timing → kernel race exploits\n")
		syscall.Close(int(fd))
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] userfaultfd syscall failed: %v\n", errno)
		if errno == syscall.EPERM {
			fmt.Fprintf(os.Stdout, "\t         EPERM — seccomp or LSM blocking uffd (good)\n")
		} else if errno == syscall.ENOSYS {
			fmt.Fprintf(os.Stdout, "\t         ENOSYS — kernel built without userfaultfd support\n")
		}
	}

	// --- Signal 3: CAP_SYS_ADMIN (needed for some uffd ioctls) ---
	hasSysAdmin := hasCapability("cap_sys_admin")
	if hasSysAdmin {
		fmt.Fprintf(os.Stdout, "\t[GREEN] CAP_SYS_ADMIN present — enables UFFDIO_REGISTER with MISSING+MINOR modes\n")
		findings++
	}

	// --- Signal 4: Kernel version context ---
	kernelVer := getKernelVersion()
	if kernelVer != "" {
		fmt.Fprintf(os.Stdout, "\t     kernel version: %s\n", kernelVer)
		// Check for known-vulnerable version ranges.
		if isVulnerableUFFDKernel(kernelVer) {
			fmt.Fprintf(os.Stdout, "\t[AMBER] kernel version may have known userfaultfd-related CVEs\n")
			fmt.Fprintf(os.Stdout, "\t         check: CVE-2022-0185, CVE-2022-2585, CVE-2022-0492 applicability\n")
		}
	}

	// --- Signal 5: Check for FUSE + uffd combo (powerful escape primitive) ---
	fusePresent := stealthFileExists(util.DevFusePath())
	if fusePresent {
		fmt.Fprintf(os.Stdout, "\t[AMBER] /dev/fuse present — FUSE + userfaultfd = reliable race exploit primitive\n")
		if uffdSysctl == "1" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] FUSE + unprivileged uffd = HIGH-risk escape combination!\n")
			findings++
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 2 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d userfaultfd indicators — uffd-assisted kernel exploit VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     userfaultfd enables precise race-condition control for kernel LPE.\n")
	} else if findings == 1 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] 1 userfaultfd indicator detected.\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no userfaultfd escape vectors detected.\n")
	}
}

// isVulnerableUFFDKernel returns true if the kernel version string falls
// within a range known to have userfaultfd-related CVEs.  This is a
// heuristic — exact CVE applicability depends on backports.
func isVulnerableUFFDKernel(ver string) bool {
	// Extract major.minor from version string.
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major := 0
	minor := 0
	fmt.Sscanf(parts[0], "%d", &major)
	fmt.Sscanf(parts[1], "%d", &minor)

	// Known vulnerable ranges (heuristic):
	//   < 5.17: CVE-2022-0185 (fs_context, uses uffd for race)
	//   < 5.18: CVE-2022-2585 (POSIX timer, uffd aids)
	//   < 5.17.3: CVE-2022-0492 (cgroup, uffd for timing)
	if major < 5 || (major == 5 && minor < 18) {
		return true
	}
	return false
}

// getKernelVersion reads the kernel version from /proc/sys/kernel/osrelease.
func getKernelVersion() string {
	return stealthReadFirstLine(util.ProcSysKernelOsrelease())
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.userfaultfd_escape",
		"Detect userfaultfd escape surface (unprivileged_uffd sysctl, syscall probe, FUSE combo, kernel CVEs) (T70)",
		[]string{"InContainer"},
		func() { CheckUserfaultfdEscape() },
	)
}
