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
	"path/filepath"
	"strings"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckRuncFdLeak audits for the runc file-descriptor leak class of
// container escapes, most notably CVE-2024-21626.
//
// CVE-2024-21626: runc's internal file descriptor for the host's
// /sys/fs/cgroup directory was leaked into the container process via
// /proc/self/fd/.  An attacker could open this fd, use fchdir() to
// escape the container's mount namespace, then access host files.
//
// Detection approach:
//  1. Enumerate /proc/self/fd and look for file descriptors that point
//     to paths OUTSIDE the container's expected namespaces (e.g. a fd
//     pointing to /sys/fs/cgroup on the host rather than the container's
//     cgroup namespace view).
//  2. Check if /proc/self/fd contains unexpected file descriptors that
//     reference host paths (e.g. /proc, /sys, /dev paths that should
//     not be accessible from the container's mount namespace).
//  3. Check runc version via /proc/self/exe readlink (the runc binary
//     path) and the container runtime socket.
//  4. Check if /proc/self/exe is writable (CVE-2019-5736 indicator).
//
// OPSEC: read-only checks.  All file opens use StealthOpen.  We do NOT
// actually open the leaked fd or attempt to use fchdir — we only read
// the /proc/self/fd symlink targets via readlinkat.
//
// T69 / security.runc_fd_leak.
func CheckRuncFdLeak() {
	fmt.Fprintf(os.Stdout, "runc fd leak escape (T69) — CVE-2024-21626 / CVE-2019-5736 detection:\n")

	findings := 0

	// --- Signal 1: Enumerate /proc/self/fd for leaked host FDs ---
	fdDir := util.ProcSelfFdPath()
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		fmt.Fprintf(os.Stdout, "\t[AMBER] cannot read %s: %v\n", fdDir, err)
	} else {
		suspiciousFDs := 0
		hostPathFDs := 0
		for _, entry := range entries {
			fdPath := filepath.Join(fdDir, entry.Name())
			// Use readlink to get the target.
			target, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}
			// Look for FDs that point to host paths outside the container.
			// Suspicious patterns:
			//   - /sys/fs/cgroup (host cgroupfs, not container's view)
			//   - /proc (if it's the HOST proc, not container's)
			//   - Paths that contain ".." traversal indicators
			//   - FDs pointing to device files we shouldn't have open
			if isHostLeakedFd(target) {
				suspiciousFDs++
				fmt.Fprintf(os.Stdout, "\t[GREEN] LEAKED FD %s → %s (host path visible from container!)\n",
					entry.Name(), target)
			}
			// Check for FDs pointing to absolute host paths.
			if strings.HasPrefix(target, "/sys/fs/cgroup") && !strings.Contains(target, "docker") && !strings.Contains(target, "containerd") {
				hostPathFDs++
			}
		}
		if suspiciousFDs > 0 {
			fmt.Fprintf(os.Stdout, "\t  ⚠  %d suspicious file descriptors found — possible CVE-2024-21626 fd leak!\n", suspiciousFDs)
			fmt.Fprintf(os.Stdout, "\t         escape: open leaked fd via /proc/self/fd/N, fchdir(fd) → host mount namespace\n")
			findings += suspiciousFDs
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] no leaked host file descriptors detected in /proc/self/fd\n")
		}
		if hostPathFDs > 0 && suspiciousFDs == 0 {
			fmt.Fprintf(os.Stdout, "\t[AMBER] %d cgroup-related FDs but no confirmed host path leak\n", hostPathFDs)
		}
	}

	// --- Signal 2: Check /proc/self/exe for CVE-2019-5736 ---
	selfExePath := util.ProcSelfExePath()
	// Try to readlink /proc/self/exe.
	exeTarget, err := os.Readlink(selfExePath)
	if err == nil {
		fmt.Fprintf(os.Stdout, "\t     /proc/self/exe → %s\n", exeTarget)
		// If it points to a runc binary path, that's expected.
		// The CVE-2019-5736 vector is being able to WRITE to /proc/self/exe.
	}

	// Test if /proc/self/exe is writable (CVE-2019-5736 indicator).
	// We don't actually write — we test O_RDWR open on the readlink target.
	if exeTarget != "" {
		exeWritable := stealthFileWritable(exeTarget)
		if exeWritable {
			fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/self/exe target (%s) is WRITABLE — CVE-2019-5736 may apply!\n", exeTarget)
			fmt.Fprintf(os.Stdout, "\t         escape: overwrite runc binary → next exec = host root\n")
			findings++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] /proc/self/exe target not writable\n")
		}
	}

	// --- Signal 3: Check runc version indicators ---
	// We can't easily get runc version from inside the container without
	// network access, but we can check the container runtime for known
	// vulnerable patterns.
	runcVersion := detectRuncVersion()
	if runcVersion != "" {
		fmt.Fprintf(os.Stdout, "\t     runc/runtime version indicator: %s\n", runcVersion)
	}

	// --- Signal 4: Check if we have unexpected access to /proc/1/root ---
	// If we can read /proc/1/root, that means we're in the host PID namespace
	// or the container has CAP_SYS_PTRACE / CAP_SYS_ADMIN.
	proc1Root := util.Proc1RootPath()
	if stealthFileExists(proc1Root) {
		// Try to stat a known host path via /proc/1/root.
		hostEtc := proc1Root + util.EtcShadowPath()
		if stealthFileExists(hostEtc) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/1/root accessible — can traverse to host filesystem via PID 1!\n")
			fmt.Fprintf(os.Stdout, "\t         escape: read /proc/1/root/etc/shadow for host credential theft\n")
			findings++
		}
	}

	// --- Signal 5: Check /proc/1/fd for leaked host FDs ---
	proc1Fd := util.Proc1FdPath()
	entries1, err := os.ReadDir(proc1Fd)
	if err == nil {
		for _, entry := range entries1 {
			fdPath := filepath.Join(proc1Fd, entry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}
			if isHostLeakedFd(target) {
				fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/1/fd/%s → %s (host fd visible via PID 1)\n",
					entry.Name(), target)
				findings++
			}
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 2 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d runc escape indicators — runc-level container escape VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     Check runc version and apply patches if vulnerable.\n")
	} else if findings == 1 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] 1 runc escape indicator detected.\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no runc fd leak indicators detected.\n")
	}
}

// isHostLeakedFd returns true if the readlink target of a /proc/*/fd/N
// entry looks like a leaked host file descriptor (points to a host path
// that shouldn't be accessible from inside the container).
func isHostLeakedFd(target string) bool {
	// Paths that indicate host fd leak:
	//   - /sys/fs/cgroup without container suffix (raw host cgroupfs)
	//   - /proc/1/root style paths
	//   - /dev/ paths that are host block devices
	//   - pipe:[...] with host-side indicators
	//   - anon_inode:[eventpoll] or similar kernel internal fds
	//     that shouldn't be visible (these are normal though)

	// Check for raw host cgroup fd.
	cgroupRoot := util.CgroupRoot()
	if target == cgroupRoot || target == cgroupRoot+"/" {
		return true
	}
	// Check for /proc/1/root traversal.
	if strings.HasPrefix(target, util.Proc1RootPath()) {
		return true
	}
	// Check for host block device fds.
	hostBlockDevs := []string{
		util.DevSdaPath(), util.DevSdbPath(), util.DevSdcPath(),
		util.DevVdaPath(), util.DevVdbPath(),
		util.DevNvme0n1Path(), util.DevNvme1n1Path(),
		util.DevXvdaPath(), util.DevXvdbPath(),
	}
	for _, dev := range hostBlockDevs {
		if target == dev {
			return true
		}
	}
	return false
}

// detectRuncVersion attempts to determine the runc version by reading
// various indicators available inside the container.
func detectRuncVersion() string {
	// Method 1: Check /proc/self/exe readlink target for version hints.
	selfExe := util.ProcSelfExePath()
	if target, err := os.Readlink(selfExe); err == nil {
		return target
	}
	// Method 2: Check container runtime socket for version info.
	// (This would require network access — skip for now.)
	return ""
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.runc_fd_leak",
		"Detect runc fd leak (CVE-2024-21626) and /proc/self/exe writable (CVE-2019-5736) (T69)",
		[]string{"InContainer"},
		func() { CheckRuncFdLeak() },
	)
}
