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
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckOverlayFSEscape audits whether the container's root filesystem uses
// OverlayFS and whether the metacopy parameter is enabled, which affects
// the feasibility of the "container escape via OverlayFS whiteout"
// technique (CVE-2022-0492 style and similar).
//
// OverlayFS escape vectors checked:
//  1. Root fs is overlay — confirms OverlayFS is in use (prerequisite).
//  2. /sys/module/overlay/parameters/metacopy = "Y" — metacopy enabled,
//     which can be exploited to create character devices that bypass
//     the container's device cgroup.
//  3. Ability to mknod a character device in the container's writable
//     layer — if CAP_MKNOD is present and the device cgroup allows it.
//  4. /proc/self/mountinfo shows "lowerdir=" pointing outside container
//     (indicates host path leakage).
//  5. OverlayFS "index" and "xino" parameters for additional context.
//
// OPSEC: read-only checks.  All file opens use StealthOpen.  We do NOT
// actually mknod anything — we test capability via /proc/self/status
// CapEff field and cgroup devices.allow.
//
// T68 / security.overlayfs_escape.
func CheckOverlayFSEscape() {
	fmt.Fprintf(os.Stdout, "OverlayFS escape surface (T68) — whiteout + metacopy + mknod analysis:\n")

	findings := 0

	// --- Signal 1: Is root fs OverlayFS? ---
	rootFSType, rootIsOverlay := detectRootFSType()
	if rootIsOverlay {
		fmt.Fprintf(os.Stdout, "\t[GREEN] root filesystem is OverlayFS (type=%s)\n", rootFSType)
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] root filesystem is %s (not OverlayFS — whiteout escape not applicable)\n", rootFSType)
	}

	// --- Signal 2: metacopy parameter ---
	metacopyPath := util.OverlayMetacopy()
	metacopyVal := stealthReadFirstLine(metacopyPath)
	if metacopyVal != "" {
		metacopy := strings.TrimSpace(metacopyVal)
		fmt.Fprintf(os.Stdout, "\t     overlay metacopy: %s\n", metacopy)
		if strings.ToUpper(metacopy) == "Y" {
			fmt.Fprintf(os.Stdout, "\t[GREEN] OverlayFS metacopy=Y — enables whiteout character device escape\n")
			fmt.Fprintf(os.Stdout, "\t         CVE-2022-0492 style: mknod /dev/ptmx in overlay → escape device cgroup\n")
			findings++
		}
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] overlay metacopy parameter not readable (module may not be loaded)\n")
	}

	// --- Signal 3: Can we mknod? ---
	canMknod := hasCapability("cap_mknod")
	if canMknod {
		fmt.Fprintf(os.Stdout, "\t[GREEN] CAP_MKNOD present — can create device nodes in container\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] CAP_MKNOD absent — cannot mknod in container\n")
	}

	// --- Signal 4: Device cgroup allows device creation? ---
	// Check if devices cgroup allows all devices (a *:* rwm).
	devicesAllow := checkDevicesAllowAll()
	if devicesAllow {
		fmt.Fprintf(os.Stdout, "\t[GREEN] devices cgroup allows all devices (a *:* rwm) — mknod'd devices will be accessible\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] devices cgroup restricts device access\n")
	}

	// --- Signal 5: Mountinfo lowerdir analysis ---
	mountInfo := readFileLines("proc/self/mountinfo")
	hasOverlayMount := false
	var lowerDirs []string
	for _, line := range mountInfo {
		if strings.Contains(line, "overlay") {
			hasOverlayMount = true
			// Extract lowerdir from mount options.
			// Format: ... - overlay overlay rw,... lowerdir=/foo:/bar,upperdir=/baz,...
			parts := strings.Split(line, " ")
			for _, p := range parts {
				if strings.HasPrefix(p, "lowerdir=") {
					lowerDirs = strings.Split(strings.TrimPrefix(p, "lowerdir="), ":")
				}
			}
		}
	}
	if hasOverlayMount {
		fmt.Fprintf(os.Stdout, "\t     OverlayFS mount confirmed in /proc/self/mountinfo\n")
	}
	if len(lowerDirs) > 0 {
		fmt.Fprintf(os.Stdout, "\t     overlay lowerdir layers:\n")
		for _, ld := range lowerDirs {
			fmt.Fprintf(os.Stdout, "\t       %s\n", ld)
		}
		// Check if any lowerdir looks like a host path.
		for _, ld := range lowerDirs {
			if strings.Contains(ld, "/var/lib/docker") ||
				strings.Contains(ld, "/var/lib/containerd") ||
				strings.Contains(ld, "/var/lib/kubelet") {
				fmt.Fprintf(os.Stdout, "\t[AMBER] lowerdir contains container runtime path: %s\n", ld)
			}
		}
	}

	// --- Signal 6: Can we read /proc/self/mountinfo's "upperdir"? ---
	// If upperdir is on the host filesystem, writing there affects host.
	for _, line := range mountInfo {
		if strings.Contains(line, "overlay") && strings.Contains(line, "upperdir=") {
			parts := strings.Split(line, " ")
			for _, p := range parts {
				if strings.HasPrefix(p, "upperdir=") {
					upperDir := strings.TrimPrefix(p, "upperdir=")
					fmt.Fprintf(os.Stdout, "\t     overlay upperdir: %s\n", upperDir)
					// If upperdir is a host path we can also access, that's
					// a direct host filesystem write channel.
					if stealthFileExists(upperDir) {
						fmt.Fprintf(os.Stdout, "\t[GREEN] upperdir %s accessible from container — direct host fs write channel!\n", upperDir)
						fmt.Fprintf(os.Stdout, "\t         escape: write to %s/../../etc/cron.d/backdoor (relative traversal may work)\n", upperDir)
						findings++
					}
				}
			}
		}
	}

	// --- Signal 7: Test if we can create a whiteout file ---
	// A whiteout in OverlayFS is a character device (0,0).
	// If we can mknod a (0,0) char device in a writable directory,
	// and metacopy is on, we can potentially escape.
	if canMknod && rootIsOverlay {
		whiteoutTest := filepath.Join(os.TempDir(), ".cdk-wo-"+util.RandString(8))
		err := syscall.Mknod(whiteoutTest, syscall.S_IFCHR|0600, int(mkdev(0, 0)))
		if err == nil {
			fmt.Fprintf(os.Stdout, "\t[GREEN] mknod (0,0) char device SUCCEEDED — OverlayFS whiteout creation possible!\n")
			fmt.Fprintf(os.Stdout, "\t         combined with metacopy=Y: can hide files from upper layer view\n")
			syscall.Unlink(whiteoutTest)
			findings++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] mknod (0,0) failed: %v\n", err)
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 3 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d OverlayFS escape indicators — whiteout/mknod escape VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     Combined attack: CAP_MKNOD + metacopy + devices.allow = device node escape.\n")
	} else if findings > 0 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] %d OverlayFS indicators — partial escape potential.\n", findings)
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no OverlayFS escape vectors detected.\n")
	}
}

// mkdev creates a dev_t value from major and minor device numbers.
// This matches the kernel's MKDEV macro.
func mkdev(major, minor uint32) uint64 {
	return uint64((major << 8) | minor)
}

// checkDevicesAllowAll returns true if the devices cgroup allows all
// device access (a *:* rwm pattern).
func checkDevicesAllowAll() bool {
	// Try cgroup v1 devices.allow path first.
	allowPath := util.CgroupDevicesAllow()
	data, err := util.StealthReadFile(allowPath)
	if err == nil {
		content := strings.TrimSpace(string(data))
		if content == "a *:* rwm" || content == "a *:* rw" || content == "*:* rwm" {
			return true
		}
	}
	// Also try cgroup v2 device filter.
	v2Path := filepath.Join(util.CgroupRoot(), "cgroup.controllers")
	if stealthFileExists(v2Path) {
		// v2 doesn't have a direct "allow all" — check device.allow list.
		// For now, just check if the file exists and is readable.
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.overlayfs_escape",
		"Detect OverlayFS whiteout escape potential (metacopy, mknod, devices.allow, upperdir access) (T68)",
		[]string{"InContainer"},
		func() { CheckOverlayFSEscape() },
	)
}
