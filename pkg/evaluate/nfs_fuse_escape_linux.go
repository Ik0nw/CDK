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

// CheckNFSMountEscape audits NFS mounts inside the container for the
// no_root_squash misconfiguration, which allows container root to write
// files as root on the NFS server — enabling escape if the NFS export
// is also mounted on the host.
//
// Also audits FUSE mounts: if /dev/fuse is accessible and we have
// CAP_SYS_ADMIN, we can mount a FUSE filesystem that intercepts host
// file accesses.
//
// OPSEC: read-only audit.  We parse mountinfo for NFS entries and check
// /dev/fuse accessibility.  No mounts are performed, no FUSE daemons
// are started.
//
// T61 / mounts.nfs_fuse_escape.
func CheckNFSMountEscape() {
	fmt.Fprintf(os.Stdout, "NFS/FUSE mount escape audit (T61):\n")

	// --- NFS no_root_squash detection ---
	nfsMounts := findNFSMounts()
	if len(nfsMounts) > 0 {
		fmt.Fprintf(os.Stdout, "\tNFS mounts detected:\n")
		for _, m := range nfsMounts {
			fmt.Fprintf(os.Stdout, "\t  %s (server: %s, opts: %s)\n",
				m.MountPoint, m.Source, strings.Join(m.Opts, ","))

			// Test if we can write as root — this would indicate
			// no_root_squash on the server side.
			testFile := m.MountPoint + "/.cdk-nfs-probe-" + util.RandString(6)
			fd, err := util.StealthOpen(testFile,
				syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
			if err == nil {
				util.StealthClose(fd)
				syscall.Unlink(testFile)
				fmt.Fprintf(os.Stdout, "\t    [GREEN] root write succeeded — no_root_squash likely active!\n")
				fmt.Fprintf(os.Stdout, "\t            escape: plant SUID binary → host root exec if host also mounts this share\n")
			} else {
				fmt.Fprintf(os.Stdout, "\t    [AMBER] root write failed (root_squash active or read-only): %v\n", err)
			}
		}
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] no NFS mounts detected.\n")
	}

	// --- FUSE escape surface ---
	fmt.Fprintf(os.Stdout, "\n\tFUSE escape surface:\n")

	fuseAccessible := false
	fd, err := util.StealthOpen(util.DevFusePath(), syscall.O_RDWR)
	if err == nil {
		util.StealthClose(fd)
		fuseAccessible = true
	}

	// Also check if FUSE is loaded.
	fuseLoaded := false
	if lines := readFileLines("proc/filesystems"); lines != nil {
		for _, l := range lines {
			if strings.Contains(l, "fuse") {
				fuseLoaded = true
				break
			}
		}
	}

	// Check for fusectl (indicates FUSE is in use).
	fusectlMounted := false
	if lines := readFileLines("proc/self/mountinfo"); lines != nil {
		for _, l := range lines {
			if strings.Contains(l, "fusectl") {
				fusectlMounted = true
				break
			}
		}
	}

	switch {
	case fuseAccessible:
		fmt.Fprintf(os.Stdout, "\t  [GREEN] /dev/fuse is read-write accessible — FUSE mount possible\n")
		fmt.Fprintf(os.Stdout, "\t          escape: mount FUSE fs → intercept host file reads via mount namespace\n")
		if fuseLoaded {
			fmt.Fprintf(os.Stdout, "\t          (fuse module loaded in /proc/filesystems)\n")
		}
	case fusectlMounted:
		fmt.Fprintf(os.Stdout, "\t  [AMBER] fusectl mounted but /dev/fuse not writable — FUSE in use but not mountable\n")
	default:
		fmt.Fprintf(os.Stdout, "\t  [AMBER] /dev/fuse not accessible — FUSE escape surface: CLOSED\n")
	}

	// --- 9p / virtio-fs mounts (common in KVM/Firecracker) ---
	fmt.Fprintf(os.Stdout, "\n\t9p/virtio-fs mounts:\n")
	virtioMounts := find9pMounts()
	if len(virtioMounts) > 0 {
		for _, m := range virtioMounts {
			fmt.Fprintf(os.Stdout, "\t  [AMBER] %s (9p/virtio-fs, source: %s)\n",
				m.MountPoint, m.Source)
			fmt.Fprintf(os.Stdout, "\t          9p mounts bypass container filesystem isolation — check for writable host paths\n")
		}
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no 9p/virtio-fs mounts detected.\n")
	}
}

// nfsMountInfo holds parsed info about an NFS mount.
type nfsMountInfo struct {
	MountPoint string
	Source     string
	Opts       []string
}

// findNFSMounts returns all NFS (nfs, nfs4) mounts from mountinfo.
func findNFSMounts() []nfsMountInfo {
	var result []nfsMountInfo
	lines := readFileLines("proc/self/mountinfo")
	for _, line := range lines {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 2 {
			continue
		}
		fstype := right[0]
		if fstype != "nfs" && fstype != "nfs4" {
			continue
		}
		mountPoint := left[4]
		source := ""
		if len(right) >= 2 {
			source = right[1]
		}
		opts := []string{}
		if len(right) >= 3 {
			opts = strings.Split(right[len(right)-1], ",")
		}
		result = append(result, nfsMountInfo{
			MountPoint: mountPoint,
			Source:     source,
			Opts:       opts,
		})
	}
	return result
}

// find9pMounts returns all 9p/virtio-fs mounts from mountinfo.
func find9pMounts() []nfsMountInfo {
	var result []nfsMountInfo
	lines := readFileLines("proc/self/mountinfo")
	for _, line := range lines {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 2 {
			continue
		}
		fstype := right[0]
		if fstype != "9p" && fstype != "virtiofs" {
			continue
		}
		mountPoint := left[4]
		source := ""
		if len(right) >= 2 {
			source = right[1]
		}
		opts := []string{}
		if len(right) >= 3 {
			opts = strings.Split(right[len(right)-1], ",")
		}
		result = append(result, nfsMountInfo{
			MountPoint: mountPoint,
			Source:     source,
			Opts:       opts,
		})
	}
	return result
}

func init() {
	RegisterSimplePrereqCheck(
		CategoryMounts,
		"mounts.nfs_fuse_escape",
		"Detect NFS no_root_squash, FUSE /dev/fuse accessibility, and 9p/virtio-fs mount escape surfaces (T61)",
		[]string{"InContainer"},
		func() { CheckNFSMountEscape() },
	)
}
