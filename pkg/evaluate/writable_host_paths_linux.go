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

// hostPathRisk describes a bind-mounted host path that, if writable from
// inside the container, enables a container escape via host-side code
// execution or credential theft.
type hostPathRisk struct {
	Path        string // path inside the container (may be a mount point)
	Name        string // short description
	Escalation  string // how to escalate if writable
	Severity    string // "critical" | "high" | "medium"
	HostPath    string // expected host-side path (for mountinfo correlation)
}

// dangerousHostPaths lists bind-mount targets that commonly appear in
// misconfigured containers and enable host takeover when writable.
//
// High-sensitivity paths are populated at init() time from obfuscated
// constants to avoid static .rodata string matching by HIDS/EDR.
var dangerousHostPaths []hostPathRisk

func init() {
	dangerousHostPaths = []hostPathRisk{
		// --- cron / scheduled execution ---
		{
			Path:       util.EtcCronDPath(),
			Name:       "host cron.d directory",
			Escalation: "write a cron job → host root executes it on schedule",
			Severity:   "critical",
			HostPath:   util.EtcCronDPath(),
		},
		{
			Path:       util.EtcCronDailyPath(),
			Name:       "host cron.daily directory",
			Escalation: "drop executable → runs daily as host root",
			Severity:   "critical",
			HostPath:   util.EtcCronDailyPath(),
		},
		{
			Path:       util.EtcCrontabPath(),
			Name:       "host crontab file",
			Escalation: "append cron entry → scheduled host root code exec",
			Severity:   "critical",
			HostPath:   util.EtcCrontabPath(),
		},
		{
			Path:       util.VarSpoolCronPath(),
			Name:       "host cron spool",
			Escalation: "write root crontab → scheduled host code exec",
			Severity:   "critical",
			HostPath:   util.VarSpoolCronPath(),
		},

		// --- dynamic linker / library injection ---
		{
			Path:       util.EtcLdSoPreloadPath(),
			Name:       "host ld.so.preload",
			Escalation: "inject shared library → every host process loads it (root RCE)",
			Severity:   "critical",
			HostPath:   util.EtcLdSoPreloadPath(),
		},
		{
			Path:       util.EtcLdSoConfDPath(),
			Name:       "host ld.so.conf.d directory",
			Escalation: "add library path config → host processes load attacker library",
			Severity:   "high",
			HostPath:   util.EtcLdSoConfDPath(),
		},

		// --- SSH / credential theft ---
		{
			Path:       util.RootSshPath(),
			Name:       "host root SSH directory",
			Escalation: "read id_rsa for host lateral movement; write authorized_keys for persistent access",
			Severity:   "critical",
			HostPath:   util.RootSshPath(),
		},
		{
			Path:       util.HomePath(),
			Name:       "host /home directory",
			Escalation: "read user SSH keys, bash_history, credentials; plant backdoors in ~/.bashrc",
			Severity:   "high",
			HostPath:   util.HomePath(),
		},
		{
			Path:       util.EtcShadowPath(),
			Name:       "host shadow password file",
			Escalation: "read password hashes → offline crack → host root access",
			Severity:   "critical",
			HostPath:   util.EtcShadowPath(),
		},
		{
			Path:       util.EtcPasswdPath(),
			Name:       "host passwd file",
			Escalation: "add UID 0 user → instant host root",
			Severity:   "critical",
			HostPath:   util.EtcPasswdPath(),
		},

		// --- systemd / init ---
		{
			Path:       util.EtcSystemdPath(),
			Name:       "host systemd unit directory",
			Escalation: "plant .service file → host root code exec on next boot or daemon-reload",
			Severity:   "critical",
			HostPath:   util.EtcSystemdPath(),
		},
		{
			Path:       util.LibSystemdSystemPath(),
			Name:       "host systemd lib unit directory",
			Escalation: "modify existing service → host root code exec",
			Severity:   "high",
			HostPath:   util.LibSystemdSystemPath(),
		},
		{
			Path:       util.EtcInitDPath(),
			Name:       "host init.d scripts",
			Escalation: "modify init script → host root code exec on service restart",
			Severity:   "high",
			HostPath:   util.EtcInitDPath(),
		},

		// --- container runtime ---
		{
			Path:       util.VarLibDockerPath(),
			Name:       "host Docker data directory",
			Escalation: "modify container configs, inject into image layers, read container secrets",
			Severity:   "critical",
			HostPath:   util.VarLibDockerPath(),
		},
		{
			Path:       util.VarLibContainerdPath(),
			Name:       "host containerd data directory",
			Escalation: "modify container specs, read image contents",
			Severity:   "high",
			HostPath:   util.VarLibContainerdPath(),
		},
		{
			Path:       util.VarLibKubeletPath(),
			Name:       "host kubelet data directory",
			Escalation: "read all pod service account tokens, modify pod specs",
			Severity:   "critical",
			HostPath:   util.VarLibKubeletPath(),
		},

		// --- PAM / authentication ---
		{
			Path:       util.EtcPamDPath(),
			Name:       "host PAM configuration",
			Escalation: "inject PAM module → capture all host credentials, backdoor auth",
			Severity:   "critical",
			HostPath:   util.EtcPamDPath(),
		},

		// --- profile.d / shell ---
		{
			Path:       util.EtcProfileDPath(),
			Name:       "host profile.d scripts",
			Escalation: "add script → runs when any user logs in (host root code exec)",
			Severity:   "high",
			HostPath:   util.EtcProfileDPath(),
		},
		{
			Path:       util.EtcBashrcPath(),
			Name:       "host global bashrc",
			Escalation: "inject code → runs when any user opens a shell",
			Severity:   "high",
			HostPath:   util.EtcBashrcPath(),
		},

		// --- Kubernetes ---
		{
			Path:       util.EtcKubernetesPath(),
			Name:       "host Kubernetes config directory",
			Escalation: "read admin kubeconfig, certificates → full cluster takeover",
			Severity:   "critical",
			HostPath:   util.EtcKubernetesPath(),
		},
	}
}

// CheckWritableHostPaths audits whether any host paths bind-mounted into the
// container are writable and provide an escape vector.
//
// The check:
//  1. Scans mountinfo for bind mounts from host paths that match our risk list.
//  2. For each mounted risk path, tests writability by attempting to open
//     the path with O_RDWR | O_CLOEXEC.
//  3. For directories, also tests whether we can create a temporary file.
//
// OPSEC: all opens use O_CLOEXEC.  We never actually write content — we
// only test open(O_RDWR) and for dirs, a single O_CREAT|O_EXCL that we
// immediately clean up.  This minimizes /proc/self/fd exposure and avoids
// creating persistent artifacts on the host.
//
// T60 / mounts.writable_host_paths.
func CheckWritableHostPaths() {
	fmt.Fprintf(os.Stdout, "writable host paths audit (T60) — bind-mounted host paths with escape potential:\n")

	// Build a set of mount points from mountinfo for correlation.
	mountMap := buildMountPointMap()

	found := 0
	for _, risk := range dangerousHostPaths {
		// Check if this path exists (it may be bind-mounted).
		fi, err := os.Stat(risk.Path)
		if err != nil {
			continue // not mounted / not present
		}

		// Check if it's actually a bind mount from the host.
		isBindMount := false
		if mp, ok := mountMap[risk.Path]; ok {
			// If the mount root matches our expected host path, it's a bind mount.
			if mp.Root == risk.HostPath || mp.Root == "/" {
				isBindMount = true
			}
			// Also check if it's a bind mount by filesystem type.
			if mp.Fstype == "" || mp.Fstype == "bind" {
				isBindMount = true
			}
		}

		// Test writability.
		writable := false
		writeMethod := ""

		if fi.IsDir() {
			// For directories: try to create a temp file.
			testFile := filepath.Join(risk.Path, ".cdk-writability-"+util.RandString(8))
			fd, err := util.StealthOpen(testFile,
				syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL)
			if err == nil {
				util.StealthClose(fd)
				syscall.Unlink(testFile)
				writable = true
				writeMethod = "directory writable (created+deleted temp file)"
			}
		} else {
			// For files: try O_RDWR open.
			fd, err := util.StealthOpen(risk.Path, syscall.O_RDWR)
			if err == nil {
				util.StealthClose(fd)
				writable = true
				writeMethod = "file writable (O_RDWR open succeeded)"
			}
		}

		// Also check readability (for credential theft even if not writable).
		readable := false
		if !writable {
			fd, err := util.StealthOpen(risk.Path, syscall.O_RDONLY)
			if err == nil {
				util.StealthClose(fd)
				readable = true
			}
		}

		if !writable && !readable {
			continue // exists but no access — skip
		}

		colour := "  ?  "
		severityTag := ""
		switch {
		case writable && risk.Severity == "critical":
			colour = "GREEN"
			severityTag = "CRITICAL"
		case writable && risk.Severity == "high":
			colour = "GREEN"
			severityTag = "HIGH"
		case writable:
			colour = "GREEN"
			severityTag = strings.ToUpper(risk.Severity)
		case readable:
			colour = "AMBER"
			severityTag = "READ-ONLY"
		}

		bindNote := ""
		if isBindMount {
			bindNote = " [bind-mounted from host]"
		}

		fmt.Fprintf(os.Stdout, "\t[%s] %-30s %s%s\n",
			colour, risk.Path, risk.Name, bindNote)
		if writable {
			fmt.Fprintf(os.Stdout, "\t         severity: %s — %s\n", severityTag, risk.Escalation)
			fmt.Fprintf(os.Stdout, "\t         method: %s\n", writeMethod)
		} else if readable {
			fmt.Fprintf(os.Stdout, "\t         readable only — credential theft possible (e.g. %s)\n", risk.Path)
		}

		found++
	}

	if found == 0 {
		fmt.Fprintf(os.Stdout, "\t[AMBER] no dangerous host paths with read/write access detected.\n")
		fmt.Fprintf(os.Stdout, "\t        (checked %d known-risk paths)\n", len(dangerousHostPaths))
	} else {
		fmt.Fprintf(os.Stdout, "\n\t  ⚠  %d dangerous host path(s) with access — bind-mount escape surface OPEN.\n", found)
	}

	// Also scan mountinfo for any unexpected writable bind mounts.
	suspiciousMounts := findSuspiciousWritableMounts()
	if len(suspiciousMounts) > 0 {
		fmt.Fprintf(os.Stdout, "\n\tadditional writable mounts worth investigating:\n")
		for _, sm := range suspiciousMounts {
			fmt.Fprintf(os.Stdout, "\t  %s\n", sm)
		}
	}
}

// mountPointInfo holds parsed mountinfo for a single mount point.
type mountPointInfo struct {
	Root    string
	Fstype  string
	Opts    []string
	MountSource string
}

// buildMountPointMap parses /proc/self/mountinfo and returns a map from
// mount point path to mount info.
func buildMountPointMap() map[string]mountPointInfo {
	result := make(map[string]mountPointInfo)
	lines := readFileLines("proc/self/mountinfo")
	for _, line := range lines {
		// mountinfo format:
		// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 2 {
			continue
		}
		mountPoint := left[4]
		mountRoot := left[3]
		fstype := right[0]
		// mount source is right[1] but may contain spaces...
		mountSource := ""
		if len(right) >= 2 {
			mountSource = right[1]
		}
		// Parse opts from the right side (last field).
		opts := []string{}
		if len(right) >= 3 {
			opts = strings.Split(right[len(right)-1], ",")
		}
		result[mountPoint] = mountPointInfo{
			Root:        mountRoot,
			Fstype:      fstype,
			Opts:        opts,
			MountSource: mountSource,
		}
	}
	return result
}

// findSuspiciousWritableMounts scans mountinfo for writable mounts from
// host paths that aren't in our known-dangerous list but are still suspicious.
func findSuspiciousWritableMounts() []string {
	mountMap := buildMountPointMap()
	var suspicious []string

	for mp, info := range mountMap {
		// Skip well-known safe mount points.
		if isSafeMountPoint(mp) {
			continue
		}
		// Check if it's writable.
		isRW := false
		for _, opt := range info.Opts {
			if opt == "rw" {
				isRW = true
				break
			}
		}
		if !isRW {
			continue
		}
		// Check if it's from a host path (not a tmpfs / proc / sys / devtmpfs).
		if info.Fstype == "proc" || info.Fstype == "sysfs" ||
			info.Fstype == "tmpfs" || info.Fstype == "devtmpfs" ||
			info.Fstype == "devpts" || info.Fstype == "cgroup" ||
			info.Fstype == "cgroup2" || info.Fstype == "overlay" ||
			info.Fstype == "aufs" {
			continue
		}
		// It's a writable non-virtual mount — suspicious.
		suspicious = append(suspicious, fmt.Sprintf(
			"%s (type=%s, source=%s, root=%s)",
			mp, info.Fstype, info.MountSource, info.Root))
	}
	return suspicious
}

// isSafeMountPoint returns true for well-known safe container mount points.
func isSafeMountPoint(mp string) bool {
	safePrefixes := []string{
		util.ProcPath(), util.SysPath(), util.DevPath(), util.RunSecretsPath(),
		util.VarRunSecretsPath(), util.EtcHostsPath(), util.EtcHostnamePath(),
		util.EtcResolvConfPath(),
	}
	for _, p := range safePrefixes {
		if mp == p || strings.HasPrefix(mp, p+"/") {
			return true
		}
	}
	if mp == "/" || mp == util.TmpPath() || mp == util.DevShmPath() ||
		mp == util.DevMqueuePath() || mp == util.CgroupRoot() {
		return true
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategoryMounts,
		"mounts.writable_host_paths",
		"Detect writable bind-mounted host paths (/etc/cron*, /etc/ld.so.preload, /root/.ssh, /var/lib/docker, ...) (T60)",
		[]string{"InContainer"},
		func() { CheckWritableHostPaths() },
	)
}
