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

// CheckPrivilegedFingerprint performs an aggregate assessment to determine
// whether the container is running in --privileged mode (or equivalent
// relaxed security posture).
//
// The check combines multiple independent signals:
//  1. CAP_SYS_ADMIN capability (the "god mode" capability)
//  2. Full device access under /dev (block devices, /dev/mem, etc.)
//  3. No seccomp filter (seccomp disabled or permissive)
//  4. No AppArmor/SELinux confinement
//  5. Host namespace sharing (PID, net, mnt)
//  6. Ability to create device nodes (CAP_MKNOD)
//  7. Access to host /dev (not a filtered devtmpfs)
//
// Each signal contributes a score; a high score indicates a privileged
// container with high confidence.
//
// OPSEC: read-only checks.  All file opens use StealthOpen (raw openat
// syscall) with O_CLOEXEC.  No syscalls that modify system state.
//
// T63 / security.privileged_fingerprint.
func CheckPrivilegedFingerprint() {
	fmt.Fprintf(os.Stdout, "privileged container fingerprint (T63) — aggregate --privileged detection:\n")

	score := 0
	maxScore := 0
	var signals []string

	// --- Signal 1: CAP_SYS_ADMIN ---
	maxScore += 3
	if hasCapability("cap_sys_admin") {
		score += 3
		signals = append(signals, "CAP_SYS_ADMIN present (3pts)")
	} else {
		signals = append(signals, "CAP_SYS_ADMIN absent (0pts)")
	}

	// --- Signal 2: CAP_NET_ADMIN (common in privileged) ---
	maxScore += 1
	if hasCapability("cap_net_admin") {
		score += 1
		signals = append(signals, "CAP_NET_ADMIN present (1pt)")
	}

	// --- Signal 3: Device access breadth ---
	maxScore += 2
	devCount := countAccessibleDevices()
	if devCount >= 8 {
		score += 2
		signals = append(signals, fmt.Sprintf("%d accessible device nodes (2pts)", devCount))
	} else if devCount >= 4 {
		score += 1
		signals = append(signals, fmt.Sprintf("%d accessible device nodes (1pt)", devCount))
	} else {
		signals = append(signals, fmt.Sprintf("%d accessible device nodes (0pts)", devCount))
	}

	// --- Signal 4: /dev/mem or /dev/kmem accessible ---
	maxScore += 3
	if canOpenDevMem() {
		score += 3
		signals = append(signals, "/dev/mem or /dev/kmem accessible (3pts)")
	} else {
		signals = append(signals, "/dev/mem and /dev/kmem not accessible (0pts)")
	}

	// --- Signal 5: Seccomp disabled ---
	maxScore += 2
	seccompMode := getSeccompMode()
	if seccompMode == 0 {
		score += 2
		signals = append(signals, "seccomp disabled (2pts)")
	} else if seccompMode == 2 {
		signals = append(signals, "seccomp filter active (0pts)")
	} else {
		score += 1
		signals = append(signals, fmt.Sprintf("seccomp mode=%d (1pt)", seccompMode))
	}

	// --- Signal 6: AppArmor not enforcing ---
	maxScore += 1
	if !isAppArmorEnforcing() {
		score += 1
		signals = append(signals, "AppArmor not enforcing (1pt)")
	} else {
		signals = append(signals, "AppArmor enforcing (0pts)")
	}

	// --- Signal 7: Host PID namespace (shared) ---
	maxScore += 2
	if isHostPIDNamespace() {
		score += 2
		signals = append(signals, "PID namespace shared with host (2pts)")
	} else {
		signals = append(signals, "PID namespace isolated (0pts)")
	}

	// --- Signal 8: Host network namespace ---
	maxScore += 2
	if isHostNetworkNamespace() {
		score += 2
		signals = append(signals, "network namespace shared with host (2pts)")
	} else {
		signals = append(signals, "network namespace isolated (0pts)")
	}

	// --- Signal 9: Can mknod (CAP_MKNOD) ---
	maxScore += 1
	if hasCapability("cap_mknod") {
		score += 1
		signals = append(signals, "CAP_MKNOD present (1pt)")
	}

	// --- Signal 10: Many block devices visible ---
	maxScore += 1
	blockDevs := countEntriesInDir("/dev/block")
	if blockDevs >= 8 {
		score += 1
		signals = append(signals, fmt.Sprintf("%d /dev/block entries visible (1pt)", blockDevs))
	}

	// --- Print results ---
	for _, sig := range signals {
		fmt.Fprintf(os.Stdout, "\t  %s\n", sig)
	}

	pct := 0
	if maxScore > 0 {
		pct = (score * 100) / maxScore
	}

	fmt.Fprintf(os.Stdout, "\n")
	verdict := ""
	colour := ""
	switch {
	case pct >= 70:
		verdict = "HIGH CONFIDENCE — this container is running in --privileged mode or equivalent"
		colour = "GREEN"
	case pct >= 40:
		verdict = "MEDIUM CONFIDENCE — several privileged indicators present but not a full --privileged container"
		colour = "AMBER"
	default:
		verdict = "LOW — container appears to be running with standard security restrictions"
		colour = "AMBER"
	}

	fmt.Fprintf(os.Stdout, "\t[%s] privilege score: %d/%d (%d%%)\n", colour, score, maxScore, pct)
	fmt.Fprintf(os.Stdout, "\t         %s\n", verdict)

	if pct >= 70 {
		fmt.Fprintf(os.Stdout, "\t         ⚠  Full container escape is likely trivial — try: mount -o remount,rw /, cgroup release_agent, /dev/mem kernel write\n")
	}
}

// hasCapability checks if the current process has the given capability.
func hasCapability(capName string) bool {
	lines := readFileLines("proc/self/status")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			return capabilityInHex(line, capName)
		}
	}
	return false
}

// capabilityInHex checks if a named capability is set in a CapEff hex string.
func capabilityInHex(capLine, capName string) bool {
	// Map capability names to their bit positions.
	capMap := map[string]uint{
		"cap_chown":            0,
		"cap_dac_override":     1,
		"cap_dac_read_search":  2,
		"cap_fowner":           3,
		"cap_fsetid":           4,
		"cap_kill":             5,
		"cap_setgid":           6,
		"cap_setuid":           7,
		"cap_setpcap":          8,
		"cap_linux_immutable":  9,
		"cap_net_bind_service": 10,
		"cap_net_broadcast":    11,
		"cap_net_admin":        12,
		"cap_net_raw":          13,
		"cap_ipc_lock":         14,
		"cap_ipc_owner":        15,
		"cap_sys_module":       16,
		"cap_sys_rawio":        17,
		"cap_sys_chroot":       18,
		"cap_sys_ptrace":       19,
		"cap_sys_pacct":        20,
		"cap_sys_admin":        21,
		"cap_sys_boot":         22,
		"cap_sys_nice":         23,
		"cap_sys_resource":     24,
		"cap_sys_time":         25,
		"cap_sys_tty_config":   26,
		"cap_mknod":            27,
		"cap_lease":            28,
		"cap_audit_write":      29,
		"cap_audit_control":    30,
		"cap_setfcap":          31,
		"cap_mac_override":     32,
		"cap_mac_admin":        33,
		"cap_syslog":           34,
		"cap_wake_alarm":       35,
		"cap_block_suspend":    36,
		"cap_audit_read":       37,
	}

	bit, ok := capMap[capName]
	if !ok {
		return false
	}

	// Parse the hex value from "CapEff: 000001ffffffffff"
	fields := strings.Fields(capLine)
	if len(fields) < 2 {
		return false
	}
	hexVal := fields[1]

	// Check the bit.
	byteIdx := len(hexVal) - 1 - int(bit/4)
	if byteIdx < 0 || byteIdx >= len(hexVal) {
		return false
	}
	nibble := hexVal[byteIdx]
	var val uint
	if nibble >= '0' && nibble <= '9' {
		val = uint(nibble - '0')
	} else if nibble >= 'a' && nibble <= 'f' {
		val = uint(nibble-'a') + 10
	} else if nibble >= 'A' && nibble <= 'F' {
		val = uint(nibble-'A') + 10
	} else {
		return false
	}
	return (val>>(bit%4))&1 == 1
}

// countAccessibleDevices counts how many device nodes under /dev we can
// open for reading.
func countAccessibleDevices() int {
	entries, err := os.ReadDir("/dev")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := "/dev/" + e.Name()
		fd, err := util.StealthOpen(path, syscall.O_RDONLY)
		if err == nil {
			util.StealthClose(fd)
			count++
		}
	}
	return count
}

// canOpenDevMem returns true if /dev/mem or /dev/kmem can be opened.
func canOpenDevMem() bool {
	fd, err := util.StealthOpen(util.DevMemPath(), syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	fd, err = util.StealthOpen(util.DevKmemPath(), syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

// getSeccompMode reads the seccomp mode from /proc/self/status.
// Returns 0=disabled, 1=strict, 2=filter.
func getSeccompMode() int {
	lines := readFileLines("proc/self/status")
	for _, line := range lines {
		if strings.HasPrefix(line, "Seccomp:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var val int
				fmt.Sscanf(fields[1], "%d", &val)
				return val
			}
		}
	}
	return -1
}

// isAppArmorEnforcing returns true if AppArmor is in enforce mode.
func isAppArmorEnforcing() bool {
	mode := readFileFirstLine("sys/module/apparmor/parameters/enabled")
	if mode == "Y" {
		// Check current profile.
		profile := readFileFirstLine("proc/self/attr/current")
		if profile != "" && !strings.Contains(profile, "unconfined") {
			return true
		}
	}
	return false
}

// isHostPIDNamespace returns true if the PID namespace appears to be
// shared with the host.
func isHostPIDNamespace() bool {
	// If we can see PID 1 and it's not a container init (like "pause" or
	// the container entrypoint), we're likely in the host PID namespace.
	initComm := readFileFirstLine("proc/1/comm")
	if initComm == "systemd" || initComm == "init" || initComm == "launchd" {
		return true
	}
	// If /proc has many entries (host-sized process table).
	if countNumericDirs("/proc") >= 150 {
		return true
	}
	return false
}

// isHostNetworkNamespace returns true if the network namespace appears
// to be shared with the host (many interfaces, host-sized routing table).
func isHostNetworkNamespace() bool {
	ifaces := countEntriesInDir("/sys/class/net")
	if ifaces >= 12 {
		return true
	}
	routes := countLines("/proc/net/tcp") + countLines("/proc/net/udp")
	if routes >= 600 {
		return true
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.privileged_fingerprint",
		"Aggregate --privileged container detection via capabilities, device access, seccomp, namespace sharing (T63)",
		[]string{"InContainer"},
		func() { CheckPrivilegedFingerprint() },
	)
}
