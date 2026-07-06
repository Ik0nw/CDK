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

// CheckContainerRuntimeFingerprint attempts to identify the container
// runtime (runc, gVisor/runsc, Kata Containers, Firecracker, etc.) and
// assesses the escape difficulty based on the runtime's security model.
//
// Detection signals:
//  - /proc/version contains "gVisor" → runsc (gVisor)
//  - /proc/cpuinfo "hypervisor" flag + limited /dev → Kata/Firecracker
//  - dmesg contains "Kata Containers" → Kata
//  - /sys/devices/virtual/dmi/id/product_name contains "Google Compute Engine"
//    and /dev is very sparse → gVisor
//  - /proc/1/cgroup contains "docker" or "containerd" → runc
//  - /run/.containerenv exists → Podman
//  - /.dockerenv exists → Docker
//  - /proc/self/mountinfo contains "overlay" → standard container
//  - /proc/self/mountinfo contains "9p" or "virtio_fs" → VM-based (Kata/Firecracker)
//
// OPSEC: read-only.  All file opens use StealthOpen with O_CLOEXEC.
//
// T64 / security.runtime_deep_inspect.
func CheckContainerRuntimeFingerprint() {
	fmt.Fprintf(os.Stdout, "container runtime fingerprint (T64) — runtime detection + escape difficulty:\n")

	runtime := "unknown"
	confidence := 0
	var indicators []string

	// --- Signal: /proc/version ---
	procVersion := readFileFirstLine("proc/version")
	if strings.Contains(strings.ToLower(procVersion), "gvisor") {
		runtime = "gVisor (runsc)"
		confidence = 95
		indicators = append(indicators, "/proc/version mentions gVisor")
	}

	// --- Signal: /.dockerenv ---
	if stealthFileExists("/.dockerenv") {
		indicators = append(indicators, "/.dockerenv present (Docker)")
		if confidence < 30 {
			runtime = "Docker/runc"
			confidence = 30
		}
	}

	// --- Signal: /run/.containerenv (Podman) ---
	if stealthFileExists("/run/.containerenv") {
		runtime = "Podman"
		confidence = 80
		indicators = append(indicators, "/run/.containerenv present (Podman)")
	}

	// --- Signal: cgroup path contains runtime name ---
	cgroupLines := readFileLines("proc/self/cgroup")
	for _, line := range cgroupLines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "docker") {
			indicators = append(indicators, "cgroup path contains 'docker'")
			if confidence < 50 {
				runtime = "Docker/runc"
				confidence = 50
			}
		}
		if strings.Contains(lower, "containerd") {
			indicators = append(indicators, "cgroup path contains 'containerd'")
			if confidence < 40 {
				runtime = "containerd/runc"
				confidence = 40
			}
		}
		if strings.Contains(lower, "kubepods") {
			indicators = append(indicators, "cgroup path contains 'kubepods' (Kubernetes)")
		}
		if strings.Contains(lower, "kata") {
			runtime = "Kata Containers"
			confidence = 90
			indicators = append(indicators, "cgroup path contains 'kata'")
		}
		if strings.Contains(lower, "firecracker") {
			runtime = "Firecracker"
			confidence = 90
			indicators = append(indicators, "cgroup path contains 'firecracker'")
		}
	}

	// --- Signal: mountinfo filesystem types ---
	mountInfo := readFileLines("proc/self/mountinfo")
	has9p := false
	hasVirtioFS := false
	hasOverlay := false
	for _, line := range mountInfo {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "9p") {
			has9p = true
		}
		if strings.Contains(lower, "virtio_fs") || strings.Contains(lower, "virtiofs") {
			hasVirtioFS = true
		}
		if strings.Contains(lower, "overlay") {
			hasOverlay = true
		}
	}
	if has9p || hasVirtioFS {
		indicators = append(indicators, "9p/virtio-fs mounts detected (VM-based runtime)")
		if confidence < 70 {
			runtime = "VM-based (Kata/Firecracker/gVisor)"
			confidence = 70
		}
	}
	if hasOverlay {
		indicators = append(indicators, "overlayfs mount (standard container)")
		if confidence < 30 {
			runtime = "runc (standard)"
			confidence = 30
		}
	}

	// --- Signal: /dev sparseness (gVisor has very few devices) ---
	devEntries := countEntriesInDir("/dev")
	if devEntries > 0 && devEntries <= 5 {
		indicators = append(indicators, fmt.Sprintf("only %d entries in /dev (gVisor-like sparseness)", devEntries))
		if confidence < 60 {
			runtime = "gVisor or micro-VM"
			confidence = 60
		}
	}

	// --- Signal: /proc/sys/kernel/osrelease ---
	osrelease := readFileFirstLine("proc/sys/kernel/osrelease")
	if strings.Contains(strings.ToLower(osrelease), "gvisor") {
		runtime = "gVisor (runsc)"
		confidence = 98
		indicators = append(indicators, "osrelease contains 'gvisor'")
	}

	// --- Signal: DMI product name (Firecracker sets this) ---
	productName := stealthReadFile("/sys/devices/virtual/dmi/id/product_name")
	if strings.Contains(productName, "Firecracker") {
		runtime = "Firecracker"
		confidence = 99
		indicators = append(indicators, "DMI product_name='Firecracker'")
	}

	// --- Signal: CPUID hypervisor bit (VM-based runtimes) ---
	cpuFlags := getCPUFlags()
	hasHypervisor := false
	for _, flag := range cpuFlags {
		if flag == "hypervisor" {
			hasHypervisor = true
			break
		}
	}
	if hasHypervisor {
		indicators = append(indicators, "CPUID hypervisor bit set (running in VM)")
	}

	// --- Signal: /sys/devices/virtual/dmi/id/sys_vendor ---
	sysVendor := stealthReadFile("/sys/devices/virtual/dmi/id/sys_vendor")
	if strings.Contains(sysVendor, "Amazon EC2") {
		// Could be Firecracker on AWS
		indicators = append(indicators, "DMI sys_vendor='Amazon EC2' (could be Firecracker on AWS)")
	}

	// --- Print results ---
	if len(indicators) == 0 {
		fmt.Fprintf(os.Stdout, "\t[AMBER] no runtime-specific indicators found — assuming bare-metal or unknown container\n")
	} else {
		for _, ind := range indicators {
			fmt.Fprintf(os.Stdout, "\t  %s\n", ind)
		}
	}

	colour := "AMBER"
	if confidence >= 80 {
		colour = "GREEN"
	}

	fmt.Fprintf(os.Stdout, "\n\t[%s] runtime: %s (confidence: %d%%)\n", colour, runtime, confidence)

	// --- Escape difficulty assessment ---
	escapeDifficulty := ""
	escapeNotes := ""
	switch {
	case strings.Contains(strings.ToLower(runtime), "gvisor"):
		escapeDifficulty = "EXTREME"
		escapeNotes = "gVisor provides a user-space kernel in Go.  Escape requires a gVisor SYSENTER/handler bug.  Check for known gVisor CVEs."
	case strings.Contains(strings.ToLower(runtime), "kata") ||
		strings.Contains(strings.ToLower(runtime), "firecracker") ||
		strings.Contains(strings.ToLower(runtime), "vm-based"):
		escapeDifficulty = "HIGH"
		escapeNotes = "VM-based runtime.  Container escape requires VM escape (KVM bug).  Focus on VM-escape vectors rather than container escapes."
	case strings.Contains(strings.ToLower(runtime), "runc") ||
		strings.Contains(strings.ToLower(runtime), "docker") ||
		strings.Contains(strings.ToLower(runtime), "containerd") ||
		strings.Contains(strings.ToLower(runtime), "podman"):
		escapeDifficulty = "LOW to MEDIUM"
		escapeNotes = "Standard Linux container.  Check cgroup release_agent, device passthrough, writable host mounts, capabilities, seccomp, and namespace isolation."
	default:
		escapeDifficulty = "UNKNOWN"
		escapeNotes = "Unable to determine runtime.  Run full evaluate profile for detailed analysis."
	}

	fmt.Fprintf(os.Stdout, "\t     escape difficulty: %s — %s\n", escapeDifficulty, escapeNotes)

	// Also note if hypervisor bit is set but runtime looks like runc.
	if hasHypervisor && strings.Contains(strings.ToLower(runtime), "runc") {
		fmt.Fprintf(os.Stdout, "\t     note: hypervisor bit set but runc detected — likely nested container in VM\n")
	}
}

// stealthFileExists checks if a file exists using raw openat syscall.
func stealthFileExists(path string) bool {
	fd, err := util.StealthOpen(path, syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

// stealthReadFile reads a file's contents using StealthReadFile.
func stealthReadFile(path string) string {
	data, err := util.StealthReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// getCPUFlags parses /proc/cpuinfo and returns the flags list from the
// first CPU entry.
func getCPUFlags() []string {
	lines := readFileLines("proc/cpuinfo")
	for _, line := range lines {
		if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
			// "flags		: fpu vme de pse tsc msr ..."
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.Fields(parts[1])
			}
		}
	}
	return nil
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.runtime_deep_inspect",
		"Deep container runtime detection (runc, gVisor, Kata, Firecracker, Podman) + escape difficulty (T64)",
		[]string{"InContainer"},
		func() { CheckContainerRuntimeFingerprint() },
	)
}
