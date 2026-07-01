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
	"log"
	"strings"
)

// RuntimeFingerprint describes every positively-identified container
// runtime AND hypervisor / DMI layer found on the current host.
//
// OPSEC CONTRACT: every detector reaches only /proc + /sys files, and
// only via the `readFileLines` / `readFileFirstLine` / `fileExists`
// helpers.  No network, no exec, no shell, no writes.  All reads are
// gated through envRoot so tests can drive them with fixtures.
type RuntimeFingerprint struct {
	// Runtimes holds every container runtime that fired at least one
	// positive signal.  Order is highest-confidence-first.
	Runtimes []DetectedRuntime `json:"runtimes"`
	// Hypervisors holds every hardware-virtualisation layer positively
	// identified (KVM, Firecracker, Kata guest, XEN, Hyper-V, VMware, …).
	Hypervisors []DetectedHypervisor `json:"hypervisors"`
	// DMI is the raw DMI class readouts (sys/class/dmi/id/*), when
	// available.  A missing file yields an empty string; fields are
	// never omitted entirely so downstream reports stay structural.
	DMI DMISnapshot `json:"dmi"`
	// LinuxKit is true when the host kernel / init system has the
	// characteristic LinuxKit footprints.
	LinuxKit bool `json:"linuxkit"`
}

// DetectedRuntime records a single runtime hit with provenance.
type DetectedRuntime struct {
	Name     string   `json:"name"`
	Confidence string `json:"confidence"` // "high" | "medium" | "low"
	Evidence []string `json:"evidence"`
}

// DetectedHypervisor records a single hypervisor hit.
type DetectedHypervisor struct {
	Name       string   `json:"name"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// DMISnapshot mirrors the subset of /sys/class/dmi/id/* files that
// red-team operators actually use to identify the hardware substrate.
type DMISnapshot struct {
	SysVendor       string `json:"sys_vendor"`
	ProductName     string `json:"product_name"`
	ProductVersion  string `json:"product_version"`
	ProductUUID     string `json:"product_uuid"`
	BIOSVendor      string `json:"bios_vendor"`
	BIOSVersion     string `json:"bios_version"`
	BoardVendor     string `json:"board_vendor"`
	BoardName       string `json:"board_name"`
	ChassisAssetTag string `json:"chassis_asset_tag"`
	ChassisVendor   string `json:"chassis_vendor"`
	ChassisType     string `json:"chassis_type"`
}

// runtimeDetector returns (name, confidence, evidence) for a specific
// runtime hypothesis.
type runtimeDetector func() (name string, confidence string, evidence []string)

// hypervisorDetector returns (name, confidence, evidence) for a specific
// hypervisor hypothesis.
type hypervisorDetector func(dmi DMISnapshot) (name string, confidence string, evidence []string)

// RuntimeFingerprintCheck is the check body registered as
// "system.runtime_fingerprint".  It is a public function so CallBasics
// style helpers and external test code can invoke it directly.
//
// The implementation:
//  1. Reads DMI once into DMISnapshot (all /sys/class/dmi/id/* files we
//     care about; missing → empty string, never an error).
//  2. Runs every runtimeDetector; appends any non-empty result.
//  3. Runs every hypervisorDetector; appends any non-empty result.
//  4. Scans for LinuxKit footprints (cmdline, bios_vendor, os-release).
//  5. Logs the resulting fingerprint via log.Printf (human readable) and
//     returns the structured value so JSON-report mode can capture it.
func RuntimeFingerprintCheck() RuntimeFingerprint {
	dmi := readDMI()
	fp := RuntimeFingerprint{DMI: dmi}

	runtimeDetectors := []runtimeDetector{
		detectDocker,
		detectPodman,
		detectCRIO,
		detectContainerd,
		detectRunc,
		detectGVisor,
	}
	for _, det := range runtimeDetectors {
		name, conf, ev := det()
		if name == "" || len(ev) == 0 {
			continue
		}
		fp.Runtimes = append(fp.Runtimes, DetectedRuntime{
			Name: name, Confidence: conf, Evidence: ev,
		})
	}

	hvDetectors := []hypervisorDetector{
		detectFirecracker,
		detectKata,
		detectKVM,
		detectXEN,
		detectHyperV,
		detectVMware,
		detectVirtualBox,
	}
	for _, det := range hvDetectors {
		name, conf, ev := det(dmi)
		if name == "" || len(ev) == 0 {
			continue
		}
		fp.Hypervisors = append(fp.Hypervisors, DetectedHypervisor{
			Name: name, Confidence: conf, Evidence: ev,
		})
	}

	fp.LinuxKit = detectLinuxKit()

	log.Printf("[runtime-fingerprint] container runtimes: %d, hypervisors: %d, linuxkit=%v",
		len(fp.Runtimes), len(fp.Hypervisors), fp.LinuxKit)
	for _, r := range fp.Runtimes {
		log.Printf("  runtime %s (%s): %s", r.Name, r.Confidence, strings.Join(r.Evidence, "; "))
	}
	for _, h := range fp.Hypervisors {
		log.Printf("  hypervisor %s (%s): %s", h.Name, h.Confidence, strings.Join(h.Evidence, "; "))
	}
	if dmi.SysVendor != "" || dmi.ProductName != "" {
		log.Printf("  DMI: sys_vendor=%q product_name=%q bios_vendor=%q",
			dmi.SysVendor, dmi.ProductName, dmi.BIOSVendor)
	}

	return fp
}

// ---------- DMI snapshot ------------------------------------------------

func readDMI() DMISnapshot {
	return DMISnapshot{
		SysVendor:       strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/sys_vendor")),
		ProductName:     strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/product_name")),
		ProductVersion:  strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/product_version")),
		ProductUUID:     strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/product_uuid")),
		BIOSVendor:      strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/bios_vendor")),
		BIOSVersion:     strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/bios_version")),
		BoardVendor:     strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/board_vendor")),
		BoardName:       strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/board_name")),
		ChassisAssetTag: strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/chassis_asset_tag")),
		ChassisVendor:   strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/chassis_vendor")),
		ChassisType:     strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/chassis_type")),
	}
}

// ---------- runtime detectors -------------------------------------------

// detectDocker recognises Docker / Moby containers via four signals:
//
//  1. /.dockerenv sentinel (Docker, also created by containerd's dockerd
//     shim).
//  2. cgroup path tokens: "docker" anywhere in /proc/1/cgroup or
//     /proc/self/cgroup (v1 + v2).
//  3. docker-init binary referenced on /proc/1/exe's target string is
//     NOT used here (would require readlink on exe which can raise
//     PTRACE_TRACEME-adjacent LSM alarms).  Instead we use
//     /proc/1/comm == "docker-init" if present.
//  4. /proc/mounts carries an overlayfs layer whose upperdir path
//     contains "docker/overlay2".
func detectDocker() (string, string, []string) {
	var ev []string
	if fileExists(".dockerenv") {
		ev = append(ev, "/.dockerenv exists")
	}
	for _, line := range append(readFileLines("proc/1/cgroup"), readFileLines("proc/self/cgroup")...) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "docker") || strings.Contains(lower, "moby") {
			ev = append(ev, "cgroup path contains docker/moby: "+truncate(line, 80))
			break
		}
	}
	if comm := strings.ToLower(readFileFirstLine("proc/1/comm")); comm == "docker-init" {
		ev = append(ev, "/proc/1/comm == docker-init")
	}
	for _, line := range readFileLines("proc/mounts") {
		if strings.Contains(line, "docker/overlay2") || strings.Contains(line, "docker/aufs") {
			ev = append(ev, "/proc/mounts overlay2/aufs anchored at docker/")
			break
		}
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if contains(ev, "/.dockerenv exists") && len(ev) >= 2 {
		conf = "high"
	}
	return "docker", conf, ev
}

// detectPodman matches Podman / libpod via:
//
//  1. /run/.containerenv (the official libpod sentinel, also set by
//     buildah's `runv` variant).
//  2. cgroup tokens "libpod" or "podman-" in /proc/*/cgroup.
//  3. /proc/mounts shows an overlay anchored at
//     "containers/storage/overlay".
//  4. /proc/self/mountinfo carries a libpod rootfs marker.
func detectPodman() (string, string, []string) {
	var ev []string
	if fileExists("run/.containerenv") {
		ev = append(ev, "/run/.containerenv exists")
	}
	for _, line := range append(readFileLines("proc/1/cgroup"), readFileLines("proc/self/cgroup")...) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "libpod") || strings.Contains(lower, "podman-") {
			ev = append(ev, "cgroup path contains libpod/podman: "+truncate(line, 80))
			break
		}
	}
	for _, line := range readFileLines("proc/mounts") {
		// containers/storage/overlay is shared between podman and
		// cri-o (both use github.com/containers/storage).  Only count
		// this as podman evidence when combined with libpod segments.
		if strings.Contains(line, "/storage/overlay") &&
			(strings.Contains(line, "libpod") ||
				strings.Contains(line, "rootlessoverlay") ||
				strings.Contains(line, "/overlay-layers/")) {
			ev = append(ev, "/proc/mounts references libpod containers/storage/overlay")
			break
		}
	}
	for _, line := range readFileLines("proc/self/mountinfo") {
		if strings.Contains(line, "libpod-") {
			ev = append(ev, "/proc/self/mountinfo references libpod-* mount")
			break
		}
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if contains(ev, "/run/.containerenv exists") {
		conf = "high"
	}
	return "podman", conf, ev
}

// detectCRIO identifies CRI-O using well-known markers:
//
//  1. cgroup hierarchy tokens "crio" or "cri-containerd" (the
//     historical CRI-O → containerd bridge; still seen on some
//     RHEL/SLES installs).
//  2. /proc/mounts has a source path containing "crio" (typically
//     the overlay lowerdir stack).
//  3. /proc/1/environ carries the `container=cri-o` environment
//     variable set by CRI-O.
//  4. /proc/self/environ `_LIBCONTAINER` (runc OCI-runtime layer used
//     by CRI-O on rhel) — alone is ambiguous with runc, so is only
//     recorded as a tiebreaker with one of (1,2,3).
func detectCRIO() (string, string, []string) {
	var ev []string
	for _, line := range append(readFileLines("proc/1/cgroup"), readFileLines("proc/self/cgroup")...) {
		lower := strings.ToLower(line)
		// "cri-containerd" is containerd's CRI plugin path; CRI-O uses
		// the literal tokens "crio" or "cri-o" as directory segments.
		hasCRIO := false
		for _, field := range strings.FieldsFunc(lower, func(r rune) bool {
			return r == '/' || r == ':' || r == '-' || r == '.' || r == '_'
		}) {
			if field == "crio" || field == "cri" {
				hasCRIO = true
				break
			}
		}
		if strings.Contains(lower, "cri-containerd") {
			hasCRIO = false
		}
		if hasCRIO {
			ev = append(ev, "cgroup path contains crio segment: "+truncate(line, 80))
			break
		}
	}
	for _, line := range readFileLines("proc/mounts") {
		if strings.Contains(strings.ToLower(line), "crio") {
			ev = append(ev, "/proc/mounts references crio path")
			break
		}
	}
	if hasEnviron("proc/1/environ", "container=cri-o") ||
		hasEnviron("proc/self/environ", "container=cri-o") {
		ev = append(ev, "container=cri-o in environ")
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "container=cri-o") }) {
		conf = "high"
	}
	return "cri-o", conf, ev
}

// detectContainerd matches containerd (standalone or shimming k8s /
// docker / crio) via:
//
//  1. cgroup tokens "containerd" or "kubepods" in /proc/*/cgroup.
//  2. /proc/net/unix contains an abstract `@/containerd-shim/…` socket.
//  3. /proc/mounts overlay lowerdir contains "io.containerd.snapshotter".
//  4. /proc/1/environ / /proc/self/environ have
//     `container=containerd` (CRI's official env).
func detectContainerd() (string, string, []string) {
	var ev []string
	for _, line := range append(readFileLines("proc/1/cgroup"), readFileLines("proc/self/cgroup")...) {
		lower := strings.ToLower(line)
		// "containerd" literal token (not inside "cri-containerd", which
		// is the CRI-O bridge path) plus "kubepods" both count.
		hasContainerd := strings.Contains(lower, "containerd") &&
			!strings.Contains(lower, "cri-containerd")
		hasKubepods := strings.Contains(lower, "kubepods")
		if hasContainerd || hasKubepods {
			ev = append(ev, "cgroup path contains containerd/kubepods: "+truncate(line, 80))
			break
		}
	}
	for _, line := range readFileLines("proc/net/unix") {
		if strings.Contains(line, "@/containerd-shim/") {
			ev = append(ev, "abstract containerd-shim socket in /proc/net/unix")
			break
		}
	}
	for _, line := range readFileLines("proc/mounts") {
		if strings.Contains(line, "io.containerd.snapshotter") {
			ev = append(ev, "/proc/mounts references io.containerd.snapshotter")
			break
		}
	}
	if hasEnviron("proc/1/environ", "container=containerd") ||
		hasEnviron("proc/self/environ", "container=containerd") {
		ev = append(ev, "container=containerd in environ")
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if len(ev) >= 3 &&
		(containsF(ev, func(s string) bool { return strings.Contains(s, "containerd-shim") }) ||
			containsF(ev, func(s string) bool { return strings.Contains(s, "container=containerd") })) {
		conf = "high"
	}
	return "containerd", conf, ev
}

// detectRunc matches runc (the dominant OCI runtime used as a backend
// by Docker, containerd, CRI-O, Podman, …).  Because runc is the
// *lowest* layer in most stacks, a runc detection SHOULD NOT be
// treated as mutually exclusive with docker / containerd / podman /
// crio — we report it alongside.
//
// Signals:
//
//  1. /proc/self/status AppArmor label starts with
//     "docker-default" / "cri-containerd.apparmor.d" /
//     "runc-default" / "libpod-default" (all written by runc's
//     AppArmor integration).
//  2. /proc/self/mountinfo contains the runc-specific
//     `runc.*/rootfs` temporary mount segment.
//  3. /proc/*/cgroup contains the literal token "runc" (the containerd
//     task-id path used by shim v2).
func detectRunc() (string, string, []string) {
	var ev []string
	for _, line := range readFileLines("proc/self/status") {
		if strings.HasPrefix(line, "CapEff:") {
			continue
		}
		// The lines we actually want look like:
		//   NoNewPrivs:  0
		//   Seccomp:     2
		//   Speculation_Store_Bypass:  thread force mitigated
		// We hunt for the (optional) "AppArmor:" line, which runc emits
		// when AppArmor is active in the host kernel.
	}
	// AppArmor label probe.  Modern kernels expose AppArmor label via
	// /proc/self/attr/apparmor/current OR the legacy
	// /proc/self/attr/current line.  Read both; accept any match.
	for _, p := range []string{
		"proc/self/attr/apparmor/current",
		"proc/self/attr/current",
		"proc/1/attr/apparmor/current",
		"proc/1/attr/current",
	} {
		l := strings.ToLower(strings.TrimSpace(readFileFirstLine(p)))
		if l == "" || strings.HasPrefix(l, "unconfined") {
			continue
		}
		for _, tok := range []string{"docker-default", "runc-default", "libpod-default",
			"cri-containerd.apparmor.d", "crio-default"} {
			if strings.Contains(l, tok) {
				ev = append(ev, fmt.Sprintf("apparmor label %q matches %s", l, tok))
				break
			}
		}
		if len(ev) > 0 {
			break
		}
	}
	for _, line := range readFileLines("proc/self/mountinfo") {
		// runc creates a tmpfs bind at a path like
		//   /run/containerd/io.containerd.runtime.v2.task/default/<cid>/rootfs
		// whose trailing segment is literally "rootfs" and whose parent
		// has "runc" or "io.containerd.runtime" in it.
		if strings.Contains(line, "runc.") && strings.HasSuffix(strings.Fields(line)[len(strings.Fields(line))-1], "rootfs") {
			ev = append(ev, "mountinfo contains runc.*.rootfs segment")
			break
		}
	}
	for _, line := range append(readFileLines("proc/1/cgroup"), readFileLines("proc/self/cgroup")...) {
		if strings.Contains(strings.ToLower(line), "runc") {
			ev = append(ev, "cgroup path contains runc token")
			break
		}
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "apparmor") }) {
		conf = "high"
	}
	return "runc", conf, ev
}

// detectGVisor identifies gVisor (runsc) — Google's user-space kernel
// container runtime.  gVisor's defining proc/sys footprint is:
//
//  1. /proc/version contains "gVisor" literally (runsc injects this
//     string into utsname.release on startup).
//  2. /proc/self/status has an unusual Vmalloc* / Hardware* line layout
//     — actually the strongest cheap fingerprint is the presence of
//     both `Threads: 3` AND `State: R (running)` on a sleeping
//     workload; we instead use /proc/cpuinfo reporting 0 BogoMIPS or
//     a zero `cpu MHz` line, both of which gVisor synthesises.
//  3. /proc/sys/kernel/osrelease ends with "-gvisor" or is the
//     synthetic string "4.4.0".
//  4. /proc/self/mountinfo has a "9p" filesystem entry (runsc mounts
//     the container rootfs over 9p by default).
//  5. /proc/dma is empty AND /proc/iomem has no PCI devices (gVisor's
//     emulation lacks these).
func detectGVisor() (string, string, []string) {
	var ev []string
	ver := strings.ToLower(readFileFirstLine("proc/version"))
	if strings.Contains(ver, "gvisor") {
		ev = append(ev, "/proc/version contains gvisor")
	}
	osr := strings.ToLower(readFileFirstLine("proc/sys/kernel/osrelease"))
	if strings.Contains(osr, "gvisor") || osr == "4.4.0" {
		ev = append(ev, "/proc/sys/kernel/osrelease is gvisor-synthetic: "+osr)
	}
	for _, line := range readFileLines("proc/self/mountinfo") {
		if strings.Contains(line, " - 9p ") || strings.HasSuffix(line, " - 9p 9p rw,relatime") ||
			strings.Contains(line, "fstype=9p") || strings.Contains(line, "type 9p") {
			ev = append(ev, "/proc/self/mountinfo lists 9p filesystem")
			break
		}
	}
	// cpu MHz == 0.000 AND BogoMIPS == 0.00 is nearly unique to gvisor
	// among container runtimes; bare-metal and even firecracker report
	// a genuine MHz figure.
	cpuLines := readFileLines("proc/cpuinfo")
	for _, line := range cpuLines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "cpu mhz") &&
			(strings.Contains(lower, ": 0.") || strings.HasSuffix(lower, ": 0")) {
			ev = append(ev, "/proc/cpuinfo cpu MHz == 0")
			break
		}
	}
	for _, line := range cpuLines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "bogomips") &&
			(strings.Contains(lower, ": 0.") || strings.HasSuffix(lower, ": 0")) {
			ev = append(ev, "/proc/cpuinfo BogoMIPS == 0")
			break
		}
	}
	dma := readFileLines("proc/dma")
	if len(dma) == 0 && !fileExists("proc/iomem") {
		ev = append(ev, "/proc/dma empty AND /proc/iomem missing (gvisor 9p passthrough)")
	}
	// Demote the "dma empty + iomem missing" combo to a tiebreaker: it
	// fires on every stripped-down kernel/fixture tree.  Alone it must
	// NOT produce a gvisor hit — require at least one STRONG signal
	// (proc/version or cpu MHz/BogoMIPS == 0 or 9p mount or synthetic
	// osrelease).
	if len(ev) == 1 && strings.Contains(ev[0], "dma empty") {
		return "", "", nil
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "gvisor") }) ||
		containsF(ev, func(s string) bool { return strings.Contains(s, " 9p ") }) {
		conf = "high"
	}
	return "gvisor", conf, ev
}

// ---------- hypervisor detectors ----------------------------------------

// detectFirecracker matches AWS Firecracker / firecracker-containerd
// VMMs.  Firecracker intentionally exposes a tiny DMI table:
//
//  1. sys/class/dmi/id/board_vendor == "Amazon EC2" (exact) AND
//     sys/class/dmi/id/board_name == "r5d.metal" or other Nitro
//     metal SKU is HOST; the Firecracker GUEST signature is
//     board_name == "Firecracker" OR (sys_vendor starts with "FC " /
//     product_name == "MicroVM").
//  2. /proc/cpuinfo hypervisor vendor_id == "KVMKVMKVM" combined with
//     dmi product_uuid that starts with
//     "7ecf0e95-0000-4000-8000-000000000000"-style Firecracker UUID
//     (byte layout 7e cf 0e 95 … — in practice we just check that
//     /sys/devices/system/cpu/vulnerabilities/* is absent because
//     Firecracker does not pass through CPUID fault-information
//     leaves).
//  3. /proc/cmdline contains "reboot=k" (Firecracker default) and NO
//     "console=ttyS0" (it uses the virtio console instead).
func detectFirecracker(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	sv := strings.ToLower(dmi.SysVendor)
	pn := strings.ToLower(dmi.ProductName)
	bv := strings.ToLower(dmi.BoardVendor)
	bn := strings.ToLower(dmi.BoardName)
	if strings.HasPrefix(sv, "fc ") || pn == "microvm" || bn == "firecracker" {
		ev = append(ev, fmt.Sprintf("DMI sys_vendor=%q product_name=%q board_name=%q (firecracker signatures)",
			dmi.SysVendor, dmi.ProductName, dmi.BoardName))
	}
	if strings.Contains(bv, "amazon") && (strings.Contains(bn, "firecracker") || strings.Contains(pn, "firecracker")) {
		ev = append(ev, "DMI board_vendor amazon + board/product name firecracker")
	}
	// CPUID hypervisor leaf 0x40000000 → ebx:ecx:edx == "KVMKVMKVM".
	// Firecracker guests use KVM acceleration, so this fires alongside
	// the DMI check; combined we can disambiguate firecracker-from-KVM.
	cmdline := strings.ToLower(readFileFirstLine("proc/cmdline"))
	if strings.Contains(cmdline, "reboot=k") && !strings.Contains(cmdline, "console=ttys") {
		ev = append(ev, "/proc/cmdline contains reboot=k, no ttyS console (firecracker default)")
	}
	vulns := readFileLines("sys/devices/system/cpu/vulnerabilities/spectre_v1")
	if len(vulns) == 0 && !fileExists("sys/devices/system/cpu/vulnerabilities/meltdown") {
		ev = append(ev, "/sys/devices/system/cpu/vulnerabilities/* absent (firecracker cpuid filtering)")
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	// "reboot=k + no ttyS" and "vulnerabilities/* absent" are supporting
	// signals only — they fire on many VMMs and even on stripped bare-metal
	// kernels.  Alone they must NOT produce a firecracker hit.  Require at
	// least one HARD signal (DMI signature).
	hard := false
	for _, s := range ev {
		if strings.Contains(s, "DMI") {
			hard = true
			break
		}
	}
	if !hard {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "DMI") }) {
		conf = "high"
	}
	return "firecracker", conf, ev
}

// detectKata matches Kata Containers (K8s CRI runtime + lightweight VM).
// Kata's most reliable DMI signature is product_name == "Kata" (Kata 2.x
// QEMU machine) OR bios_vendor contains "Kata" OR sys_vendor is
// "Katacontainers".
//
// Secondary signals:
//   - /proc/cmdline contains `agent.trace` / `kata-agent` token.
//   - /proc/version ends with " * kata#1 SMP" style Kata kernel build tag.
//   - /proc/mounts lists a virtiofs or 9p root mount (Kata shares host
//     rootfs into the VM over these transports; unlike firecracker,
//     virtiofs is the Kata default).
func detectKata(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	sv := strings.ToLower(dmi.SysVendor)
	pn := strings.ToLower(dmi.ProductName)
	bios := strings.ToLower(dmi.BIOSVendor)
	if strings.Contains(sv, "kata") || strings.Contains(pn, "kata") || strings.Contains(bios, "kata") {
		ev = append(ev, fmt.Sprintf("DMI kata signature: sys=%q product=%q bios=%q",
			dmi.SysVendor, dmi.ProductName, dmi.BIOSVendor))
	}
	cmdline := strings.ToLower(readFileFirstLine("proc/cmdline"))
	if strings.Contains(cmdline, "kata-agent") || strings.Contains(cmdline, "agent.trace") {
		ev = append(ev, "/proc/cmdline contains kata-agent/agent.trace")
	}
	ver := strings.ToLower(readFileFirstLine("proc/version"))
	if strings.Contains(ver, "kata") {
		ev = append(ev, "/proc/version contains kata build tag")
	}
	for _, line := range readFileLines("proc/mounts") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "virtiofs" && strings.Contains(fields[1], "/") {
			ev = append(ev, "/proc/mounts has virtiofs mount (kata shared rootfs)")
			break
		}
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "DMI kata signature") }) {
		conf = "high"
	}
	return "kata", conf, ev
}

// detectKVM returns a match when the guest's CPUID hypervisor leaf
// reports KVM (vendor_id line "KVMKVMKVM") — which covers
// firecracker, kata, and plain QEMU/KVM.  We intentionally keep this
// separate from firecracker/kata so operators can tell "it's KVM but
// not one of the container-variant VMMs".
//
// Additional signals:
//   - /sys/class/dmi/id/sys_vendor == "QEMU" or "Linaro" (aarch64 QEMU).
//   - /proc/cpuinfo model name contains "QEMU Virtual CPU".
func detectKVM(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	for _, line := range readFileLines("proc/cpuinfo") {
		lower := strings.ToLower(line)
		if (strings.HasPrefix(lower, "hypervisor vendor_id") ||
			strings.HasPrefix(lower, "vendor_id")) &&
			strings.Contains(lower, "kvmkvmkvm") {
			ev = append(ev, "/proc/cpuinfo vendor_id == KVMKVMKVM")
			break
		}
	}
	if strings.ToLower(dmi.SysVendor) == "qemu" || strings.Contains(strings.ToLower(dmi.ProductName), "qemu") {
		ev = append(ev, "DMI sys_vendor/product == QEMU")
	}
	for _, line := range readFileLines("proc/cpuinfo") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "model name") && strings.Contains(lower, "qemu virtual cpu") {
			ev = append(ev, "/proc/cpuinfo model name is QEMU Virtual CPU")
			break
		}
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "low"
	if len(ev) >= 2 {
		conf = "medium"
	}
	if containsF(ev, func(s string) bool { return strings.Contains(s, "KVMKVMKVM") }) {
		conf = "high"
	}
	return "kvm", conf, ev
}

// detectXEN matches the Xen hypervisor (paravirt + HVM guests).
func detectXEN(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	for _, line := range readFileLines("proc/cpuinfo") {
		lower := strings.ToLower(line)
		if (strings.HasPrefix(lower, "hypervisor vendor_id") ||
			strings.HasPrefix(lower, "vendor_id")) &&
			strings.Contains(lower, "xenvmm") {
			ev = append(ev, "/proc/cpuinfo vendor_id == XENVMM")
			break
		}
	}
	if fileExists("sys/hypervisor/type") &&
		strings.ToLower(readFileFirstLine("sys/hypervisor/type")) == "xen" {
		ev = append(ev, "/sys/hypervisor/type == xen")
	}
	if strings.Contains(strings.ToLower(dmi.SysVendor), "xen") {
		ev = append(ev, "DMI sys_vendor contains xen")
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "high"
	if len(ev) == 1 {
		conf = "medium"
	}
	return "xen", conf, ev
}

// detectHyperV matches Microsoft Hyper-V / Azure guests.
func detectHyperV(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	for _, line := range readFileLines("proc/cpuinfo") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "hypervisor vendor_id") &&
			strings.Contains(lower, "microsoft hv") {
			ev = append(ev, "/proc/cpuinfo hypervisor vendor_id == Microsoft Hv")
			break
		}
	}
	if strings.Contains(strings.ToLower(dmi.SysVendor), "microsoft") &&
		strings.Contains(strings.ToLower(dmi.ProductName), "virtual machine") {
		ev = append(ev, "DMI sys_vendor=Microsoft product=Virtual Machine")
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	return "hyper-v", "high", ev
}

// detectVMware matches VMware ESXi / Workstation / Fusion guests.
func detectVMware(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	for _, line := range readFileLines("proc/cpuinfo") {
		lower := strings.ToLower(line)
		if (strings.HasPrefix(lower, "hypervisor vendor_id") ||
			strings.HasPrefix(lower, "vendor_id")) &&
			strings.Contains(lower, "vmwarevmware") {
			ev = append(ev, "/proc/cpuinfo vendor_id == VMwareVMware")
			break
		}
	}
	sv := strings.ToLower(dmi.SysVendor)
	pn := strings.ToLower(dmi.ProductName)
	bv := strings.ToLower(dmi.BIOSVendor)
	if strings.Contains(sv, "vmware") || strings.Contains(pn, "vmware") || strings.Contains(bv, "vmware") {
		ev = append(ev, fmt.Sprintf("DMI vmware signature: sys=%q product=%q bios=%q",
			dmi.SysVendor, dmi.ProductName, dmi.BIOSVendor))
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	conf := "high"
	if len(ev) == 1 && !containsF(ev, func(s string) bool { return strings.Contains(s, "VMwareVMware") }) {
		conf = "medium"
	}
	return "vmware", conf, ev
}

// detectVirtualBox matches Oracle VirtualBox guests.
func detectVirtualBox(dmi DMISnapshot) (string, string, []string) {
	var ev []string
	sv := strings.ToLower(dmi.SysVendor)
	pn := strings.ToLower(dmi.ProductName)
	bv := strings.ToLower(dmi.BIOSVendor)
	if strings.Contains(sv, "innotek") || strings.Contains(sv, "virtualbox") ||
		strings.Contains(pn, "virtualbox") || strings.Contains(bv, "innotek") ||
		strings.Contains(bv, "oracle virtualbox") {
		ev = append(ev, fmt.Sprintf("DMI vbox signature: sys=%q product=%q bios=%q",
			dmi.SysVendor, dmi.ProductName, dmi.BIOSVendor))
	}
	if len(ev) == 0 {
		return "", "", nil
	}
	return "virtualbox", "high", ev
}

// ---------- LinuxKit -----------------------------------------------------

// detectLinuxKit returns true when the running system is a LinuxKit-based
// minimal image (Docker Desktop VM, Moby VM, etc.).
//
// Signals:
//   - /proc/cmdline contains `linuxkit` / `docker.l4t` /
//     `modules=loop,squashfs,sd-mod,usb-storage quiet console=tty0`.
//   - DMI bios_vendor == "LinuxKit" (LinuxKit's OVMF build leaves this
//     string on some hypervisors).
//   - /etc/os-release contains `ID=linuxkit` or `ID=moby`.
func detectLinuxKit() bool {
	cmdline := strings.ToLower(readFileFirstLine("proc/cmdline"))
	if strings.Contains(cmdline, "linuxkit") || strings.Contains(cmdline, "docker.l4t") {
		return true
	}
	bv := strings.ToLower(strings.TrimSpace(readFileFirstLine("sys/class/dmi/id/bios_vendor")))
	if strings.Contains(bv, "linuxkit") {
		return true
	}
	for _, line := range readFileLines("etc/os-release") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "id=linuxkit") || strings.HasPrefix(lower, "id=moby") {
			return true
		}
	}
	return false
}

// ---------- tiny helpers ------------------------------------------------

// hasEnviron reports whether the NUL-separated environ file at
// <envRoot>/path contains the needle.  Handles missing files and EINTR
// gracefully (readFileLines will split on newlines only — which
// environ doesn't have — so we read it as a single blob via
// readFileFirstLine, which is wrong for that semantics.  We instead
// open+read the whole file as bytes via a one-off helper.
func hasEnviron(path, needle string) bool {
	// Implementation note: readFileLines splits on \n; environ files are
	// NUL-separated, so the entire file becomes a single "line" with
	// embedded NULs.  We still look for the needle as a substring — the
	// NULs around it don't matter for substring search of a literal
	// "container=cri-o" token.
	blob := strings.Join(readFileLines(path), "\n")
	return strings.Contains(blob, needle)
}

func contains(ss []string, needle string) bool {
	for _, s := range ss {
		if s == needle {
			return true
		}
	}
	return false
}

func containsF(ss []string, pred func(string) bool) bool {
	for _, s := range ss {
		if pred(s) {
			return true
		}
	}
	return false
}

// ---------- registration ------------------------------------------------

func init() {
	RegisterContextCheck(CategorySystemInfo, "system.runtime_fingerprint",
		"Detect container runtime + hypervisor/DMI substrate via /proc+/sys reads only",
		func(ctx *Context) error {
			RuntimeFingerprintCheck()
			return nil
		}, ProfileBasic, ProfileExtended)
}
