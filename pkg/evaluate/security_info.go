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
	"bufio"
	"compress/gzip"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// namespaceTypes lists the Linux namespaces relevant to container isolation.
var namespaceTypes = []string{"cgroup", "ipc", "mnt", "net", "pid", "uts"}

// nsVerdict summarises a namespace's isolation confidence.
type nsVerdict int

const (
	nsAmbiguous nsVerdict = iota
	nsIsolated
	nsShared
)

func (v nsVerdict) String() string {
	switch v {
	case nsIsolated:
		return "isolated"
	case nsShared:
		return "NOT isolated (shared with host)"
	default:
		return "ambiguous (could not determine)"
	}
}

// CheckNamespaceIsolation emits a per-namespace isolation verdict.
//
// Design note: the old implementation compared /proc/1/ns/FOO with
// /proc/self/ns/FOO and called any match "shared with host".  That is
// categorically wrong: inside a container, PID 1 IS the container init so
// the two symlinks are always identical; the check told the operator
// nothing.
//
// The new implementation uses several independent side-channel signals
// per namespace and requires a clear majority before committing to
// "shared" or "isolated".  Unclear cases report "ambiguous" — per the
// CDK project rule "宁漏勿 flag" we never raise a false positive.
func CheckNamespaceIsolation() {
	log.Println("Namespace isolation status:")

	// --- shared signals (computed once) --------------------------------
	rootFSType, rootIsOverlay := detectRootFSType()
	initComm := readFirstLine("/proc/1/comm")
	procPidEntries := countNumericDirs("/proc")
	nspidLevels := countNSPidLevels("/proc/1/status")
	shmMountSize := devShmSizeMB()
	hostNSHints := hostPID1InitHints(initComm, nspidLevels, procPidEntries, rootIsOverlay)

	for _, ns := range namespaceTypes {
		var reasons []string
		var score int // >0 = isolated, <0 = shared, near-zero = ambiguous

		switch ns {
		case "pid":
			if hostNSHints {
				score -= 3
				reasons = append(reasons, "PID 1 + /proc layout look host-like")
			}
			if nspidLevels > 1 {
				score += 3
				reasons = append(reasons, fmt.Sprintf("NSpid nesting depth=%d", nspidLevels))
			}
			if nspidLevels == 1 && !hostNSHints {
				score += 0
				reasons = append(reasons, "NSpid depth=1 but host hints absent")
			}
			if procPidEntries >= 150 {
				score -= 2
				reasons = append(reasons, fmt.Sprintf("%d PID dirs in /proc (host-sized)", procPidEntries))
			}
			if procPidEntries > 0 && procPidEntries < 60 {
				score += 1
				reasons = append(reasons, fmt.Sprintf("%d PID dirs (container-sized)", procPidEntries))
			}
			if initComm == "systemd" || initComm == "init" || initComm == "launchd" {
				score -= 2
				reasons = append(reasons, fmt.Sprintf("PID 1 comm=%q", initComm))
			}

		case "mnt":
			if rootIsOverlay {
				score += 3
				reasons = append(reasons, fmt.Sprintf("root fs type=%q (container layout)", rootFSType))
			} else if rootFSType == "ext4" || rootFSType == "xfs" || rootFSType == "btrfs" {
				// Bare-metal root fs type — but containers can also mount these
				// as root via --device.  Only count as weak host hint.
				score -= 1
				reasons = append(reasons, fmt.Sprintf("root fs type=%q", rootFSType))
			}
			if hasContainerMountFingerprint() {
				score += 2
				reasons = append(reasons, "containerruntime mounts visible (/etc/hosts bind-mounts, /sys ro)")
			}
			// If we can see host block-devices under /dev, weak shared signal.
			if countEntriesInDir("/dev/block") >= 8 {
				score -= 1
				reasons = append(reasons, "many /dev/block entries visible")
			}

		case "net":
			ifaces := countEntriesInDir("/sys/class/net")
			routes := countLines("/proc/net/tcp") + countLines("/proc/net/udp")
			if ifaces >= 12 {
				score -= 2
				reasons = append(reasons, fmt.Sprintf("%d net ifaces", ifaces))
			} else if ifaces >= 2 && ifaces <= 5 {
				score += 2
				reasons = append(reasons, fmt.Sprintf("%d net ifaces (container-sized: lo+eth0+...)", ifaces))
			}
			if routes >= 600 {
				score -= 1
				reasons = append(reasons, fmt.Sprintf("%d tcp+udp sockets", routes))
			}

		case "uts":
			h := readFirstLine("/proc/sys/kernel/hostname")
			// Docker default hostname is a 12-hex container id.
			if looksLikeContainerID(h) {
				score += 3
				reasons = append(reasons, fmt.Sprintf("hostname=%q matches 12-hex container-id pattern", h))
			}
			// Host-style hostnames: ip-<dash>-<dash>-<dash>-<dash> (EC2),
			// k8s-node-*, master-*, *-node, etc.
			if looksLikeHostHostname(h) {
				score -= 2
				reasons = append(reasons, fmt.Sprintf("hostname=%q host-style", h))
			}

		case "ipc":
			// Posix MQ fs size is tiny in containers (often 800k).  Weak signal.
			if shmMountSize >= 0 {
				if shmMountSize == 64 || shmMountSize == 128 {
					score += 2
					reasons = append(reasons, fmt.Sprintf("/dev/shm size=%dMB (Docker default)", shmMountSize))
				} else if shmMountSize >= 16000 {
					score -= 1
					reasons = append(reasons, fmt.Sprintf("/dev/shm size=%dMB (host-sized)", shmMountSize))
				}
			}

		case "cgroup":
			// cgroup v2: if cgroup.controllers is exposed at all, the namespace
			// may be shared with host.  Container usually only sees their own
			// subtree (cgroup namespace isolates hierarchies).
			if cgroupNamespaceLooksShared() {
				score -= 1
				reasons = append(reasons, "cgroup root looks fully visible")
			} else {
				score += 1
				reasons = append(reasons, "cgroup subtree view only")
			}
		}

		var verdict nsVerdict
		switch {
		case score >= 2:
			verdict = nsIsolated
		case score <= -2:
			verdict = nsShared
		default:
			verdict = nsAmbiguous
		}
		reasonStr := ""
		if len(reasons) > 0 {
			reasonStr = " — " + strings.Join(reasons, "; ")
		}
		fmt.Printf("\t%s: %s%s\n", ns, verdict, reasonStr)
	}
}

// --- helpers used by CheckNamespaceIsolation -------------------------------

// detectRootFSType returns (fstype, isOverlayLike).
func detectRootFSType() (string, bool) {
	mi, err := util.GetMountInfo()
	if err != nil {
		return "", false
	}
	for _, m := range mi {
		if m.MountPoint == "/" {
			overlayLike := m.Fstype == "overlay" || m.Fstype == "aufs" || strings.Contains(m.Device, "overlay")
			return m.Fstype, overlayLike
		}
	}
	return "", false
}

// hasContainerMountFingerprint returns true when classic container mount
// signatures are present (bind-mounted /etc/hosts, /etc/resolv.conf,
// /etc/hostname from a docker-<id>/ path, /sys mounted ro, etc.).
func hasContainerMountFingerprint() bool {
	mi, err := util.GetMountInfo()
	if err != nil {
		return false
	}
	signs := 0
	for _, m := range mi {
		switch {
		case m.MountPoint == "/etc/hosts" && strings.HasPrefix(m.Root, "/docker/containers/"):
			signs++
		case m.MountPoint == "/etc/resolv.conf" && strings.HasPrefix(m.Root, "/docker/containers/"):
			signs++
		case m.MountPoint == "/etc/hostname" && strings.HasPrefix(m.Root, "/docker/containers/"):
			signs++
		case m.MountPoint == "/sys" && containsString(m.Opts, "ro"):
			signs++
		case m.MountPoint == "/run/secrets":
			signs++
		case m.Device == "overlay" && m.MountPoint == "/":
			signs++
		}
	}
	return signs >= 2
}

// readFirstLine returns the first line of a file trimmed of trailing whitespace.
func readFirstLine(path string) string {
	b, err := util.StealthReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}

// countNumericDirs counts entries under path whose name is purely numeric.
func countNumericDirs(path string) int {
	entries, err := os.ReadDir(path)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

// countNSPidLevels reads the NSpid line of the given /proc/<pid>/status and
// returns how many integer levels it contains.  A container nested in one
// pid namespace reports 2 (the host pid + the container pid).  Bare-metal
// pid 1 reports only 1.
func countNSPidLevels(pidStatusPath string) int {
	b, err := util.StealthReadFile(pidStatusPath)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		parts := strings.Fields(line)
		// parts[0] = "NSpid:"
		return len(parts) - 1
	}
	return 0
}

// hostPID1InitHints returns true when the combined evidence strongly suggests
// we are running in the host pid namespace (i.e. PID 1 here is the real host
// init).
func hostPID1InitHints(initComm string, nspidLevels, procPids int, rootIsOverlay bool) bool {
	// Container case: overlay root + NSpid nested + few PIDs = definitely nested.
	if rootIsOverlay && nspidLevels >= 2 {
		return false
	}
	// Definitely host: classic systemd init AND single NSpid level AND lots of PIDs.
	if (initComm == "systemd" || initComm == "init") && nspidLevels == 1 && procPids >= 200 {
		return true
	}
	// Strong container: container-id hostname OR short pid list + overlay
	// (handled in the hostname / mnt checks).  No need to return true here.
	return false
}

// countEntriesInDir counts non-hidden non-symlink entries in a sysfs-style dir.
// Returns -1 on error.
func countEntriesInDir(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	return len(entries)
}

// countLines returns the number of '\n'-separated lines in a file (min 0).
func countLines(path string) int {
	b, err := util.StealthReadFile(path)
	if err != nil {
		return -1
	}
	return strings.Count(string(b), "\n")
}

var hex12 = regexp.MustCompile(`^[0-9a-f]{12}$`)

func looksLikeContainerID(h string) bool {
	return hex12.MatchString(h)
}

func looksLikeHostHostname(h string) bool {
	l := strings.ToLower(h)
	switch {
	case strings.HasPrefix(l, "ip-"):
		return true
	case strings.Contains(l, "-node"):
		return true
	case strings.HasPrefix(l, "master-") || strings.HasPrefix(l, "worker-"):
		return true
	case strings.HasPrefix(l, "k8s-"):
		return true
	case strings.HasPrefix(l, "compute-"):
		return true
	}
	return false
}

// devShmSizeMB parses /proc/mounts looking for the /dev/shm tmpfs mount and
// returns its size=<NNNNNk> value in MB, or -1 if not found.
func devShmSizeMB() int {
	lines, err := utilReadLines("/proc/mounts")
	if err != nil {
		return -1
	}
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) < 4 || fields[1] != "/dev/shm" {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if !strings.HasPrefix(opt, "size=") {
				continue
			}
			v := strings.TrimPrefix(opt, "size=")
			if strings.HasSuffix(v, "m") || strings.HasSuffix(v, "M") {
				n, err := strconv.Atoi(v[:len(v)-1])
				if err == nil {
					return n
				}
			}
			if strings.HasSuffix(v, "g") || strings.HasSuffix(v, "G") {
				n, err := strconv.Atoi(v[:len(v)-1])
				if err == nil {
					return n * 1024
				}
			}
			if strings.HasSuffix(v, "k") || strings.HasSuffix(v, "K") {
				n, err := strconv.Atoi(v[:len(v)-1])
				if err == nil {
					return n / 1024
				}
			}
		}
	}
	return -1
}

// cgroupNamespaceLooksShared uses a few quick heuristics: if we see the top-
// level cgroup.controllers *and* /sys/fs/cgroup contains many subdirs (all
// host-level slices), we're probably in the host cgroup namespace.
func cgroupNamespaceLooksShared() bool {
	// We only examine the v2 case; v1 is harder and we leave it ambiguous.
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return false
	}
	n := countEntriesInDir("/sys/fs/cgroup")
	// Real host cgroup roots have tens of slice dirs; a container sees at most
	// a handful.
	return n >= 20
}

// utilReadLines wraps StealthReadFile + string split so we don't have to
// import bufio scanner for simple line reads.
func utilReadLines(path string) ([]string, error) {
	data, err := util.StealthReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// CheckSeccompStatus reads the Seccomp field from /proc/self/status and reports
// whether Seccomp is disabled (0), strict (1), or filter (2) mode.
func CheckSeccompStatus() {
	data, err := util.StealthReadFile(util.ProcSelfStatusPath())
	if err != nil {
		log.Printf("seccomp: unable to read /proc/self/status: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Seccomp:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				log.Println("seccomp: malformed Seccomp line")
				return
			}
			switch parts[1] {
			case "0":
				log.Println("Seccomp: disabled")
			case "1":
				log.Println("Seccomp: strict mode (1)")
			case "2":
				log.Println("Seccomp: filter mode (2)")
			default:
				log.Printf("Seccomp: unknown value %s", parts[1])
			}
			return
		}
	}
	log.Println("Seccomp: field not found in /proc/self/status (kernel may not support Seccomp)")
}

// CheckSeccompKernelSupport reports whether the running kernel was compiled with
// Seccomp support by checking for the Seccomp field in /proc/self/status and,
// optionally, the kernel config.
func CheckSeccompKernelSupport() {
	// The presence of the "Seccomp:" line in /proc/self/status indicates support.
	data, err := util.StealthReadFile(util.ProcSelfStatusPath())
	if err != nil {
		log.Printf("seccomp: unable to read /proc/self/status: %v", err)
		return
	}
	if strings.Contains(string(data), "Seccomp:") {
		log.Println("Seccomp: kernel supports Seccomp")
	} else {
		log.Println("Seccomp: kernel does NOT support Seccomp")
	}

	// Additional confirmation via kernel config when available.
	if val, ok := readKernelConfigOption("CONFIG_SECCOMP"); ok {
		log.Printf("Seccomp: kernel config CONFIG_SECCOMP=%s", val)
	}
}

// CheckSELinux detects whether SELinux is present and enforcing.
func CheckSELinux() {
	// /sys/fs/selinux/enforce exists only when SELinux is compiled in and mounted.
	enforceFile := util.SelinuxEnforcePath()
	data, err := util.StealthReadFile(enforceFile)
	if err != nil {
		log.Println("SELinux: not detected (no selinuxfs)")
		return
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		log.Println("SELinux: enforcing")
	case "0":
		log.Println("SELinux: permissive (loaded but not enforcing)")
	default:
		log.Printf("SELinux: unexpected enforce value %q", strings.TrimSpace(string(data)))
	}

	// Show the container's SELinux label if available.
	if label, err := util.StealthReadFile(util.ProcSelfAttrCurrentPath()); err == nil {
		trimmed := strings.TrimRight(string(label), "\x00\n")
		log.Printf("SELinux: container label: %s", trimmed)
	}
}

// CheckAppArmor inspects kernel compile options, boot parameters, runtime
// status, and the active AppArmor profile for the current process.
func CheckAppArmor() {
	// 1. Kernel compile option.
	if val, ok := readKernelConfigOption("CONFIG_SECURITY_APPARMOR"); ok {
		log.Printf("AppArmor: kernel config CONFIG_SECURITY_APPARMOR=%s", val)
	} else {
		log.Println("AppArmor: kernel config not available")
	}

	// 2. Boot parameters.
	if cmdline, err := util.StealthReadFile(util.ProcCmdlinePath()); err == nil {
		params := string(cmdline)
		if strings.Contains(params, "apparmor=1") || strings.Contains(params, "security=apparmor") {
			log.Printf("AppArmor: enabled via boot parameters (%s)", strings.TrimSpace(params))
		} else if strings.Contains(params, "apparmor=0") {
			log.Println("AppArmor: disabled via boot parameter apparmor=0")
		} else {
			log.Println("AppArmor: no explicit AppArmor boot parameter found")
		}
	}

	// 3. Runtime status.
	if data, err := util.StealthReadFile(util.AppArmorEnabledPath()); err == nil {
		if strings.TrimSpace(string(data)) == "Y" {
			log.Println("AppArmor: module is enabled (runtime)")
		} else {
			log.Println("AppArmor: module is loaded but disabled (runtime)")
		}
	} else {
		log.Println("AppArmor: module not loaded")
	}

	// 4. Container AppArmor profile.
	if label, err := util.StealthReadFile(util.ProcSelfAttrCurrentPath()); err == nil {
		trimmed := strings.TrimRight(string(label), "\x00\n")
		if trimmed == "" || trimmed == "unconfined" {
			log.Println("AppArmor: container is unconfined (no profile attached)")
		} else {
			log.Printf("AppArmor: container profile: %s", trimmed)
		}
	} else {
		log.Println("AppArmor: unable to read container profile")
	}
}

// readKernelConfigOption searches the kernel config (compressed or plain) for
// the given option key and returns its value along with a boolean indicating
// whether the key was found.
func readKernelConfigOption(key string) (string, bool) {
	// Prefer /proc/config.gz (available when CONFIG_IKCONFIG_PROC=y).
	configGzPath := util.ProcConfigGzPath()
	fd, err := util.StealthOpen(configGzPath, syscall.O_RDONLY)
	if err == nil {
		f := os.NewFile(uintptr(fd), configGzPath)
		defer f.Close()
		if gz, err := gzip.NewReader(f); err == nil {
			defer gz.Close()
			scanner := bufio.NewScanner(gz)
			for scanner.Scan() {
				if val, ok := matchConfigLine(scanner.Text(), key); ok {
					return val, true
				}
			}
			return "", false
		}
	}

	// Fall back to /boot/config-<uname -r>.
	uname, err := util.StealthReadFile(util.ProcSysKernelOsrelease())
	if err != nil {
		return "", false
	}
	configPath := "/boot/config-" + strings.TrimSpace(string(uname))
	fd2, err := util.StealthOpen(configPath, syscall.O_RDONLY)
	if err != nil {
		return "", false
	}
	f2 := os.NewFile(uintptr(fd2), configPath)
	defer f2.Close()
	scanner := bufio.NewScanner(f2)
	for scanner.Scan() {
		if val, ok := matchConfigLine(scanner.Text(), key); ok {
			return val, true
		}
	}
	return "", false
}

// matchConfigLine checks whether a kernel config line sets the given key and
// returns the value (e.g. "y", "m", "n", or a quoted string).
func matchConfigLine(line, key string) (string, bool) {
	// Kernel config lines look like: CONFIG_FOO=y or # CONFIG_FOO is not set
	if strings.HasPrefix(line, key+"=") {
		return strings.TrimPrefix(line, key+"="), true
	}
	if line == "# "+key+" is not set" {
		return "n", true
	}
	return "", false
}

func init() {
	RegisterSimplePrereqCheck(CategorySecurity, "security.namespace_isolation",
		"Check container namespace isolation", []string{"InContainer"}, CheckNamespaceIsolation)
	RegisterSimplePrereqCheck(CategorySecurity, "security.seccomp_status",
		"Check Seccomp status", []string{"InContainer"}, CheckSeccompStatus)
	RegisterSimplePrereqCheck(CategorySecurity, "security.seccomp_support",
		"Check kernel Seccomp support", []string{"InContainer"}, CheckSeccompKernelSupport)
	RegisterSimplePrereqCheck(CategorySecurity, "security.selinux",
		"Check SELinux status", []string{"InContainer"}, CheckSELinux)
	RegisterSimplePrereqCheck(CategorySecurity, "security.apparmor",
		"Check AppArmor status and container profile", []string{"InContainer"}, CheckAppArmor)
}
