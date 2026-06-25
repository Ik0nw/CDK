package evaluate

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Env holds the results of a single local-only environment preflight pass.
// Every field defaults to false; DetectEnv only flips flags when it finds
// positive local evidence.  File read failures never panic — they just
// leave the corresponding flag false.
type Env struct {
	InContainer       bool
	HasDockerSock     bool
	HasContainerdSock bool
	HasK8sSA          bool
	InClusterDNS      bool
	InCloud           bool
	HasCgroupV1       bool
	HasCgroupV2       bool
	Privileged        bool

	// CloudVendor is non-empty only when InCloud=true and a specific vendor
	// was identified.  Values: "aws" | "gcp" | "azure" | "aliyun" | "tencent"
	// | "huawei" | "volcengine/byteplus".
	CloudVendor string

	// DetectedVia records, for each flag that was flipped true, a short
	// human-readable note describing which piece of evidence triggered it.
	// Keyed by the same camelCase flag names used by Prereqs.
	DetectedVia map[string]string
}

// flagByName maps Prereq strings (as written in Check.Prereqs) to predicates
// over *Env.  Unknown names in MissingPrereqs are treated as "missing"
// (fail-closed).
var flagByName = map[string]func(*Env) bool{
	"InContainer":       func(e *Env) bool { return e.InContainer },
	"HasDockerSock":     func(e *Env) bool { return e.HasDockerSock },
	"HasContainerdSock": func(e *Env) bool { return e.HasContainerdSock },
	"HasK8sSA":          func(e *Env) bool { return e.HasK8sSA },
	"InClusterDNS":      func(e *Env) bool { return e.InClusterDNS },
	"InCloud":           func(e *Env) bool { return e.InCloud },
	"HasCgroupV1":       func(e *Env) bool { return e.HasCgroupV1 },
	"HasCgroupV2":       func(e *Env) bool { return e.HasCgroupV2 },
	"Privileged":        func(e *Env) bool { return e.Privileged },
}

// envRoot is the filesystem root used by all detection helpers.  It
// defaults to "/" but can be overridden in tests via overrideEnvRoot.
// This lets us test against fixture fake-procfs / fake-sysfs without
// touching the real host.
var envRoot = "/"

// DetectEnv runs the entire preflight suite exactly once.  Callers should
// cache the return value.  Never returns nil; all file I/O errors yield
// false on the corresponding flag.  No network, no shell execution.
func DetectEnv() *Env {
	env := &Env{DetectedVia: make(map[string]string)}
	// Detection order is significant: cheaper / more definitive flags first.
	detectInContainer(env)
	detectHasDockerSock(env)
	detectHasContainerdSock(env)
	detectHasK8sSA(env)
	detectInClusterDNS(env)
	detectInCloud(env) // sets both InCloud and CloudVendor
	detectCgroupVersions(env)
	detectPrivileged(env)
	return env
}

// MissingPrereqs returns the subset of prereqs whose names are unknown OR
// whose corresponding Env flag is false.  An empty/nil prereq list yields
// an empty/nil result (check runs unconditionally).
//
// Unknown flag names are treated as "missing" (fail-closed) and logged.
func MissingPrereqs(env *Env, prereqs []string) []string {
	if len(prereqs) == 0 {
		return nil
	}
	if env == nil {
		return append([]string(nil), prereqs...)
	}
	var missing []string
	for _, p := range prereqs {
		pred, ok := flagByName[p]
		if !ok {
			// Unknown prereq: fail-closed + stderr warning via caller's
			// logger; here we append so caller can surface it.
			missing = append(missing, p+"?") // trailing ? means unknown
			continue
		}
		if !pred(env) {
			missing = append(missing, p)
		}
	}
	return missing
}

// ---------- detection functions ----------
// Each is unexported, side-effects env.* and env.DetectedVia.

// detectInContainer uses several well-known markers.  Order of checks
// follows the spec; first match short-circuits and records how it was
// detected.
func detectInContainer(env *Env) {
	// 1. /.dockerenv (Docker, containerd, Moby)
	if fileExists(".dockerenv") {
		env.InContainer = true
		setVia(env, "InContainer", "/.dockerenv exists")
		return
	}
	// 2. /run/.containerenv (Podman, libpod)
	if fileExists("run/.containerenv") {
		env.InContainer = true
		setVia(env, "InContainer", "/run/.containerenv exists")
		return
	}
	// 3. /proc/1/cgroup contains container-specific tokens
	for _, line := range readFileLines("proc/1/cgroup") {
		lower := strings.ToLower(line)
		for _, tok := range []string{"docker", "containerd", "kubepods", "lxc",
			"systemd/docker", "cri-containerd", "podman"} {
			if strings.Contains(lower, tok) {
				env.InContainer = true
				fmtVia(env, "InContainer", "/proc/1/cgroup contains %q", tok)
				return
			}
		}
	}
	// 4. /proc/1/sched first line: PID (in host ns) != 1
	line := readFileFirstLine("proc/1/sched")
	if line == "" {
		return
	}
	// sched format: "comm (pid, #threads: N)\nrest"
	re := regexp.MustCompile(`^[^(]+\((\d+),`)
	m := re.FindStringSubmatch(line)
	if len(m) >= 2 {
		pid, err := strconv.Atoi(m[1])
		if err == nil && pid != 1 {
			env.InContainer = true
			fmtVia(env, "InContainer", "/proc/1/sched host pid=%d != 1", pid)
		}
	}
}

func detectHasDockerSock(env *Env) {
	// Primary: /var/run/docker.sock is a socket.
	path := filepath.Join(envRoot, "var/run/docker.sock")
	if fi, err := os.Stat(path); err == nil && (fi.Mode()&os.ModeSocket) != 0 {
		env.HasDockerSock = true
		setVia(env, "HasDockerSock", "/var/run/docker.sock is a socket")
		return
	}
	// Secondary: DOCKER_HOST env var pointing at a unix socket.
	dh := os.Getenv("DOCKER_HOST")
	if strings.HasPrefix(dh, "unix://") {
		sockPath := strings.TrimPrefix(dh, "unix://")
		// DOCKER_HOST is resolved in the *host* namespace, not under
		// envRoot (envRoot only affects /proc/sys/etc reads).  So stat it
		// directly.
		if fi, err := os.Stat(sockPath); err == nil && (fi.Mode()&os.ModeSocket) != 0 {
			env.HasDockerSock = true
			fmtVia(env, "HasDockerSock", "DOCKER_HOST=unix://… socket at %q", sockPath)
		}
	}
}

var containerdShimAbstractRe = regexp.MustCompile(`@/containerd-shim/[^ ]+shim\.sock`)

func detectHasContainerdSock(env *Env) {
	// 1. Plain socket: /run/containerd/containerd.sock
	path := filepath.Join(envRoot, "run/containerd/containerd.sock")
	if fi, err := os.Stat(path); err == nil && (fi.Mode()&os.ModeSocket) != 0 {
		env.HasContainerdSock = true
		setVia(env, "HasContainerdSock", "/run/containerd/containerd.sock exists")
		return
	}
	// 2. Abstract socket (@/containerd-shim/…/shim.sock) via /proc/net/unix.
	for _, line := range readFileLines("proc/net/unix") {
		if containerdShimAbstractRe.MatchString(line) {
			env.HasContainerdSock = true
			setVia(env, "HasContainerdSock", "abstract containerd-shim socket seen in /proc/net/unix")
			return
		}
	}
}

func detectHasK8sSA(env *Env) {
	tokenPath := filepath.Join(envRoot,
		"var/run/secrets/kubernetes.io/serviceaccount/token")
	fi, err := os.Stat(tokenPath)
	if err == nil && fi.Size() > 0 {
		env.HasK8sSA = true
		fmtVia(env, "HasK8sSA", "SA token exists (%d bytes)", fi.Size())
	}
}

// kubeDNSRange is the standard K8s service subnet for CoreDNS.
var kubeDNSRange = &net.IPNet{
	IP:   net.IPv4(10, 96, 0, 0),
	Mask: net.CIDRMask(12, 32), // 10.96.0.0/12
}

func detectInClusterDNS(env *Env) {
	lines := readFileLines("etc/resolv.conf")
	for _, line := range lines {
		// Strip inline comments.
		if idx := strings.IndexAny(line, ";#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "search ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "search"))
			for _, dom := range strings.Fields(rest) {
				if dom == "svc.cluster.local" ||
					strings.HasSuffix(dom, ".svc.cluster.local") ||
					strings.Contains(dom, "svc.cluster.local") {
					env.InClusterDNS = true
					fmtVia(env, "InClusterDNS", "search domain %q", dom)
					return
				}
			}
		}
		if strings.HasPrefix(line, "nameserver ") {
			ipStr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver"))
			fields := strings.Fields(ipStr)
			if len(fields) > 0 {
				ip := net.ParseIP(fields[0])
				if ip != nil && kubeDNSRange.Contains(ip) {
					env.InClusterDNS = true
					fmtVia(env, "InClusterDNS", "nameserver %s falls in 10.96.0.0/12", fields[0])
					return
				}
			}
		}
	}
}

type vendorRule struct {
	name string
	pred func(vendorFiles map[string]string) bool
}

// detectInCloud consults DMI + cloud-init files and sets env.InCloud
// and env.CloudVendor when a specific vendor is confidently identified.
// Vendor rules are checked in ORDER: Volcengine must beat generic ECS
// heuristics used by Aliyun/AWS.
func detectInCloud(env *Env) {
	files := vendorFiles(envRoot)
	rules := []vendorRule{
		{"volcengine/byteplus", func(f map[string]string) bool {
			sv := strings.ToLower(f["sys_vendor"])
			pn := strings.ToLower(f["product_name"])
			ds := strings.ToLower(f["cloud_datasource"])
			hn, _ := os.Hostname()
			hnl := strings.ToLower(hn)
			// Rule 1: sys_vendor literally volcengine / bytedance
			if strings.Contains(sv, "volcengine") || strings.Contains(sv, "bytedance") {
				return true
			}
			// Rule 2: product_name byteplus + hostname iv-*/v-*
			if strings.Contains(pn, "byteplus") &&
				(strings.HasPrefix(hnl, "iv-") || strings.HasPrefix(hnl, "v-")) {
				return true
			}
			// Rule 3: cloud-init datasource mentions volc/byteplus
			if strings.Contains(ds, "volc") || strings.Contains(ds, "byteplus") {
				return true
			}
			return false
		}},
		{"aliyun", func(f map[string]string) bool {
			sv := strings.ToLower(f["sys_vendor"])
			tag := strings.ToLower(f["chassis_asset_tag"])
			return strings.Contains(sv, "alibaba cloud") ||
				strings.Contains(sv, "aliyun") ||
				strings.HasPrefix(tag, "alibaba-") ||
				strings.HasPrefix(tag, "aliyun-")
		}},
		{"aws", func(f map[string]string) bool {
			puuid := strings.ToLower(f["product_uuid"])
			bv := strings.ToLower(f["bios_vendor"])
			ds := strings.ToLower(f["cloud_datasource"])
			return strings.HasPrefix(puuid, "ec2") ||
				strings.Contains(bv, "amazon ec2") ||
				strings.Contains(ds, "datasourceec2")
		}},
		{"gcp", func(f map[string]string) bool {
			pn := strings.ToLower(f["product_name"])
			bv := strings.ToLower(f["bios_vendor"])
			return strings.Contains(pn, "google compute engine") ||
				strings.Contains(bv, "google")
		}},
		{"azure", func(f map[string]string) bool {
			tag := f["chassis_asset_tag"]
			sv := strings.ToLower(f["sys_vendor"])
			pn := strings.ToLower(f["product_name"])
			if tag == "7783-7084-3265-9085-8269-3286-77" {
				return true
			}
			if strings.Contains(sv, "microsoft") && strings.Contains(pn, "virtual machine") {
				return true
			}
			return false
		}},
		{"tencent", func(f map[string]string) bool {
			return strings.Contains(strings.ToLower(f["sys_vendor"]), "tencent")
		}},
		{"huawei", func(f map[string]string) bool {
			return strings.Contains(strings.ToLower(f["sys_vendor"]), "huawei")
		}},
	}
	for _, r := range rules {
		if r.pred(files) {
			env.InCloud = true
			env.CloudVendor = r.name
			fmtVia(env, "InCloud", "vendor=%s matched via DMI/cloud-init", r.name)
			return
		}
	}
}

// vendorFiles reads every DMI + cloud-init file we use, once, into a map.
// Missing files yield "".  Keyed by short name (not full path).
// NOTE: the root parameter is accepted for API consistency but paths are
// resolved by readFileFirstLine which already prepends the package-level
// envRoot internally.
func vendorFiles(root string) map[string]string {
	r := map[string]string{}
	m := map[string]string{
		"sys_vendor":        "sys/class/dmi/id/sys_vendor",
		"product_name":      "sys/class/dmi/id/product_name",
		"product_uuid":      "sys/class/dmi/id/product_uuid",
		"product_version":   "sys/class/dmi/id/product_version",
		"chassis_asset_tag": "sys/class/dmi/id/chassis_asset_tag",
		"bios_vendor":       "sys/class/dmi/id/bios_vendor",
		"board_vendor":      "sys/class/dmi/id/board_vendor",
		"cloud_datasource":  "var/lib/cloud/instance/datasource",
	}
	for key, path := range m {
		r[key] = readFileFirstLine(path)
	}
	return r
}

func detectCgroupVersions(env *Env) {
	if fileExists("sys/fs/cgroup/cgroup.controllers") {
		env.HasCgroupV2 = true
		setVia(env, "HasCgroupV2", "/sys/fs/cgroup/cgroup.controllers present")
	}
	// v1 requires: no cgroup.controllers file AND /proc/self/cgroup shows
	// v1 hierarchical lines.
	if !env.HasCgroupV2 {
		v1Hierarchies := []string{"devices:/", "memory:/", "cpu:/", "cpuset:/",
			"blkio:/", "hugetlb:/", "perf_event:/", "freezer:/", "net_cls:/",
			"pids:/", "rdma:/"}
		for _, line := range readFileLines("proc/self/cgroup") {
			for _, h := range v1Hierarchies {
				if strings.Contains(line, h) {
					env.HasCgroupV1 = true
					fmtVia(env, "HasCgroupV1", "v1 hierarchy %q present in /proc/self/cgroup", h)
					return
				}
			}
		}
	}
}

// allCaps is CapEff = 0000003fffffffff (40 capability bits, Linux 6.4+).
// The legacy 38-bit full mask 0000003fffffffff also matches; we simply
// parse numerically and check that the low 40 bits are all 1.
const allCapBits uint64 = 0x0000003fffffffff

func detectPrivileged(env *Env) {
	var capEff string
	var seccomp string
	for _, line := range readFileLines("proc/self/status") {
		if strings.HasPrefix(line, "CapEff:") {
			capEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		} else if strings.HasPrefix(line, "Seccomp:") {
			seccomp = strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
		}
	}
	if capEff != "" {
		v, err := strconv.ParseUint(capEff, 16, 64)
		if err == nil && (v&allCapBits) == allCapBits {
			env.Privileged = true
			fmtVia(env, "Privileged", "CapEff=%s (all 40 bits set)", capEff)
			return
		}
	}
	// Fallback: Seccomp==0 means no seccomp filter applied — highly
	// correlated with privileged mode on container runtimes.
	if seccomp == "0" {
		// Do NOT set the flag on bare-metal (Seccomp 0 is normal there).
		// Only consider it meaningful inside a container context.
		if env.InContainer {
			env.Privileged = true
			setVia(env, "Privileged", "Seccomp: 0 within container")
		}
	}
}

// ---------- shared file-read helpers ----------

// fileExists returns true only when path exists and is stat-able with no
// special permission requirements.  Errors → false, never panics.
func fileExists(path string) bool {
	_, err := os.Stat(filepath.Join(envRoot, path))
	return err == nil
}

// readFileLines reads path and returns its trimmed, non-empty lines.  On
// any error returns nil.
func readFileLines(path string) []string {
	f, err := os.Open(filepath.Join(envRoot, path))
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" {
			lines = append(lines, t)
		}
	}
	return lines
}

// readFileFirstLine returns line 1 of path, or "" on any failure.
func readFileFirstLine(path string) string {
	lines := readFileLines(path)
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// setVia records env.DetectedVia[flag] = note and is a thin helper to keep
// detection functions concise.
func setVia(env *Env, flag, note string) {
	if env.DetectedVia == nil {
		env.DetectedVia = make(map[string]string)
	}
	if _, ok := env.DetectedVia[flag]; !ok {
		env.DetectedVia[flag] = note
	}
}

// fmtVia is a fmt.Sprintf variant of setVia.
func fmtVia(env *Env, flag, format string, a ...interface{}) {
	setVia(env, flag, fmt.Sprintf(format, a...))
}
