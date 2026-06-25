package evaluate

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
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

// ---------- detection stubs (filled in Task 3) ----------
// Each is unexported, side-effects env.* and env.DetectedVia.

func detectInContainer(env *Env)       {}
func detectHasDockerSock(env *Env)     {}
func detectHasContainerdSock(env *Env) {}
func detectHasK8sSA(env *Env)          {}
func detectInClusterDNS(env *Env)      {}
func detectInCloud(env *Env)           {}
func detectCgroupVersions(env *Env)    {}
func detectPrivileged(env *Env)        {}

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
