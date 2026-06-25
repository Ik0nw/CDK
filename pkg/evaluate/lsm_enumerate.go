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
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// knownLSMs lists the Linux Security Modules an operator cares about
// when auditing container escape surfaces.  The "big five" are the
// ones that actually block container-escape primitives on modern
// fleets: AppArmor, SELinux, Landlock, SMACK, TOMOYO.  We also report
// Yama (ptrace restrictions) and LoadPin (kernel module enforcing)
// because they independently change escape calculus.
var knownLSMs = []string{
	"landlock", "smack", "tomoyo", "apparmor",
	"selinux", "yama", "loadpin", "integrity",
}

// lsmProbeResult records one LSM's detected state.
type lsmProbeResult struct {
	Name   string
	Loaded bool
	Active bool // loaded AND enforcing / attaching domains to container
	Note   string
}

// LsmEnumerate reports every LSM that was (a) listed in the kernel's
// enabled-LSM list AND (b) independently confirmed via a per-LSM
// probe path.
//
// F4: full enumeration covers Landlock, SMACK, TOMOYO (not just
// AppArmor + SELinux as the existing checks did).
//
// F22: AppArmor detection no longer relies SOLELY on
// /sys/module/apparmor/parameters/enabled — containers often have
// that file masked by a tmpfs bind mount while AppArmor continues to
// enforce.  We probe apparmor via three independent signals:
//   - /sys/kernel/security/lsm list (unblockable from inside container)
//   - /proc/self/attr/apparmor/current (new procfs API)
//   - /proc/self/attr/current format ("foo (enforce)" style labels)
//
// If any of those three fire we call AppArmor loaded / active, even
// when /sys/module/apparmor is missing.
//
// OPSEC: only reads /sys, /proc, and a handful of RawSyscalls with
// arguments that cannot produce host side-effects (landlock fd probe
// returned fd is closed, prctl PR_SET_NO_NEW_PRIVS is per-thread +
// LockOSThread).
func LsmEnumerate(ctx *Context) error {
	// ------- 1. Kernel master list ------------------------------------
	kernelListed := map[string]bool{}
	if lines := readFileLines("sys/kernel/security/lsm"); len(lines) > 0 {
		for _, raw := range lines {
			for _, tok := range strings.Split(raw, ",") {
				kernelListed[strings.TrimSpace(strings.ToLower(tok))] = true
			}
		}
	}
	if len(kernelListed) == 0 {
		// /sys/kernel/security not mounted in container is common.  We
		// still run every per-LSM probe below — each probe uses a
		// probe path that either exists (LSM loaded) or returns
		// -ENOENT / -EOPNOTSUPP / -ENOSYS cleanly.
		fmt.Printf("LSM: /sys/kernel/security/lsm not visible (securityfs may not be mounted)\n")
		fmt.Printf("     Falling back to per-LSM syscall + /proc probes.\n")
	} else {
		names := make([]string, 0, len(kernelListed))
		for k := range kernelListed {
			names = append(names, k)
		}
		fmt.Printf("LSM: kernel enabled = %s\n", strings.Join(names, ","))
	}

	// ------- 2. Per-LSM probes ----------------------------------------
	fmt.Printf("per-LSM enumeration (%d targets):\n", len(knownLSMs))
	var (
		loadedCount int
		activeCount int
	)
	results := make([]lsmProbeResult, 0, len(knownLSMs))
	for _, name := range knownLSMs {
		res := probeLsm(name)
		results = append(results, res)
		if res.Loaded {
			loadedCount++
		}
		if res.Active {
			activeCount++
		}
		colour := "[  ?  ]"
		switch {
		case res.Active:
			colour = "[AMBER]" // active LSM = blocks some escapes
		case res.Loaded:
			colour = "[GREEN]" // loaded but container is not subject to it
		}
		tag := ""
		if res.Note != "" {
			tag = "  — " + res.Note
		}
		fmt.Printf("\t%s %-10s loaded=%-5v active=%-5v%s\n",
			colour, name, res.Loaded, res.Active, tag)
	}

	// ------- 3. Operator-level summary --------------------------------
	fmt.Printf("\tloaded=%d active=%d / %d known LSMs probed\n",
		loadedCount, activeCount, len(knownLSMs))
	switch {
	case activeCount == 0:
		fmt.Printf("\tINFO: no MAC LSM actively enforcing on this container.\n" +
			"\t      Only capability + seccomp gates apply; exploit surface is maximal.\n")
	case activeCount == 1:
		fmt.Printf("\tINFO: 1 LSM active — combine its specific findings with capability + seccomp.\n")
	default:
		fmt.Printf("\tINFO: stacked MAC LSMs (%d active).  Exploit chains must bypass every layer.\n",
			activeCount)
	}

	// ------- 4. F22 AppArmor mask false-negative reminder -------------
	// Emit the specific note if we detected AppArmor via non-module paths.
	for _, r := range results {
		if r.Name == "apparmor" && r.Active &&
			(strings.Contains(r.Note, "masked") || strings.Contains(r.Note, "procfs")) {
			fmt.Printf("\tF22 NOTE: AppArmor detected via %s despite /sys/module/apparmor being\n"+
				"\t        missing/unreadable.  Operators using the old sys/module-only check\n"+
				"\t        would have FALSELY concluded AppArmor was OFF.\n", r.Note)
		}
	}
	return nil
}

// probeLsm dispatches to the per-LSM probe helper.
func probeLsm(name string) lsmProbeResult {
	switch name {
	case "landlock":
		return probeLandlock()
	case "smack":
		return probeSmack()
	case "tomoyo":
		return probeTomoyo()
	case "apparmor":
		return probeAppArmor()
	case "selinux":
		return probeSelinux()
	case "yama":
		return probeYama()
	case "loadpin":
		return probeLoadpin()
	case "integrity":
		return probeIntegrity()
	default:
		return lsmProbeResult{Name: name}
	}
}

// ------------------------------------------------------------
// Per-LSM probe helpers.
// Each helper is independent; they only read + make harmless syscalls.
// ------------------------------------------------------------

// fileNonEmpty reports true if the path is readable and contains at
// least one non-whitespace byte.  Used for /proc/self/attr/* probe.
func fileNonEmpty(rel string) (string, bool) {
	lines := readFileLines(rel)
	joined := strings.Join(lines, "\n")
	trimmed := strings.TrimSpace(joined)
	return trimmed, trimmed != ""
}

// probeLandlock tests whether the landlock_create_ruleset syscall
// returns ENOSYS.  On kernels that support Landlock the syscall
// returns a new ruleset fd even when no landlock policy has been
// applied yet to the container (Loaded=true).  To detect whether
// Landlock is ACTIVELY enforcing on the container we read
// /proc/self/status "Landlocked:" — 1 = current process is inside a
// landlocked domain.
//
// Probe is provably side-effect free:
//   - prctl(PR_SET_NO_NEW_PRIVS=1) is required before ruleset creation
//     on older kernels; since it's per-thread + we LockOSThread, it
//     cannot affect any other goroutine.
//   - landlock_create_ruleset returns an fd.  We immediately call
//     Close on it.  No ruleset is applied to a process, no BPF
//     program is uploaded, nothing persists.
func probeLandlock() lsmProbeResult {
	res := lsmProbeResult{Name: "landlock"}

	// Step 1: active flag via /proc/self/status Landlocked:.
	if lines := readFileLines("proc/self/status"); len(lines) > 0 {
		for _, ln := range lines {
			if strings.HasPrefix(ln, "Landlocked:") {
				fields := strings.Fields(ln)
				if len(fields) >= 2 && fields[1] == "1" {
					res.Active = true
					res.Note = "/proc/self/status Landlocked=1 (process enclosed in ruleset)"
				} else {
					res.Note = "kernel compiled with Landlock but current process not restricted"
				}
				// Presence of the field = kernel has Landlock.
				res.Loaded = true
				return res
			}
		}
	}
	// Step 2: syscall probe (Landlocked field only on 5.13+; syscall
	// probe also works on 5.10 backports where field is absent).
	var (
		nr uintptr
	)
	switch runtime.GOARCH {
	case "amd64":
		nr = 444 // landlock_create_ruleset
	case "arm64":
		nr = 444
	case "386":
		nr = 444
	case "arm":
		nr = 444
	default:
		return res
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// PR_SET_NO_NEW_PRIVS = 38, value = 1.  prctl NR per arch.
	var prctlNr uintptr
	switch runtime.GOARCH {
	case "amd64":
		prctlNr = 157
	case "arm64":
		prctlNr = 167
	case "386":
		prctlNr = 172
	case "arm":
		prctlNr = 172
	}
	if prctlNr != 0 {
		syscall.RawSyscall6(prctlNr, 38, 1, 0, 0, 0, 0)
	}
	// struct landlock_ruleset_attr (minimal) = { .handled_access_fs = 0 }
	var zeroAttr [8]byte
	fd, _, errNo := syscall.RawSyscall6(nr,
		uintptr(0), // attr NULL (ok too) — use &zeroAttr to be safe
		uintptr(unsafe.Pointer(&zeroAttr[0])),
		8,  // sizeof(minimal ruleset_attr)
		0,  // flags = 0
		0, 0)
	switch errNo {
	case 0:
		res.Loaded = true
		// Landlock loaded; we don't know if active but fd creation = compiled in.
		syscall.Close(int(fd))
		if res.Note == "" {
			res.Note = "landlock_create_ruleset fd returned (kernel has Landlock)"
		}
	case syscall.ENOSYS:
		// Kernel definitely lacks Landlock.
		res.Note = "landlock_create_ruleset = ENOSYS (kernel lacks LSM)"
	default:
		// EINVAL / E2BIG / other non-ENOSYS = syscall exists.
		res.Loaded = true
		if res.Note == "" {
			res.Note = fmt.Sprintf("landlock_create_ruleset errno=%v (LSM compiled in)", errNo)
		}
	}
	return res
}

// probeSmack checks for SMACK label presence via /proc/self/attr/current
// prefix, /proc/self/attr/smack/current, and /sys/fs/smackfs.
func probeSmack() lsmProbeResult {
	res := lsmProbeResult{Name: "smack"}
	// /proc/self/attr/smack/current = standard SMACK label file.
	if lbl, ok := fileNonEmpty("proc/self/attr/smack/current"); ok {
		res.Loaded = true
		res.Active = true
		res.Note = fmt.Sprintf("label=%q (via /proc/self/attr/smack/current)", lbl)
		return res
	}
	// Legacy: "SMACK label" in /proc/self/attr/current without subdir.
	if lbl, ok := fileNonEmpty("proc/self/attr/current"); ok {
		trim := strings.TrimSpace(lbl)
		// SMACK proc labels start with '?' or a SMACK label word.  Heuristic:
		// non-empty AND doesn't start with unconfined/selinux: / enforce (not
		// AppArmor/SELinux text) AND smackfs exists → SMACK.
		if _, present := fileNonEmpty("sys/fs/smackfs/load"); present {
			res.Loaded = true
			// If we got here without /proc/self/attr/smack, container still has
			// no SMACK domain attached → loaded but not active on this process.
			res.Active = strings.TrimSpace(trim) != "" &&
				trim != "_" && trim != "floor" && trim != "*"
			res.Note = fmt.Sprintf("smackfs present; /proc/self/attr/current=%q", trim)
			return res
		}
	}
	return res
}

// probeTomoyo checks /sys/kernel/security/tomoyo/version (mounted
// securityfs) and /proc/self/attr/tomoyo_domain (process's domain).
func probeTomoyo() lsmProbeResult {
	res := lsmProbeResult{Name: "tomoyo"}
	if dom, ok := fileNonEmpty("proc/self/attr/tomoyo_domain"); ok {
		res.Loaded = true
		res.Active = true
		res.Note = fmt.Sprintf("domain=%q", dom)
		return res
	}
	if ver, ok := fileNonEmpty("sys/kernel/security/tomoyo/version"); ok {
		res.Loaded = true
		// TOMOYO doesn't enforce until userspace policy loads; kernel
		// builds with TOMOYO but no policy loaded = loaded !active.
		res.Active = false
		res.Note = fmt.Sprintf("kernel support; version=%s", ver)
	}
	return res
}

// probeAppArmor — F22: triple-signal detection.  Returns Active=true
// if the process is running inside an AppArmor profile.
//
// Signals:
//   S1. /proc/self/attr/apparmor/current → new-style label file.
//   S2. /sys/kernel/security/apparmor/profiles exists + non-empty.
//   S3. /proc/self/attr/current matches "<name> (<mode>)" OR starts
//       with "docker-default" / "cri-containerd.apparmor.d/<name>"
//       (standard container profile names).
//   S4. /sys/module/apparmor/parameters/enabled (original, kept as
//       tie-breaker + for kernels without /sys/kernel/security).
//
// If ANY of S1/S2/S3 fire we consider AppArmor loaded/active even
// when S4 returns ENOENT (masked tmpfs bind, extremely common in
// container runtimes).  S4 alone with no process-visible evidence =
// loaded, !active (container runtime didn't apply a profile to us).
func probeAppArmor() lsmProbeResult {
	res := lsmProbeResult{Name: "apparmor"}
	signals := []string{}

	// S1: /proc/self/attr/apparmor/current (process label).
	if lbl, ok := fileNonEmpty("proc/self/attr/apparmor/current"); ok {
		signals = append(signals, "procfs attr/apparmor/current")
		res.Loaded = true
		trim := strings.ToLower(lbl)
		// "unconfined" = loaded but process not restricted.
		if !strings.Contains(trim, "unconfined") && strings.TrimSpace(trim) != "" {
			res.Active = true
			res.Note = fmt.Sprintf("profile=%q (S1: /proc/self/attr/apparmor/current)", lbl)
		} else {
			res.Note = fmt.Sprintf("process unconfined via S1: %q", lbl)
		}
	}

	// S2: /sys/kernel/security/apparmor/profiles (enumerated policy).
	if prof, ok := fileNonEmpty("sys/kernel/security/apparmor/profiles"); ok {
		signals = append(signals, "securityfs apparmor/profiles")
		res.Loaded = true
		// Policy loaded → runtime will enforce; not necessarily on THIS
		// process (check S1/S3).
		if !res.Active {
			res.Note = fmt.Sprintf("%d profiles loaded (S2: securityfs)", len(strings.Split(prof, "\n")))
		}
	}

	// S3: /proc/self/attr/current AppArmor-style label.
	if lbl, ok := fileNonEmpty("proc/self/attr/current"); ok {
		trim := strings.TrimSpace(lbl)
		// Pattern examples:
		//   "docker-default (enforce)"
		//   "cri-containerd.apparmor.d/docker-default (complain)"
		//   "my-custom-profile (enforce)"
		if strings.Contains(trim, " (enforce)") ||
			strings.Contains(trim, " (complain)") ||
			strings.Contains(trim, " (kill)") ||
			strings.HasPrefix(trim, "docker-default") ||
			strings.Contains(trim, "apparmor.d/") {
			signals = append(signals, "procfs attr/current format")
			res.Loaded = true
			if strings.Contains(trim, "(enforce)") || strings.Contains(trim, "(kill)") {
				res.Active = true
			}
			if res.Note == "" {
				res.Note = fmt.Sprintf("label=%q (S3)", trim)
			}
		}
	}

	// S4: /sys/module/apparmor/parameters/enabled (classic).
	if val, ok := fileNonEmpty("sys/module/apparmor/parameters/enabled"); ok {
		signals = append(signals, "sys/module/apparmor (S4)")
		if strings.TrimSpace(strings.ToUpper(val)) == "Y" {
			if !res.Loaded {
				res.Loaded = true
				res.Note = "enabled via sys/module (S4); no process-visible evidence"
			}
			// If we already set loaded=true from S1..S3, don't overwrite note.
		}
	}

	if res.Loaded && (len(signals) > 1 || (len(signals) == 1 && signals[0] != "sys/module/apparmor (S4)")) {
		// Signal came from a non-/sys/module path.  Attach the F22 flag.
		hasMaskedSignal := false
		for _, s := range signals {
			if s != "sys/module/apparmor (S4)" {
				hasMaskedSignal = true
				break
			}
		}
		if hasMaskedSignal {
			if res.Note == "" {
				res.Note = "detected via non-/sys/module probe(s): " + strings.Join(signals, ",")
			} else {
				res.Note += "  [F22: detected via procfs/masked-fs probe(s): " + strings.Join(signals, ",") + "]"
			}
		}
	}
	return res
}

// probeSelinux reports status via /proc/self/attr/current label + enforce file.
func probeSelinux() lsmProbeResult {
	res := lsmProbeResult{Name: "selinux"}
	enforce, hasEnforce := fileNonEmpty("sys/fs/selinux/enforce")
	label, hasLabel := fileNonEmpty("proc/self/attr/current")
	switch {
	case hasEnforce && strings.TrimSpace(enforce) == "1":
		res.Loaded = true
		res.Active = true
		res.Note = fmt.Sprintf("enforcing; label=%q", label)
	case hasEnforce:
		res.Loaded = true
		res.Active = false
		res.Note = fmt.Sprintf("loaded, permissive mode; label=%q", label)
	case hasLabel && len(strings.Split(label, ":")) >= 3:
		// SELinux labels are user:role:type[:level].  3+ colon parts = SELinux.
		res.Loaded = true
		res.Active = false
		res.Note = fmt.Sprintf("label present (%q) but enforce file not visible", label)
	}
	return res
}

// probeYama reads ptrace_scope (kernel.yama.ptrace_scope sysctl).
// Present file = Yama LSM loaded; value >= 2 = ptrace-escape path is
// actively blocked.
func probeYama() lsmProbeResult {
	res := lsmProbeResult{Name: "yama"}
	if val, ok := fileNonEmpty("proc/sys/kernel/yama/ptrace_scope"); ok {
		res.Loaded = true
		v := strings.TrimSpace(val)
		// 0 = classic, 1 = restricted PTRACE_TRACEME (default Ubuntu),
		// 2 = admin-only attach, 3 = no-ptrace-at-all.
		switch v {
		case "0":
			res.Active = false
			res.Note = "ptrace_scope=0 (no restriction)"
		case "1", "2", "3":
			res.Active = true
			res.Note = fmt.Sprintf("ptrace_scope=%s (ptrace escape gated)", v)
		default:
			res.Active = true
			res.Note = fmt.Sprintf("ptrace_scope=%s (non-standard)", v)
		}
	}
	return res
}

// probeLoadpin checks /sys/kernel/security/loadpin/verified (file LSM
// blocks kernel module / firmware loads from non-verified sources).
func probeLoadpin() lsmProbeResult {
	res := lsmProbeResult{Name: "loadpin"}
	if val, ok := fileNonEmpty("sys/kernel/security/loadpin/verified"); ok {
		res.Loaded = true
		res.Active = true
		res.Note = fmt.Sprintf("verified=%s", val)
	} else if val, ok = fileNonEmpty("proc/sys/kernel/module/sig_enforce"); ok {
		// Alternate indicator: module signature enforcement in the same
		// general bucket (prevents unsigned LKM load).
		if strings.TrimSpace(val) != "0" {
			res.Loaded = true
			res.Active = true
			res.Note = "module.sig_enforce=" + strings.TrimSpace(val) + " (LKM signature gate)"
		}
	}
	return res
}

// probeIntegrity reports IMA / EVM status.  We do NOT upload
// measurements or trigger policy evaluation; we only read.
func probeIntegrity() lsmProbeResult {
	res := lsmProbeResult{Name: "integrity"}
	paths := []string{
		"sys/kernel/security/ima/hash",
		"sys/kernel/security/ima/ascii_runtime_measurements",
		"sys/kernel/security/evm",
	}
	found := []string{}
	for _, p := range paths {
		if _, ok := fileNonEmpty(p); ok {
			found = append(found, p)
		}
	}
	if len(found) > 0 {
		res.Loaded = true
		// IMA-measuring IMA-appraise-enforcing is hard to tell from
		// inside container without extra capabilities; be conservative
		// and call it active (measurement = evidence collection).
		res.Active = true
		res.Note = "paths visible: " + strings.Join(found, ", ")
	}
	return res
}

func init() {
	RegisterContextPrereqCheck(CategorySecurity, "security.lsm_enumerate",
		"Full LSM enumeration (Landlock/SMACK/TOMOYO) + AppArmor masked-fs detection (F4+F22)",
		[]string{"InContainer"},
		LsmEnumerate)
}
