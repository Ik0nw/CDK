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
	"io/ioutil"
	"os"
	"strings"
)

// T52: security.apparmor_deep — AppArmor LSM state + per-process profile
// + enforce/complain mode.
//
// Answers the attacker question: "Is my process actually confined by
// AppArmor? Which profile? Is it a generic container profile
// (docker-default) or an unconfined equivalent? Is AppArmor in ENFORCE
// vs COMPLAIN mode? Is the LSM compiled in but disabled at boot?"
//
// lsm_enumerate only reports a coarse loaded/active boolean for AppArmor
// (and works around the F22 masking of /sys/module/apparmor).  This deep
// check exposes the per-process label + per-profile mode — the fields an
// attacker actually needs to decide whether an AppArmor-gated escape is
// worth attempting.
//
// Probes (ALL file reads, zero syscalls, zero side-effects):
//   1. /sys/module/apparmor/parameters/enabled — "Y"/"N" single char;
//      whether kernel AppArmor is active.  Frequently masked by a tmpfs
//      bind mount in containers (F22), so absence ≠ disabled.
//   2. /sys/kernel/security/apparmor/profiles — loaded profiles list, one
//      per line as "name (mode)" where mode ∈ enforce/complain/kill/audit.
//      We count profiles + flag container-shaped names.
//   3. /proc/self/attr/apparmor/current — profile applied to THIS process
//      (the critical field).  "unconfined" → not confined.  Existence of
//      this file proves AppArmor is the active LSM.
//   4. /proc/self/attr/current — fallback when the apparmor-specific attr
//      file is absent (AppArmor disabled).  Only trusted when its content
//      is AppArmor-shaped ("name (enforce|complain|kill)" or a known
//      container profile prefix); otherwise it may carry a SELinux label.
//
// Verdict (strict 宁漏勿flag — no false [GREEN] weak-isolation claims):
//   [AMBER] ISOLATED when the authoritative per-process attr file shows a
//           real profile in enforce/kill mode.  The apparmor-specific attr
//           file is ground truth for THIS process (its mere existence
//           proves AppArmor active), so a real enforce label alone
//           suffices.  Liberal AMBER is the safe direction under
//           宁漏勿flag: a false ISOLATED only causes the attacker to
//           deprioritize an actually-open target (a miss, tolerated).
//   [GREEN] NOT confined (weak isolation — the DANGEROUS direction) is
//           claimed only with corroboration: enabled=Y AND (unconfined OR
//           complain mode).  Without enabled=Y (or the apparmor-specific
//           attr file proving AppArmor active) we never claim [GREEN].
//   [  ?  ] AMBIGUOUS for everything else (compiled out / disabled at boot
//           / attr unreadable / fallback label without corroboration).

func appArmorOut() *os.File { return os.Stdout }

// readAAFile returns the trimmed contents of path, or "" on any error.
func readAAFile(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parseAAProfileLine splits an AppArmor profiles-file line of the form
// "profile_name (mode)" (with optional trailing flags) into name + mode.
// Lines without a "(mode)" token return the trimmed line as name and an
// empty mode.  A name of "" means an empty/blank line.
func parseAAProfileLine(line string) (name, mode string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	idx := strings.Index(line, " (")
	if idx < 0 {
		return line, ""
	}
	name = strings.TrimSpace(line[:idx])
	rest := line[idx+2:] // begins with "mode...)"
	// mode is the token up to the first ")".
	if end := strings.Index(rest, ")"); end >= 0 {
		mode = strings.TrimSpace(rest[:end])
	} else {
		mode = strings.TrimSpace(rest)
	}
	return name, mode
}

// containerAAProfileMatch reports whether a profile name looks like a
// standard container-runtime AppArmor profile (the ones an attacker most
// cares about, since they are generic and well-studied for gaps).
func containerAAProfileMatch(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return false
	}
	return strings.Contains(n, "docker-default") ||
		strings.Contains(n, "cri-containerd") ||
		strings.Contains(n, "containerd-") ||
		strings.Contains(n, "containerd.apparmor.d") ||
		strings.HasPrefix(n, "kubernetes-") ||
		strings.HasPrefix(n, "k8s-")
}

// selfAALabel reads the AppArmor profile label applied to the current
// process.  It prefers the apparmor-specific attr file (whose existence
// proves AppArmor is the active LSM) and falls back to the generic
// /proc/self/attr/current only when its content is AppArmor-shaped.
//
// Returns (label, mode, source) where source is "apparmor/current",
// "attr/current", or "" (no usable label).
func selfAALabel() (label, mode, source string) {
	const aaPath = "/proc/self/attr/apparmor/current"
	if raw := readAAFile(aaPath); raw != "" {
		// Existence of this file proves AppArmor is active; trust it
		// unconditionally (even an "unconfined" label is meaningful).
		n, m := parseAAProfileLine(raw)
		if n == "" {
			// e.g. bare "unconfined" with no parens.
			n = raw
		}
		return n, m, "apparmor/current"
	}

	const fallback = "/proc/self/attr/current"
	if raw := readAAFile(fallback); raw != "" {
		// Only trust the generic attr file when the content is
		// AppArmor-shaped; otherwise it may carry a SELinux context.
		if strings.Contains(raw, " (enforce)") ||
			strings.Contains(raw, " (complain)") ||
			strings.Contains(raw, " (kill)") ||
			strings.Contains(raw, " (audit)") ||
			strings.Contains(raw, "apparmor.d/") ||
			strings.HasPrefix(strings.TrimSpace(raw), "docker-default") {
			n, m := parseAAProfileLine(raw)
			if n == "" {
				n = strings.TrimSpace(raw)
			}
			return n, m, "attr/current"
		}
	}
	return "", "", ""
}

// truncStr caps s to at most n runes, appending "..." if truncated.
func truncStr(s string, n int) string {
	if n <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// ProbeAppArmorDeep implements T52.
func ProbeAppArmorDeep() {
	fmt.Fprintln(appArmorOut(), "security.apparmor_deep — AppArmor LSM state + per-process profile + enforce/complain mode:")

	// --- Probe 1: kernel enabled flag --------------------------------
	enabledRaw := readAAFile("/sys/module/apparmor/parameters/enabled")
	enabled := strings.ToUpper(enabledRaw)
	switch enabled {
	case "Y":
		fmt.Fprintf(appArmorOut(), "\t[AMBER] AppArmor enabled (/sys/module/apparmor/parameters/enabled = Y)\n")
	case "N":
		fmt.Fprintf(appArmorOut(), "\t[  ?  ] AppArmor disabled at boot (/sys/module/apparmor/parameters/enabled = N)\n")
	default:
		// Absent or unreadable — very common in containers (F22 mask).
		fmt.Fprintf(appArmorOut(), "\t[  ?  ] /sys/module/apparmor/parameters/enabled absent/unreadable (F22: often masked in containers; not conclusive)\n")
	}

	// --- Probe 2: loaded profiles + container matches ----------------
	profData := readAAFile("/sys/kernel/security/apparmor/profiles")
	profCount := 0
	var containerMatches []string
	if profData != "" {
		for _, line := range strings.Split(profData, "\n") {
			name, mode := parseAAProfileLine(line)
			if name == "" {
				continue
			}
			profCount++
			if containerAAProfileMatch(name) {
				if mode == "" {
					containerMatches = append(containerMatches, name)
				} else {
					containerMatches = append(containerMatches, name+" ("+mode+")")
				}
			}
		}
	}
	if profCount > 0 {
		names := "none found"
		if len(containerMatches) > 0 {
			names = truncStr(strings.Join(containerMatches, ", "), 160)
		}
		fmt.Fprintf(appArmorOut(), "\t        Loaded profiles: %d (container matches: %s)\n", profCount, names)
	} else {
		fmt.Fprintf(appArmorOut(), "\t        Loaded profiles: 0 or unreadable (/sys/kernel/security/apparmor/profiles)\n")
	}

	// --- Probe 3+4: per-process label --------------------------------
	label, mode, src := selfAALabel()
	labelLower := strings.ToLower(label)
	isUnconfined := label == "" && src == "" // no label at all
	if strings.Contains(labelLower, "unconfined") {
		// explicit unconfined label
		isUnconfined = true
	}
	labelReal := label != "" && !strings.Contains(labelLower, "unconfined")

	if src != "" {
		modeStr := mode
		if modeStr == "" {
			modeStr = "?"
		}
		// Color the per-process label by whether it actually confines.
		col := "  ?  "
		switch {
		case labelReal && (strings.EqualFold(mode, "enforce") || strings.EqualFold(mode, "kill")):
			col = "AMBER"
		case labelReal && strings.EqualFold(mode, "complain"):
			col = "GREEN"
		case isUnconfined:
			col = "GREEN"
		}
		fmt.Fprintf(appArmorOut(), "\t[%s] /proc/self/attr/%s = %s (%s)\n", col, src, label, modeStr)
	} else {
		fmt.Fprintf(appArmorOut(), "\t[  ?  ] /proc/self/attr/{apparmor/,}current unreadable (no AppArmor label visible)\n")
	}

	// Complain-mode note: escapes are logged, not blocked → effectively open.
	if labelReal && strings.EqualFold(mode, "complain") {
		fmt.Fprintf(appArmorOut(), "\t[GREEN] profile on self is in COMPLAIN mode — violations logged, NOT blocked (escape attempts not prevented)\n")
	}

	// --- Verdict (strict 宁漏勿flag) ---------------------------------
	aaSpecific := src == "apparmor/current" // file existence proves AppArmor active
	fmt.Fprint(appArmorOut(), "\t  Verdict: ")
	switch {
	// Strong confinement: authoritative attr file shows enforce/kill.
	case aaSpecific && labelReal && (strings.EqualFold(mode, "enforce") || strings.EqualFold(mode, "kill")):
		fmt.Fprintf(appArmorOut(), "ISOLATED by AppArmor profile %q (%s).\n", label, mode)
		fmt.Fprintln(appArmorOut(), "\t            (per-process attr authoritative; enabled-flag corroboration not required)")
	// Fallback attr (no apparmor-specific file) + enabled=Y corroborates confinement.
	case enabled == "Y" && labelReal && (strings.EqualFold(mode, "enforce") || strings.EqualFold(mode, "kill")):
		fmt.Fprintf(appArmorOut(), "ISOLATED by AppArmor profile %q (%s).\n", label, mode)
		fmt.Fprintln(appArmorOut(), "\t            (fallback attr + enabled=Y corroboration)")
	// AppArmor active (apparmor-specific attr) + complain → not effectively confined.
	case aaSpecific && labelReal && strings.EqualFold(mode, "complain"):
		fmt.Fprintln(appArmorOut(), "NOT effectively confined by AppArmor (complain mode = log only).")
	// AppArmor active + explicit unconfined label → not confined.
	case aaSpecific && isUnconfined:
		fmt.Fprintln(appArmorOut(), "NOT confined by AppArmor (process label = unconfined; runtime applied no profile).")
	// enabled=Y corroborates a generic unconfined/complain state.
	case enabled == "Y" && (isUnconfined || (labelReal && strings.EqualFold(mode, "complain"))):
		fmt.Fprintln(appArmorOut(), "NOT confined by AppArmor (enabled=Y but process unconfined / complain).")
	// AppArmor off / disabled at boot / masked.
	case enabled == "N" || enabled == "":
		fmt.Fprintln(appArmorOut(), "AMBIGUOUS (AppArmor compiled out / disabled at boot / enabled-file masked; rely on other LSMs).")
	// enabled=Y but no usable per-process label.
	case enabled == "Y" && src == "":
		fmt.Fprintln(appArmorOut(), "AMBIGUOUS (AppArmor enabled but per-process attr unreadable; confinement indeterminate).")
	default:
		fmt.Fprintln(appArmorOut(), "AMBIGUOUS (insufficient agreeing signals).")
	}
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.apparmor_deep",
		"AppArmor enabled-flag + loaded profiles + per-process profile + enforce/complain mode [F17]",
		[]string{"InContainer"},
		func() { ProbeAppArmorDeep() },
	)
}
