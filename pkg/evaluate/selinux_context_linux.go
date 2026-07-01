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

// SELinux deep-context probe (T53).  Pure file-read; no syscalls,
// no side effects, no shell.

package evaluate

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// selinuxOut returns the target writer for this check's output.
// Using a function (instead of a package-level var) ensures the
// json.go stdout-swap mechanism works correctly — see T39 notes.
func selinuxOut() *os.File { return os.Stdout }

// EnumerateSELinuxDeep performs a read-only deep SELinux probe.
//
// Signals gathered (all from /proc + selinuxfs, zero host side-effects):
//   1. /proc/self/attr/current         → process security context
//      (container_t / spc_t / unconfined_t / crio_t / ...)
//   2. /proc/self/attr/{exec,fscreate,keycreate} → auxiliary contexts
//   3. /sys/fs/selinux/enforce         → 0=permissive, 1=enforcing
//   4. /sys/fs/selinux/policyvers      → policy DB revision
//   5. /sys/fs/selinux/mls             → 0/1 Multi-Level Security flag
//
// Verdict rules (宁漏勿 flag — never raise a false positive):
//   - context contains "spc_t"        → NOT isolated (SPC = super-privileged)
//   - context contains "unconfined_t" → NOT isolated (no MAC on this process)
//   - enforce=0 + any context         → NOT isolated (audit-only, permissive)
//   - enforce=1 + container_t/crio_t  → PARTIALLY isolated (standard policy)
//   - selinuxfs absent                → AMBIGUOUS (LSM not mounted / compiled out)
func EnumerateSELinuxDeep() {
	out := selinuxOut()
	fmt.Fprintf(out, "security.selinux_deep — SELinux context and policy status:\n")

	// --- 1. selinuxfs reachability (master gate) ----------------------
	enforceRaw := readFileFirstLine("sys/fs/selinux/enforce")
	policyversRaw := readFileFirstLine("sys/fs/selinux/policyvers")
	mlsRaw := readFileFirstLine("sys/fs/selinux/mls")

	hasMounted := enforceRaw != "" || policyversRaw != "" || mlsRaw != ""
	if !hasMounted {
		// /sys/fs/selinux not mounted.  We still report the procfs
		// label if one is visible (SELinux may be enforcing even if
		// the container runtime masked selinuxfs).
		fmt.Fprintf(out, "  \t[  ?  ] selinuxfs = NOT mounted (/sys/fs/selinux/* unreadable)\n")
	} else {
		fmt.Fprintf(out, "  \tselinuxfs mounted = YES (/sys/fs/selinux/enforce readable)\n")
	}

	// --- 2. Current process context -----------------------------------
	ctxCurrent := readSelinuxContext("proc/self/attr/current")
	ctxExec := readSelinuxContext("proc/self/attr/exec")
	ctxFsCreate := readSelinuxContext("proc/self/attr/fscreate")
	ctxKeyCreate := readSelinuxContext("proc/self/attr/keycreate")

	ctxParts := strings.Split(ctxCurrent, ":")
	// Standard SELinux context format: user:role:type:level[:category]
	// e.g. system_u:system_r:container_t:s0:c123,c456
	var ctxType, ctxLevel string
	if len(ctxParts) >= 3 {
		ctxType = ctxParts[2]
	}
	if len(ctxParts) >= 4 {
		ctxLevel = strings.Join(ctxParts[3:], ":")
	}

	// Classify the type tag.
	var (
		tagColor    = "[  ?  ]"
		tagVerdict  = ""
		severity    = 0 // -1=NOT-isolated (GREEN for attacker), 0=ambig, +1=isolated (AMBER)
	)
	switch {
	case ctxCurrent == "":
		tagVerdict = "no label visible (SELinux compiled out / procfs masked)"
	case ctxType == "spc_t":
		tagColor = "[GREEN]"
		tagVerdict = "WARNING: SPC (super-privileged container) type — effectively no SELinux confinement"
		severity = -1
	case strings.Contains(ctxType, "unconfined_t"):
		tagColor = "[GREEN]"
		tagVerdict = "WARNING: unconfined_t domain — no MAC enforcement on this process"
		severity = -1
	case ctxType == "container_t" || ctxType == "container_file_t" ||
		ctxType == "crio_t" || ctxType == "svirt_lxc_net_t" ||
		ctxType == "svirt_t":
		// Standard container policies.
		tagColor = "[  ?  ]"
		tagVerdict = "standard container policy (container_t / crio_t / svirt_t)"
	case ctxType == "kernel_t":
		tagColor = "[GREEN]"
		tagVerdict = "kernel_t context visible (running in kernel domain — host-level or privileged)"
		severity = -1
	default:
		tagVerdict = fmt.Sprintf("custom domain type=%q (review policy manually)", ctxType)
	}

	if ctxCurrent != "" {
		fmt.Fprintf(out, "  \t%s policy = %s (%s)\n", tagColor, ctxCurrent, tagVerdict)
	} else {
		fmt.Fprintf(out, "  \t%s policy = (no SELinux label visible)\n", tagColor)
	}

	// --- 3. Auxiliary contexts (exec / fscreate / keycreate) ----------
	printAuxCtx(out, "exec context", ctxExec)
	printAuxCtx(out, "fscreate context", ctxFsCreate)
	printAuxCtx(out, "keycreate context", ctxKeyCreate)

	// --- 4. Enforce mode ----------------------------------------------
	enforce := -1
	if enforceRaw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(enforceRaw)); err == nil {
			enforce = n
		}
	}
	switch enforce {
	case 1:
		fmt.Fprintf(out, "  \t[AMBER] enforce = 1 (enforcing — exploits that do write/fd-passing may fail)\n")
		if severity == 0 && ctxType != "spc_t" && !strings.Contains(ctxType, "unconfined_t") {
			severity = 1
		}
	case 0:
		fmt.Fprintf(out, "  \t[GREEN] enforce = 0 (permissive-mode; SELinux logs but does NOT block)\n")
		severity = -1
	default:
		fmt.Fprintf(out, "  \t[  ?  ] enforce = unknown (selinuxfs/enforce unreadable)\n")
	}

	// --- 5. Policy version --------------------------------------------
	if policyversRaw != "" {
		pv := strings.TrimSpace(policyversRaw)
		fmt.Fprintf(out, "  \tpolicy version = %s", pv)
		if n, err := strconv.Atoi(pv); err == nil {
			// Annotate well-known policy versions:
			//   <=28 → RHEL 7 era
			//   29-31 → RHEL 8 / Fedora 30-33
			//   32+  → RHEL 9 / Fedora 34+
			switch {
			case n >= 33:
				fmt.Fprintf(out, " (RHEL9 / Fedora34+ era policy)\n")
			case n >= 29:
				fmt.Fprintf(out, " (RHEL8 / Fedora30-33 era policy)\n")
			case n <= 28:
				fmt.Fprintf(out, " (RHEL7 era policy — may lack container_t refinements)\n")
			default:
				fmt.Fprintf(out, "\n")
			}
		} else {
			fmt.Fprintf(out, "\n")
		}
	} else {
		fmt.Fprintf(out, "  \tpolicy version = unknown\n")
	}

	// --- 6. MLS -------------------------------------------------------
	mls := -1
	if mlsRaw != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(mlsRaw)); err == nil {
			mls = n
		}
	}
	switch mls {
	case 1:
		if ctxLevel != "" {
			fmt.Fprintf(out, "  \tMLS enabled = YES  (level=%s) — Multi-Level Security + categories active\n", ctxLevel)
		} else {
			fmt.Fprintf(out, "  \tMLS enabled = YES  — Multi-Level Security active\n")
		}
	case 0:
		fmt.Fprintf(out, "  \tMLS enabled = NO   — type-enforcement only (no sensitivity levels)\n")
	default:
		fmt.Fprintf(out, "  \tMLS enabled = unknown\n")
	}

	// --- 7. Summary verdict -------------------------------------------
	fmt.Fprintf(out, "  \t")
	switch severity {
	case -1:
		// Escape-friendly: permissive OR spc OR unconfined.
		fmt.Fprintf(out, "Verdict: ")
		switch {
		case ctxType == "spc_t":
			fmt.Fprintf(out, "spc_t domain + enforce=%d → NOT ISOLATED; SELinux offers zero confinement.\n", enforce)
		case strings.Contains(ctxType, "unconfined_t"):
			fmt.Fprintf(out, "unconfined_t + enforce=%d → NOT ISOLATED; no MAC applied to this process.\n", enforce)
		case enforce == 0:
			fmt.Fprintf(out, "permissive mode (enforce=0) → NOT ISOLATED; SELinux logs but blocks nothing.\n")
		default:
			fmt.Fprintf(out, "NOT ISOLATED signals present — treat as unconfined.\n")
		}
	case 1:
		// Enforcing + standard container type.
		fmt.Fprintf(out, "Verdict: %s (enforcing) → PARTIALLY ISOLATED; avoid cross-process write primitives.\n", ctxType)
	default:
		// Ambiguous.
		if !hasMounted && ctxCurrent == "" {
			fmt.Fprintf(out, "Verdict: AMBIGUOUS — no SELinux signals visible (LSM absent or container-fs masked).\n")
		} else {
			fmt.Fprintf(out, "Verdict: AMBIGUOUS — partial SELinux data, manual review recommended.\n")
		}
	}
}

// readSelinuxContext reads one of the /proc/self/attr/* pseudo-files and
// returns the NUL + newline-trimmed context string.  On any error returns
// the empty string.
func readSelinuxContext(path string) string {
	lines := readFileLines(path)
	if len(lines) == 0 {
		return ""
	}
	// SELinux contexts are terminated with a trailing '\0' byte; strip
	// it (along with whitespace) so the raw label is printable.
	s := strings.TrimRight(lines[0], "\x00")
	s = strings.TrimSpace(s)
	return s
}

// printAuxCtx prints one auxiliary context line with the standard tag.
func printAuxCtx(out *os.File, label, ctx string) {
	display := ctx
	if display == "" {
		display = "(inherit / unset)"
	}
	// Aux contexts are always informational; never a verdict-driver.
	fmt.Fprintf(out, "  \t[  ?  ] %s = %s\n", label, display)
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.selinux_deep",
		"SELinux: current process context (container_t vs spc_t vs unconfined), enforce mode, policy version [F11]",
		[]string{"InContainer"},
		func() { EnumerateSELinuxDeep() },
	)
}
