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
	"strconv"
	"strings"
)

// T56: security.ptrace_scope — kernel.yama.ptrace_scope value + per-process
// PR_SET_DUMPABLE state + /proc/sys/kernel/yama/* gates.
//
// Answers: "Can an attacker inside the container use ptrace() to attach to
// another process in the same PID ns? Can they inject code into sibling
// containers via CAP_SYS_PTRACE + same-ns attach? Are Yama LSM gates set
// to permissive values that enable process-to-process code injection?"
//
// Values (from linux/Documentation/admin-guide/sysctl/kernel.rst):
//   0 = classic ptrace permissions: any process with same UID can PTRACE_ATTACH
//       → classic process injection vector
//   1 = restricted: only PTRACE_TRACEME + ancestors can trace  (Ubuntu default)
//   2 = admin-only: CAP_SYS_PTRACE required in the INIT USERNS
//       → inside container, userns-shifted CAP_SYS_PTRACE doesn't count
//   3 = no attach at all: irreversible (until reboot)
//
// Additionally read:
//   /proc/self/status:Seccomp — dumpable/ptraceable bits
//   /proc/sys/kernel/yama/protected_symlinks
//   /proc/sys/kernel/yama/protected_hardlinks
//   /proc/sys/kernel/yama/protected_fifos
//   /proc/sys/kernel/yama/protected_regular

func ptraceScopeOut() *os.File { return os.Stdout }

func readYamaInt(name string) int {
	data, err := ioutil.ReadFile("/proc/sys/kernel/yama/" + name)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return v
}

// EnumeratePtraceScope implements T56.
func EnumeratePtraceScope() {
	fmt.Fprintln(ptraceScopeOut(), "security.ptrace_scope — Yama LSM ptrace + protected-* gates:")

	scope := readYamaInt("ptrace_scope")
	psymlinks := readYamaInt("protected_symlinks")
	phardlinks := readYamaInt("protected_hardlinks")
	pfifos := readYamaInt("protected_fifos")
	// protected_regular exists on 6.5+
	pregular := readYamaInt("protected_regular")

	// --- Table 1: Yama gates ------------------------------------------
	var c, note string
	switch scope {
	case -1:
		c, note = "  ?  ", "(YAMA not compiled in / file unreadable)"
	case 0:
		c, note = "GREEN", "UNRESTRICTED — any same-UID process can PTRACE_ATTACH (classic code-injection vector)."
	case 1:
		c, note = "  ?  ", "RESTRICTED — ancestor-only TRACEME (Ubuntu default; still allows injection via exec chain)."
	case 2:
		c, note = "AMBER", "ADMIN-ONLY — INIT-NS CAP_SYS_PTRACE required (container-userns caps generally insufficient)."
	case 3:
		c, note = "AMBER", "NO ATTACH — ptrace fully disabled, irreversible until reboot."
	default:
		c, note = "  ?  ", fmt.Sprintf("(unexpected scope=%d)", scope)
	}
	fmt.Fprintf(ptraceScopeOut(), "\t\t[%s] ptrace_scope      = %-3v — %s\n", c, scope, note)

	gates := []struct {
		Label string
		Val   int
	}{
		{"protected_symlinks", psymlinks},
		{"protected_hardlinks", phardlinks},
		{"protected_fifos    ", pfifos},
		{"protected_regular  ", pregular},
	}
	for _, g := range gates {
		if g.Val == -1 {
			continue // don't print for 4.x kernels where file missing
		}
		col := "  ?  "
		what := ""
		switch g.Val {
		case 0:
			col, what = "GREEN", "permissive — TOCTOU via /tmp races open."
		case 1:
			col, what = "AMBER", "sticky-dirs only (standard)."
		case 2:
			col, what = "AMBER", "always (stronger)."
		}
		fmt.Fprintf(ptraceScopeOut(), "\t\t[%s] %s = %-3v — %s\n", col, g.Label, g.Val, what)
	}

	// --- Table 2: process-specific Seccomp / Dumpable fields ----------
	fmt.Fprintln(ptraceScopeOut(), "\tPer-process state (/proc/self/status):")
	seccompField := statusField("/proc/self/status", "Seccomp")
	if seccompField != "" {
		fmt.Fprintf(ptraceScopeOut(), "\t\tSeccomp = %s\n", seccompField)
	}
	dumpable := statusField("/proc/self/status", "Dumpable")
	if dumpable != "" {
		col := "  ?  "
		switch dumpable {
		case "1", "SUID_DUMPABLE":
			col = "GREEN"
		case "0", "SUID_DUMP_DISABLE":
			col = "AMBER"
		}
		fmt.Fprintf(ptraceScopeOut(), "\t\t[%s] Dumpable = %s\n", col, dumpable)
	}

	// --- Summary -------------------------------------------------------
	fmt.Fprintln(ptraceScopeOut(), "\t  ---")
	switch {
	case scope == 0:
		fmt.Fprintln(ptraceScopeOut(), "\t  [GREEN] SUMMARY: Yama ptrace_scope=0 — process-injection / PTRACE_ATTACK vector FULLY OPEN.")
	case scope == 1:
		fmt.Fprintln(ptraceScopeOut(), "\t  [  ?  ] SUMMARY: ptrace_scope=1 — ancestry-gated; check for ancestor process takeover options.")
	case scope == 2 || scope == 3:
		fmt.Fprintln(ptraceScopeOut(), "\t  [AMBER] SUMMARY: ptrace_scope ≥2 — container userns caps generally cannot escalate to ptrace; reduce priority.")
	}
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.ptrace_scope",
		"kernel.yama.ptrace_scope + protected_symlinks/hardlinks/fifos + per-process Seccomp/Dumpable [F16]",
		[]string{"InContainer"},
		func() { EnumeratePtraceScope() },
	)
}
