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
	"strconv"
	"strings"

	"github.com/cdk-team/CDK/pkg/util"
)

// T54: security.kernel_lockdown — Linux kernel lockdown LSM mode plus the
// independent module-loading / kexec gates that close off kernel-level
// escape primitives.
//
// Answers the attacker question: "Is Linux kernel lockdown LSM in INTEGRITY
// or CONFIDENTIALITY mode? If so, kernel module loading, /dev/mem, /dev/kmem,
// kexec, hibernate and secure-boot key manipulation are blocked — which cuts
// off many kernel-level escape primitives (LKM rootkit, kexec-as-pivot,
// /dev/mem RW, etc.)."
//
// Lockdown modes (from Documentation/admin-guide/lockdown.rst):
//   none             — lockdown off; everything permitted.
//   integrity        — kernel-subsystem integrity mode; blocks module
//                      loading, /dev/mem + /dev/kmem, kexec, MSR writes,
//                      PCMCIA CIS, ACPI custom method.
//   confidentiality  — integrity + memory confidentiality; additionally
//                      blocks hibernation, BPF, dmesg, kexec (even for
//                      crash), userfaultfd tricks, etc.
//
// The active mode is the bracketed token in /sys/kernel/security/lockdown,
// e.g.  "[integrity] none confidentiality"  → active = "integrity".
//
// Probes (read-only file reads, zero host side-effects):
//   1. /sys/kernel/security/lockdown   — modes line; bracketed = active.
//   2. /sys/kernel/security/lsm        — comma list; "lockdown" present?
//   3. /proc/sys/kernel/modules_disabled         — 1 = module loading blocked.
//   4. /sys/module/module/parameters/enable      — single value (some distros).
//   5. /proc/sys/kernel/kexec_load_disabled      — 1 = kexec blocked.

func lockdownOut() *os.File { return os.Stdout }

// lockdownReadTrim reads a (small sysfs/procfs) file and returns its
// whitespace-trimmed content.  Returns "" if the file is absent or unreadable.
func lockdownReadTrim(path string) string {
	data, err := util.StealthReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// lockdownReadInt reads a small integer-valued sysctl/sysfs file.  Returns -1
// if the file is absent, unreadable, or not a clean integer.
func lockdownReadInt(path string) int {
	s := lockdownReadTrim(path)
	if s == "" {
		return -1
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return v
}

// lockdownActiveMode parses the /sys/kernel/security/lockdown modes line and
// returns the bracketed (currently active) mode, e.g. "integrity".  Returns
// "" if no bracketed token is present.
func lockdownActiveMode(content string) string {
	for _, tok := range strings.Fields(content) {
		if len(tok) >= 2 && tok[0] == '[' && tok[len(tok)-1] == ']' {
			return tok[1 : len(tok)-1]
		}
	}
	return ""
}

// lockdownLSMPresent reports whether "lockdown" appears in the
// /sys/kernel/security/lsm comma-separated list.
func lockdownLSMPresent(content string) bool {
	for _, tok := range strings.Split(content, ",") {
		if strings.TrimSpace(strings.ToLower(tok)) == "lockdown" {
			return true
		}
	}
	return false
}

// ProbeKernelLockdown implements T54.
func ProbeKernelLockdown() {
	fmt.Fprintln(lockdownOut(), "security.kernel_lockdown — kernel lockdown LSM mode + module/kexec gates:")

	// --- Probe 1: /sys/kernel/security/lockdown modes line --------------
	lockdownRaw := lockdownReadTrim(util.SysKernelSecurityLockdownPath())
	lockdownFilePresent := lockdownRaw != ""
	activeMode := lockdownActiveMode(lockdownRaw)

	fmt.Fprintln(lockdownOut(), "\tLockdown LSM modes (/sys/kernel/security/lockdown):")
	if !lockdownFilePresent {
		fmt.Fprintln(lockdownOut(), "\t\t[  ?  ] file absent — kernel < 5.4 or CONFIG_SECURITY_LOCKDOWN_LSM=n (cannot determine lockdown state)")
	} else {
		col := "  ?  "
		switch activeMode {
		case "none":
			col = "GREEN"
		case "integrity", "confidentiality":
			col = "AMBER"
		}
		fmt.Fprintf(lockdownOut(), "\t\t[%s] active mode = %s\n", col, activeMode)
		fmt.Fprintf(lockdownOut(), "\t\t       modes line: %s\n", lockdownRaw)
	}

	// --- Probe 2: /sys/kernel/security/lsm contains "lockdown"? ---------
	lsmRaw := lockdownReadTrim(util.SysKernelSecurityLsmPath())
	lsmHasLockdown := lockdownLSMPresent(lsmRaw)
	if lsmRaw == "" {
		fmt.Fprintln(lockdownOut(), "\t\t[  ?  ] /sys/kernel/security/lsm not visible (securityfs unmounted?) — cannot confirm lockdown LSM loaded")
	} else {
		col := "GREEN"
		note := "NO — lockdown LSM NOT in kernel lsm= list"
		if lsmHasLockdown {
			col = "AMBER"
			note = "YES — lockdown LSM is loaded"
		}
		fmt.Fprintf(lockdownOut(), "\t\t[%s] lockdown in /sys/kernel/security/lsm: %s\n", col, note)
	}

	// --- Probe 3-5: independent module/kexec gates ----------------------
	modulesDisabled := lockdownReadInt(util.ProcSysKernelModulesDisabled())
	kexecDisabled := lockdownReadInt(util.KexecLoadThreshold())
	moduleEnable := lockdownReadTrim(util.SysModuleModuleEnablePath())

	fmt.Fprintln(lockdownOut(), "\tRelated kernel gates:")
	printLockdownGate("modules_disabled    ", modulesDisabled, "1=module loading blocked", "0=module loading permitted")
	printLockdownGate("kexec_load_disabled ", kexecDisabled, "1=kexec load blocked", "0=kexec load permitted")
	if moduleEnable != "" {
		fmt.Fprintf(lockdownOut(), "\t\t[  ?  ] /sys/module/module/parameters/enable = %s (distro-specific module knob)\n", moduleEnable)
	}

	// --- Summary verdict (spec priority order, first match wins) --------
	fmt.Fprintln(lockdownOut(), "\t  ---")
	fmt.Fprint(lockdownOut(), "\t  ")
	switch {
	case activeMode == "confidentiality" && modulesDisabled == 1 && kexecDisabled == 1:
		fmt.Fprintln(lockdownOut(), "[AMBER] SUMMARY: FULL KERNEL LOCKDOWN — confidentiality mode + modules_disabled=1 + kexec_load_disabled=1.")
		fmt.Fprintln(lockdownOut(), "\t            (module loading, /dev/mem, kexec, hibernate, BPF, dmesg all gated)")
	case activeMode == "confidentiality":
		fmt.Fprintln(lockdownOut(), "[AMBER] SUMMARY: KERNEL LOCKDOWN (confidentiality) — strongest mode; module/kexec gates inherently blocked.")
	case activeMode == "integrity":
		fmt.Fprintln(lockdownOut(), "[AMBER] SUMMARY: KERNEL LOCKDOWN (integrity) — module loading, /dev/mem, kexec, MSR writes blocked.")
	case modulesDisabled == 1 && kexecDisabled == 1:
		fmt.Fprintln(lockdownOut(), "[AMBER] SUMMARY: STRONG — modules_disabled=1 + kexec_load_disabled=1 (without lockdown LSM).")
		fmt.Fprintln(lockdownOut(), "\t            (LKM rootkit + kexec-pivot escape primitives closed independently of lockdown)")
	case activeMode == "none":
		fmt.Fprintln(lockdownOut(), "[GREEN] SUMMARY: lockdown DISABLED — lockdown=[none]; kernel-level escape primitives NOT gated by lockdown LSM.")
	case !lockdownFilePresent:
		fmt.Fprintln(lockdownOut(), "[  ?  ] SUMMARY: AMBIGUOUS — /sys/kernel/security/lockdown absent (kernel < 5.4 or !CONFIG_SECURITY_LOCKDOWN_LSM).")
	default:
		fmt.Fprintf(lockdownOut(), "[  ?  ] SUMMARY: AMBIGUOUS — unrecognised lockdown mode %q.\n", activeMode)
	}
}

// printLockdownGate emits one int-valued gate row with the right colour.
func printLockdownGate(label string, val int, onNote, offNote string) {
	col := "  ?  "
	note := "(file unreadable)"
	switch val {
	case 1:
		col = "AMBER"
		note = onNote
	case 0:
		col = "GREEN"
		note = offNote
	}
	fmt.Fprintf(lockdownOut(), "\t\t[%s] %s = %-3v — %s\n", col, label, val, note)
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.kernel_lockdown",
		"Linux kernel lockdown LSM mode (none/integrity/confidentiality) + modules_disabled + kexec_load_disabled gates [F12]",
		[]string{"InContainer"},
		func() { ProbeKernelLockdown() },
	)
}
