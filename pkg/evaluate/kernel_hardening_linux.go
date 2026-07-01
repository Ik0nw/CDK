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

// T55: system.kernel_hardening — brute-force reads ~40 kernel hardening
// sysctls and kconfig-derived security flags plus CPU side-channel
// mitigation status, sorted by category, with explicit color coding.
//
// Color scheme (attacker perspective):
//   [GREEN] = surface open  (exploit primitive available / hardening OFF)
//   [AMBER] = hardened      (gate closed / mitigation present)
//   [  ?  ] = ambiguous     (sysctl unreadable — absent or no permission)
//
// This check is deliberately chatty (exhaustive visibility): the attacker
// wants a full panel of known hardening presence/absence to triage which
// kernel exploit primitives remain viable on this host.  All probes are
// read-only file reads — zero side-effects on the kernel or host.
//
// NOTE on score semantics: the "Hardening score" is purely informational
// and additive — a non-hardened (GREEN) reading is never a false positive
// for the attacker, it simply means the gate is open.  Exceptions to the
// "non-zero == hardened" rule are noted per-entry (e.g. sysrq,
// suid_dumpable, max_user_namespaces, stack_tracer_enabled where 0 is the
// hardened state, and randomize_va_space / perf_event_paranoid where the
// hardened threshold is a specific value rather than merely non-zero).

// kHardOut is the output sink for this check (stdout wrapper, mirror pattern).
func kHardOut() *os.File { return os.Stdout }

// readKsysctl reads a single-integer /proc/sys/* file.  Returns (value, ok);
// ok is false when the file is absent or unreadable.  ok (rather than a -1
// sentinel) is used so that legitimately-negative sysctls such as
// perf_event_paranoid=-1 are preserved unambiguously.
func readKsysctl(path string) (int, bool) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}
	return v, true
}

// readCpuVuln reads /sys/devices/system/cpu/vulnerabilities/<name> and
// returns its trimmed content.  ok is false when unreadable.
func readCpuVuln(name string) (string, bool) {
	data, err := ioutil.ReadFile("/sys/devices/system/cpu/vulnerabilities/" + name)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

// kSysctl describes one sysctl probe: how to decide hardened-ness and how to
// annotate the value for the panel.  Colour is derived — hardened→AMBER,
// open→GREEN, unreadable→[  ?  ] — so each entry only needs the two
// predicates below.
type kSysctl struct {
	Label    string
	Path     string
	Hardened func(v int) bool
	Note     func(v int) string
}

// kHardCounts tallies probe outcomes for the summary block.
type kHardCounts struct {
	total      int
	readable   int
	hardened   int
	unreadable int
}

// printKSysctl emits one sysctl row and updates counts.
func printKSysctl(e kSysctl, c *kHardCounts) {
	v, ok := readKsysctl(e.Path)
	c.total++
	if !ok {
		c.unreadable++
		fmt.Fprintf(kHardOut(), "\t\t[%s] %-38s = %-5s — %s\n",
			"  ?  ", e.Label, "-", "(sysctl unreadable — absent or no read permission)")
		return
	}
	c.readable++
	hardened := e.Hardened(v)
	colour := "GREEN"
	if hardened {
		colour = "AMBER"
		c.hardened++
	}
	fmt.Fprintf(kHardOut(), "\t\t[%s] %-38s = %-5s — %s\n", colour, e.Label, strconv.Itoa(v), e.Note(v))
}

// printCpuVuln emits one CPU side-channel mitigation row and updates counts.
// "Vulnerable" → GREEN (open), "Mitigation:"/"Not affected" → AMBER (hardened).
func printCpuVuln(name string, c *kHardCounts) {
	content, ok := readCpuVuln(name)
	c.total++
	if !ok {
		c.unreadable++
		fmt.Fprintf(kHardOut(), "\t\t[%s] %-22s : (file unreadable)\n", "  ?  ", name)
		return
	}
	c.readable++
	colour := "  ?  "
	hardened := false
	switch {
	case strings.Contains(content, "Vulnerable"):
		colour = "GREEN"
	case strings.Contains(content, "Mitigation"), strings.Contains(content, "Not affected"):
		colour = "AMBER"
		hardened = true
	default:
		colour = "  ?  "
	}
	if hardened {
		c.hardened++
	}
	fmt.Fprintf(kHardOut(), "\t\t[%s] %-22s : %s\n", colour, name, content)
}

// --- Category 1: memory / stack protections (KASLR / KASAN / panic) ---
var kHardMemProtections = []kSysctl{
	{
		Label:    "kernel.randomize_va_space",
		Path:     "/proc/sys/kernel/randomize_va_space",
		Hardened: func(v int) bool { return v == 2 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "ASLR OFF — trivial ROP/JOP"
			case 1:
				return "partial ASLR (mmap+stack only) — heap not randomized"
			case 2:
				return "full ASLR (mmap+stack+heap) — standard"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.kptr_restrict",
		Path:     "/proc/sys/kernel/kptr_restrict",
		Hardened: func(v int) bool { return v >= 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "KASLR LEAK — /proc/kallsyms real addrs, %pK prints raw"
			case 1:
				return "non-root sees hashed/zeroed %pK"
			case 2:
				return "%pK always zeroed (full restrict)"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.dmesg_restrict",
		Path:     "/proc/sys/kernel/dmesg_restrict",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "non-root can read dmesg — kernel log info leak"
			case 1:
				return "dmesg restricted to CAP_SYSLOG"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.stack_tracer_enabled",
		Path:     "/proc/sys/kernel/stack_tracer_enabled",
		Hardened: func(v int) bool { return v == 0 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "stack tracer off"
			case 1:
				return "stack tracer ON — ftrace stack info-leak surface"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.modules_disabled",
		Path:     "/proc/sys/kernel/modules_disabled",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "LKM loadable (modprobe/insmod) — kernel exploit primitive"
			case 1:
				return "modules disabled (irreversible until reboot)"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.softlockup_panic",
		Path:     "/proc/sys/kernel/softlockup_panic",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "no panic on softlockup — ROP/hang friendly"
			case 1:
				return "panics on softlockup — disrupts ROP stability"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.hardlockup_panic",
		Path:     "/proc/sys/kernel/hardlockup_panic",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "no panic on hard lockup"
			case 1:
				return "panics on hard lockup — disrupts exploit spin loops"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.panic_on_oops",
		Path:     "/proc/sys/kernel/panic_on_oops",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "oops continues — exploit can recover"
			case 1:
				return "oops → panic — kills exploit mid-flight"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.panic_on_warn",
		Path:     "/proc/sys/kernel/panic_on_warn",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "WARN continues — some WARN-based primitives open"
			case 1:
				return "WARN → panic — closes WARN-based exploit paths"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.unprivileged_userfaultfd",
		Path:     "/proc/sys/kernel/unprivileged_userfaultfd",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "USERFAULTFD OPEN — UAF grooming / THP-collapse primitive"
			case 1:
				return "userfaultfd restricted (>=5.11)"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.unprivileged_bpf_disabled",
		Path:     "/proc/sys/kernel/unprivileged_bpf_disabled",
		Hardened: func(v int) bool { return v >= 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "unpriv BPF unrestricted — LPE vector family"
			case 1:
				return "CAP_BPF required (>=5.16)"
			case 2:
				return "disabled, irreversible until reboot"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.perf_event_paranoid",
		Path:     "/proc/sys/kernel/perf_event_paranoid",
		Hardened: func(v int) bool { return v >= 2 },
		Note: func(v int) string {
			switch v {
			case -1:
				return "all events for all users — OPEN"
			case 0:
				return "kernel perf for unpriv — OPEN"
			case 1:
				return "kernel profiling restricted"
			case 2:
				return "cpu events restricted"
			case 3:
				return "perf fully restricted (6.x)"
			default:
				return "unknown value"
			}
		},
	},
}

// --- Category 2: kernel exploit primitive gates ---
var kHardExploitGates = []kSysctl{
	{
		Label:    "kernel.kexec_load_disabled",
		Path:     "/proc/sys/kernel/kexec_load_disabled",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "kexec_load allowed — kernel overwrite primitive"
			case 1:
				return "kexec_load disabled"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.sysrq",
		Path:     "/proc/sys/kernel/sysrq",
		Hardened: func(v int) bool { return v == 0 },
		Note: func(v int) string {
			switch {
			case v == 0:
				return "sysrq fully disabled"
			case v == 1:
				return "sysrq fully enabled — magic-sysrq vectors open"
			case v > 1:
				return "sysrq bitmask enabled — partial magic-sysrq vectors open"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.yama.ptrace_scope",
		Path:     "/proc/sys/kernel/yama/ptrace_scope",
		Hardened: func(v int) bool { return v >= 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "ptrace unrestricted — credential theft surface"
			case 1:
				return "ptrace across exec restricted (same uid)"
			case 2:
				return "admin-only ptrace"
			case 3:
				return "ptrace fully disabled"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "vm.unprivileged_userfaultfd",
		Path:     "/proc/sys/vm/unprivileged_userfaultfd",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "userfaultfd OPEN (vm variant) — UAF primitive"
			case 1:
				return "userfaultfd restricted (>=5.11)"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "vm.mmap_min_addr",
		Path:     "/proc/sys/vm/mmap_min_addr",
		Hardened: func(v int) bool { return v > 0 },
		Note: func(v int) string {
			switch {
			case v == 0:
				return "mmap_min_addr=0 — NULL deref → mmap(0) primitive OPEN"
			case v > 0:
				return fmt.Sprintf("mmap_min_addr=%d — NULL mmap blocked", v)
			default:
				return "unknown value"
			}
		},
	},
}

// --- Category 3: namespace / fs / container hardening ---
var kHardNamespaceFS = []kSysctl{
	{
		Label:    "fs.protected_hardlinks",
		Path:     "/proc/sys/fs/protected_hardlinks",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "hardlink protection off"
			case 1:
				return "hardlink protection on"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "fs.protected_symlinks",
		Path:     "/proc/sys/fs/protected_symlinks",
		Hardened: func(v int) bool { return v == 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "symlink protection off — /tmp symlink races"
			case 1:
				return "symlink protection on"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "fs.protected_fifos",
		Path:     "/proc/sys/fs/protected_fifos",
		Hardened: func(v int) bool { return v >= 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "fifo protection off"
			case 1:
				return "fifo protection (sticky dirs)"
			case 2:
				return "fifo protection (all dirs)"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "fs.protected_regular",
		Path:     "/proc/sys/fs/protected_regular",
		Hardened: func(v int) bool { return v >= 1 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "regular-file protection off"
			case 1:
				return "protected in sticky dirs"
			case 2:
				return "protected in all dirs"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "fs.suid_dumpable",
		Path:     "/proc/sys/fs/suid_dumpable",
		Hardened: func(v int) bool { return v == 0 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "no suid core dumps (hardened)"
			case 1:
				return "debug core dumps — info leak"
			case 2:
				return "suidsafe core dumps"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "kernel.unprivileged_userns_clone",
		Path:     "/proc/sys/kernel/unprivileged_userns_clone",
		Hardened: func(v int) bool { return v == 0 },
		Note: func(v int) string {
			switch v {
			case 0:
				return "unpriv userns clone disabled (hardened)"
			case 1:
				return "unpriv userns clone ALLOWED — broad escape surface"
			default:
				return "unknown value"
			}
		},
	},
	{
		Label:    "user.max_user_namespaces",
		Path:     "/proc/sys/user/max_user_namespaces",
		Hardened: func(v int) bool { return v == 0 },
		Note: func(v int) string {
			switch {
			case v == 0:
				return "user namespaces disabled (hardened)"
			case v > 0:
				return fmt.Sprintf("user namespaces allowed (max=%d)", v)
			default:
				return "unknown value"
			}
		},
	},
}

// --- Category 4: CPU side-channel mitigations (informational) ---
var kHardCpuVulns = []string{
	"itlb_multihit",
	"l1tf",
	"mds",
	"meltdown",
	"spec_store_bypass",
	"spectre_v1",
	"spectre_v2",
	"srbds",
	"tsx_async_abort",
	"retbleed",
	"gds",
	"gather_data_sampling",
}

// DumpKernelHardening implements T55.
func DumpKernelHardening() {
	fmt.Fprintln(kHardOut(), "system.kernel_hardening — kernel hardening / exploit-mitigation panel:")

	var c kHardCounts

	fmt.Fprintln(kHardOut(), "\t--- 1. Memory / stack protections ---")
	for _, e := range kHardMemProtections {
		printKSysctl(e, &c)
	}

	fmt.Fprintln(kHardOut(), "\t--- 2. Kernel exploit primitive gates ---")
	for _, e := range kHardExploitGates {
		printKSysctl(e, &c)
	}

	fmt.Fprintln(kHardOut(), "\t--- 3. Namespace / FS hardening ---")
	for _, e := range kHardNamespaceFS {
		printKSysctl(e, &c)
	}

	fmt.Fprintln(kHardOut(), "\t--- 4. CPU mitigations ---")
	for _, name := range kHardCpuVulns {
		printCpuVuln(name, &c)
	}

	// --- Summary ---
	fmt.Fprintln(kHardOut(), "\t--- Summary ---")
	ratio := 0.0
	if c.total > 0 {
		ratio = float64(c.hardened) / float64(c.total)
	}
	fmt.Fprintf(kHardOut(), "\t  Hardening score = %d/%d (higher = more hardened)\n", c.hardened, c.total)
	fmt.Fprintf(kHardOut(), "\t  (%d readable, %d unreadable/ambiguous, %d open-surface)\n",
		c.readable, c.unreadable, c.readable-c.hardened)

	colour := "  ?  "
	verdict := "AMBIGUOUS"
	switch {
	case c.total == 0:
		colour = "  ?  "
		verdict = "AMBIGUOUS (no probes ran)"
	case c.unreadable == c.total:
		colour = "  ?  "
		verdict = "AMBIGUOUS (all probes unreadable — not a Linux host or no /proc/sys access)"
	case ratio >= 0.66:
		colour = "AMBER"
		verdict = "well-hardened (limited kernel exploit surface)"
	case ratio <= 0.33:
		colour = "GREEN"
		verdict = "OPEN (many kernel exploit primitives available)"
	default:
		colour = "  ?  "
		verdict = "mixed hardening — partial exploit surface"
	}
	fmt.Fprintf(kHardOut(), "\t  [%s] Surface: %s\n", colour, verdict)
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySystemInfo,
		"system.kernel_hardening",
		"Dump kernel hardening / exploit-mitigation sysctls + CPU vuln status [F13]",
		[]string{"InContainer"},
		func() { DumpKernelHardening() },
	)
}
