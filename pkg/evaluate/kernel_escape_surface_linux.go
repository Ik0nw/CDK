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
	"strings"
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckKernelEscapeSurface audits kernel-level escape primitives that
// are reachable from inside a container:
//
//  1. /proc/sys/kernel/core_pattern — if writable, set to "|/tmp/x" to
//     get code execution when any process crashes (core dump pipe).
//     This is the canonical "kernel modprobe" style escape.
//
//  2. /sys/kernel/uevent_helper — if writable, set to a binary path and
//     trigger a uevent (e.g. hotplug) to get host root exec.
//
//  3. /proc/sys/kernel/modprobe — if writable, point to a custom binary,
//     then trigger a missing kernel module request (e.g. mount -t cifs).
//
//  4. /proc/sys/kernel/hotplug — legacy hotplug handler, same as uevent_helper.
//
//  5. kexec_load_disabled — if 0 and CAP_SYS_BOOT, can kexec_load a new
//     kernel image → full host takeover.
//
//  6. perf_event_paranoid — if <= 0 and CAP_SYS_ADMIN, can use perf_event_open
//     to read host kernel memory via per-cpu counters.
//
// OPSEC: all file opens use StealthOpen (raw openat syscall) with
// O_CLOEXEC.  Paths are XOR-obfuscated via util helpers.  No writes
// performed — we only test open(O_RDWR) to assess writability.
//
// T67 / security.kernel_escape_surface.
func CheckKernelEscapeSurface() {
	fmt.Fprintf(os.Stdout, "kernel escape surface (T67) — core_pattern, uevent_helper, modprobe, kexec:\n")

	findings := 0

	// --- Signal 1: core_pattern ---
	corePatternPath := util.CorePatternPath()
	corePattern := stealthReadFirstLine(corePatternPath)
	coreWritable := stealthFileWritable(corePatternPath)

	if corePattern != "" {
		fmt.Fprintf(os.Stdout, "\t     core_pattern: %s\n", strings.TrimSpace(corePattern))
		if strings.HasPrefix(strings.TrimSpace(corePattern), "|") {
			fmt.Fprintf(os.Stdout, "\t[AMBER] core_pattern is a pipe (already configured for crash handler)\n")
		}
	}
	if coreWritable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] core_pattern WRITABLE — set '|/tmp/shell' → trigger crash → host RCE\n")
		fmt.Fprintf(os.Stdout, "\t         classic escape: echo '|/tmp/.x' > %s, then kill -SIGSEGV any process\n",
			corePatternPath)
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] core_pattern not writable from container\n")
	}

	// --- Signal 2: uevent_helper ---
	ueventPath := util.UeventHelperPath()
	ueventHelper := stealthReadFirstLine(ueventPath)
	ueventWritable := stealthFileWritable(ueventPath)

	if ueventHelper != "" {
		fmt.Fprintf(os.Stdout, "\t     uevent_helper: %s\n", strings.TrimSpace(ueventHelper))
	}
	if ueventWritable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] uevent_helper WRITABLE — set binary path → trigger uevent → host RCE\n")
		fmt.Fprintf(os.Stdout, "\t         escape: echo '/tmp/.x' > %s, then mknod + add a device to trigger\n",
			ueventPath)
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] uevent_helper not writable from container\n")
	}

	// --- Signal 3: modprobe path ---
	modprobePath := util.ModprobePath()
	modprobeBinary := stealthReadFirstLine(modprobePath)
	modprobeWritable := stealthFileWritable(modprobePath)

	if modprobeBinary != "" {
		fmt.Fprintf(os.Stdout, "\t     modprobe path: %s\n", strings.TrimSpace(modprobeBinary))
	}
	if modprobeWritable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] modprobe WRITABLE — replace path → trigger missing module → host RCE\n")
		fmt.Fprintf(os.Stdout, "\t         escape: echo '/tmp/.x' > %s, then request a netfilter module via iptables\n",
			modprobePath)
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] modprobe path not writable\n")
	}

	// --- Signal 4: hotplug (legacy) ---
	hotplugPath := util.HotplugPath()
	hotplugHelper := stealthReadFirstLine(hotplugPath)
	hotplugWritable := stealthFileWritable(hotplugPath)

	if hotplugHelper != "" {
		fmt.Fprintf(os.Stdout, "\t     hotplug (legacy): %s\n", strings.TrimSpace(hotplugHelper))
	}
	if hotplugWritable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] hotplug WRITABLE — legacy uevent handler, same escape as uevent_helper\n")
		findings++
	}

	// --- Signal 5: kexec_load_disabled ---
	kexecPath := util.KexecLoadThreshold()
	kexecDisabled := stealthReadFirstLine(kexecPath)
	if kexecDisabled != "" {
		kexecVal := strings.TrimSpace(kexecDisabled)
		fmt.Fprintf(os.Stdout, "\t     kexec_load_disabled=%s\n", kexecVal)
		hasSysBoot := hasCapability("cap_sys_boot")
		if kexecVal == "0" && hasSysBoot {
			fmt.Fprintf(os.Stdout, "\t[GREEN] kexec_load enabled + CAP_SYS_BOOT — can kexec_load a new kernel → full host takeover\n")
			fmt.Fprintf(os.Stdout, "\t         escape: prepare bzImage + initrd, call kexec_load, then kexec -e\n")
			findings++
		} else if kexecVal == "0" {
			fmt.Fprintf(os.Stdout, "\t[AMBER] kexec_load enabled but no CAP_SYS_BOOT\n")
		}
	}

	// --- Signal 6: perf_event_paranoid ---
	perfPath := util.PerfEventParanoid()
	perfParanoid := stealthReadFirstLine(perfPath)
	if perfParanoid != "" {
		perfVal := strings.TrimSpace(perfParanoid)
		fmt.Fprintf(os.Stdout, "\t     perf_event_paranoid=%s\n", perfVal)
		hasSysAdmin := hasCapability("cap_sys_admin")
		if (perfVal == "0" || perfVal == "-1") && hasSysAdmin {
			fmt.Fprintf(os.Stdout, "\t[GREEN] perf_event_paranoid=%s + CAP_SYS_ADMIN — perf_event_open can sample host kernel\n", perfVal)
			fmt.Fprintf(os.Stdout, "\t         escape: use perf_event_open with PERF_SAMPLE_CALLCHAIN to leak kernel pointers\n")
			findings++
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 2 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d kernel escape vectors — kernel-level host compromise VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     These are among the most reliable container escapes (no cgroup dependency).\n")
	} else if findings == 1 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] 1 kernel escape indicator detected.\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no kernel escape surface detected.\n")
	}
}

// stealthReadFirstLine reads the first line of a file using StealthReadFile.
func stealthReadFirstLine(path string) string {
	data, err := util.StealthReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	lines := strings.SplitN(string(data), "\n", 2)
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

// stealthFileWritable returns true if the file can be opened O_RDWR.
// Uses StealthOpen to avoid libc hooks.
func stealthFileWritable(path string) bool {
	fd, err := util.StealthOpen(path, syscall.O_RDWR)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.kernel_escape_surface",
		"Detect kernel escape vectors: core_pattern, uevent_helper, modprobe, kexec, perf_event (T67)",
		[]string{"InContainer"},
		func() { CheckKernelEscapeSurface() },
	)
}
