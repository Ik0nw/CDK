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
	"regexp"
	"strings"
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckKernelPointerLeaks audits whether kernel pointers are exposed to
// userspace, which enables KASLR bypass and simplifies kernel exploitation.
//
// Sources of kernel pointer leaks:
//  1. /proc/kallsyms — if kptr_restrict is 0, symbol addresses are visible
//  2. /proc/modules — if kptr_restrict is 0, module base addresses visible
//  3. dmesg / kernel log — if dmesg_restrict is 0, kernel pointers in logs
//  4. /sys/kernel/notes, /sys/kernel/uevent_seqcount
//  5. /proc/stat, /proc/vmallocinfo (sometimes leak addresses)
//
// OPSEC: read-only.  We open files with O_RDONLY|O_CLOEXEC.  We only
// read the first few lines of each file to check for pointer patterns.
// No syscalls that modify kernel state.
//
// T62 / security.kptr_leak.
func CheckKernelPointerLeaks() {
	fmt.Fprintf(os.Stdout, "kernel pointer leak audit (T62) — KASLR bypass potential:\n")

	leakSources := 0

	// --- /proc/kallsyms ---
	kptrRestrict := getKptrRestrict()
	kallsymsLeak := checkKallsymsLeak()

	switch {
	case kallsymsLeak && kptrRestrict == 0:
		fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/kallsyms — kernel symbols VISIBLE (kptr_restrict=0)\n")
		fmt.Fprintf(os.Stdout, "\t         KASLR fully bypassed — all symbol addresses readable\n")
		leakSources++
	case kallsymsLeak:
		fmt.Fprintf(os.Stdout, "\t[AMBER] /proc/kallsyms — some symbols visible (kptr_restrict=%d)\n", kptrRestrict)
		leakSources++
	default:
		fmt.Fprintf(os.Stdout, "\t[AMBER] /proc/kallsyms — symbols hidden or all zeros (kptr_restrict=%d)\n", kptrRestrict)
	}

	// --- /proc/modules ---
	modulesLeak := checkModulesLeak()
	if modulesLeak {
		fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/modules — module base addresses VISIBLE\n")
		fmt.Fprintf(os.Stdout, "\t         KASLR bypass for loaded modules\n")
		leakSources++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] /proc/modules — addresses hidden or all zeros\n")
	}

	// --- dmesg_restrict ---
	dmesgRestrict := getDmesgRestrict()
	if dmesgRestrict == 0 {
		fmt.Fprintf(os.Stdout, "\t[GREEN] dmesg_restrict=0 — kernel ring buffer accessible to all users\n")
		fmt.Fprintf(os.Stdout, "\t         kernel pointers in dmesg output may leak KASLR offsets\n")
		leakSources++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] dmesg_restrict=%d — kernel ring buffer restricted\n", dmesgRestrict)
	}

	// --- /proc/vmallocinfo ---
	vmallocLeak := checkVmallocInfoLeak()
	if vmallocLeak {
		fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/vmallocinfo — vmalloc addresses VISIBLE\n")
		leakSources++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] /proc/vmallocinfo — addresses hidden or unreadable\n")
	}

	// --- /sys/kernel/notes ---
	notesLeak := checkSysKernelNotes()
	if notesLeak {
		fmt.Fprintf(os.Stdout, "\t[GREEN] /sys/kernel/notes — readable (may contain kernel build info)\n")
	}

	// --- /proc/kcore ---
	kcoreReadable := checkKcoreReadable()
	if kcoreReadable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] /proc/kcore — READABLE! Full kernel memory dump possible\n")
		fmt.Fprintf(os.Stdout, "\t         CRITICAL: complete kernel memory accessible to container\n")
		leakSources++
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if leakSources > 0 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d kernel pointer leak source(s) — KASLR bypass VIABLE.\n", leakSources)
		fmt.Fprintf(os.Stdout, "\t     Kernel exploits (e.g. dirty pipe, pipe_buffer) become significantly easier.\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no significant kernel pointer leaks detected.\n")
	}
}

// getKptrRestrict reads /proc/sys/kernel/kptr_restrict.
func getKptrRestrict() int {
	line := readFileFirstLine("proc/sys/kernel/kptr_restrict")
	if line == "" {
		return -1 // unknown
	}
	var val int
	fmt.Sscanf(line, "%d", &val)
	return val
}

// getDmesgRestrict reads /proc/sys/kernel/dmesg_restrict.
func getDmesgRestrict() int {
	line := readFileFirstLine("proc/sys/kernel/dmesg_restrict")
	if line == "" {
		return -1
	}
	var val int
	fmt.Sscanf(line, "%d", &val)
	return val
}

// kernelPtrRegex matches a kernel virtual address (0xffff... or 0xffff...)
var kernelPtrRegex = regexp.MustCompile(`0xffff[0-9a-f]{8,12}`)

// nonZeroKernelPtr matches a kernel pointer that's not all zeros.
var nonZeroKernelPtr = regexp.MustCompile(`0xffff[0-9a-f]*[1-9a-f][0-9a-f]*`)

// checkKallsymsLeak returns true if /proc/kallsyms exposes non-zero addresses.
func checkKallsymsLeak() bool {
	kallsymsPath := util.ProcKallsymsPath()
	lines := readFileLines("proc/kallsyms")
	if len(lines) == 0 {
		// Try direct open in case readFileLines (which uses envRoot) has issues.
		fd, err := util.StealthOpen(kallsymsPath, syscall.O_RDONLY)
		if err != nil {
			return false
		}
		util.StealthClose(fd)
		// File exists but we couldn't parse — try reading a few lines.
		data, err := util.StealthReadFile(kallsymsPath)
		if err != nil || len(data) == 0 {
			return false
		}
		lines = strings.SplitN(string(data), "\n", 50)
	}

	// Check first 50 lines for non-zero kernel addresses.
	limit := 50
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 0; i < limit; i++ {
		if nonZeroKernelPtr.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// checkModulesLeak returns true if /proc/modules exposes non-zero base addresses.
func checkModulesLeak() bool {
	lines := readFileLines("proc/modules")
	if len(lines) == 0 {
		return false
	}
	// /proc/modules format: name size refcount deps state address [options]
	// The address field is a hex number (without 0x prefix typically).
	hexAddr := regexp.MustCompile(`\b[0-9a-f]{8,16}\b`)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Field at index 5 should be the address (0x... or just hex).
		addrField := fields[5]
		if hexAddr.MatchString(addrField) {
			// Check it's not all zeros.
			if addrField != "0000000000000000" && addrField != "0x0000000000000000" {
				return true
			}
		}
	}
	return false
}

// checkVmallocInfoLeak returns true if /proc/vmallocinfo exposes non-zero addresses.
func checkVmallocInfoLeak() bool {
	lines := readFileLines("proc/vmallocinfo")
	if len(lines) == 0 {
		return false
	}
	limit := 20
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 0; i < limit; i++ {
		if kernelPtrRegex.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// checkSysKernelNotes returns true if /sys/kernel/notes is readable.
func checkSysKernelNotes() bool {
	fd, err := util.StealthOpen("/sys/kernel/notes", syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

// checkKcoreReadable returns true if /proc/kcore is readable.
func checkKcoreReadable() bool {
	fd, err := util.StealthOpen(util.ProcKcorePath(), syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.kptr_leak",
		"Detect kernel pointer leaks via /proc/kallsyms, /proc/modules, dmesg, vmallocinfo, kcore (T62)",
		[]string{"InContainer"},
		func() { CheckKernelPointerLeaks() },
	)
}
