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
	"strconv"
	"strings"
	"syscall"
)

// io_uring_disabled sysctl values (from Linux UAPI
// Documentation/admin-guide/sysctl/kernel.rst):
//
//	0  io_uring is fully available to all tasks (default on pre-6.x kernels)
//	1  io_uring is restricted to tasks with CAP_SYS_ADMIN / CAP_SYS_RAWIO
//	   (depending on exact kernel version)
//	2  io_uring is globally disabled; every io_uring_setup call returns
//	   -EPERM regardless of privileges
//
// Values above 2 are reserved and treated as "more restrictive than 2".

// iouringDisabledMeaning maps the numeric sysctl value to a human readable
// description used in the operator report.
var iouringDisabledMeaning = map[string]string{
	"0": "fully enabled (all users)",
	"1": "restricted (privileged-only / capability-gated)",
	"2": "globally disabled (EPERM for everyone)",
}

// iouringSyscallNR returns the Linux syscall NR for io_uring_setup on the
// running arch, or 0 if the arch is unknown.  io_uring was merged in 5.1
// (2019) so the NRs are well-established across every mainstream arch.
//
// NR source: each arch's <asm/unistd.h>.  These values are stable ABI —
// they never change.
func iouringSyscallNR() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 425
	case "arm64":
		return 425
	case "386":
		return 425
	case "arm":
		return 425
	case "riscv64":
		return 425
	case "ppc64le":
		return 425
	case "s390x":
		return 425
	default:
		return 0
	}
}

// probeIoUringSetup executes io_uring_setup(entries=0, params=NULL) via
// RawSyscall6.  The argument tuple is provably side-effect free:
//
//   - entries=0 is explicitly rejected by io_uring.c:io_uring_setup() with
//     -EINVAL before any rings, SQEs, or CQEs are allocated.  The function
//     returns without touching any task state (verified against Linux
//     5.10..6.12 source).
//   - params=NULL: the kernel only dereferences params when entries > 0.
//
// The only two outcomes are therefore:
//
//  1. kernel reached io_uring_setup and validated args → -EINVAL
//  2. io_uring was compiled out / seccomp blocked it / io_uring_disabled≥2
//     → -ENOSYS / -EPERM / -EACCES / other errno
//
// LockOSThread is used for hygiene (no state change possible, but it
// matches the pattern used by seccomp_deep_inspect and lsm_enumerate).
func probeIoUringSetup(nr uintptr) (syscallVerdict, syscall.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, _, errNo := syscall.RawSyscall6(nr,
		0, // entries = 0 → kernel immediately returns -EINVAL
		0, // struct io_uring_params __user *params = NULL
		0, 0, 0, 0)
	return classifyErrno(errNo), errNo
}

// CheckIoUring runs the two-signal io_uring surface audit:
//
//  Signal A — /proc/sys/kernel/io_uring_disabled sysctl read.
//    Admin-level knob that restricts io_uring globally.
//
//  Signal B — io_uring_setup(0, NULL) raw-syscall probe.
//    Answers three questions independently of the sysctl:
//      (i)   does the running kernel have io_uring compiled in?
//      (ii)  did seccomp (SECCOMP_RET_ERRNO / RET_KILL_PROCESS) block it?
//      (iii) does io_uring_disabled cause EPERM for this task?
//
// OPSEC: reads exactly one /proc file, executes exactly one raw syscall
// with args guaranteed side-effect-free.  No shell, no fork, no network,
// no filesystem writes.  Safe to run in every container context.
//
// T49 / system.io_uring.
func CheckIoUring(ctx *Context) error {
	nr := iouringSyscallNR()
	if nr == 0 {
		fmt.Printf("io_uring: skipping — arch %q has no known io_uring_setup NR\n",
			runtime.GOARCH)
		return nil
	}

	// ---- 1. sysctl signal ---------------------------------------------
	sysctlVal := readFileFirstLine("proc/sys/kernel/io_uring_disabled")
	sysctlTrim := strings.TrimSpace(sysctlVal)

	fmt.Printf("io_uring audit (T49)\n")
	if sysctlTrim == "" {
		fmt.Printf("\tsysctl  kernel/io_uring_disabled  : <file missing>\n")
		fmt.Printf("\t        (kernel may predate 5.19, when the sysctl was added; probe\n")
		fmt.Printf("\t         result below is authoritative regardless)\n")
	} else {
		meaning, ok := iouringDisabledMeaning[sysctlTrim]
		if !ok {
			meaning = fmt.Sprintf("unknown value %q (treat as ≥2 / globally-restrictive)",
				sysctlTrim)
		}
		fmt.Printf("\tsysctl  kernel/io_uring_disabled  : %s  —  %s\n",
			sysctlTrim, meaning)
	}

	// Parse numeric for downstream logic.  Unknown / missing → treat as
	// level "0" (don't assume restriction; let the probe carry the weight).
	var disabledLevel int
	if sysctlTrim != "" {
		if v, err := strconv.Atoi(sysctlTrim); err == nil {
			disabledLevel = v
		}
	}

	// ---- 2. syscall probe signal --------------------------------------
	verdict, errNo := probeIoUringSetup(nr)

	errnoDisp := errNo.Error()
	if errNo == 0 {
		errnoDisp = "0 (no-error — SURPRISING: entries=0 should EINVAL)"
	} else if strings.HasPrefix(errnoDisp, "errno ") {
		errnoDisp = fmt.Sprintf("errno=%d", int(errNo))
	}

	var colour string
	switch verdict {
	case VerdictPassed:
		colour = "[GREEN]" // io_uring syscall reached the kernel
	case VerdictBlocked:
		colour = "[AMBER]" // seccomp / kernel-side disable blocked it
	default:
		colour = "[  ?  ]"
	}

	fmt.Printf("\tprobe   io_uring_setup(0, NULL)   : %s  (%s)\n",
		verdict, errnoDisp)

	// ---- 3. combined interpretation -----------------------------------
	// Map the (sysctl, probe) pair into an operator conclusion.
	var conclusion string
	exploitable := false

	switch {
	// Case 1: fully open.
	case disabledLevel == 0 && verdict == VerdictPassed:
		exploitable = true
		conclusion = "io_uring is AVAILABLE and UNRESTRICTED for this task." +
			"  Modern io_uring-based container escape primitives (pipe_buffer," +
			" msg_zerocopy, SQE-fixed-buffer, etc.) are in play."

	// Case 2: sysctl=1 (priv-gated) but probe still reached kernel (EINVAL).
	// This happens when the container is privileged (CAP_SYS_ADMIN present),
	// which is exactly the scenario a red-team operator cares about.
	case disabledLevel == 1 && verdict == VerdictPassed:
		exploitable = true
		// Check the priv flag if available for a sharper message.
		env := ctx.Env
		if env != nil && env.Privileged {
			conclusion = "io_uring is gated at sysctl level 1 (capability-only)" +
				" AND this task cleared the gate (probe reached kernel)." +
				"  Privileged container + io_uring = full escape surface available."
		} else {
			conclusion = "io_uring is gated at sysctl level 1, yet the probe" +
				" reached the kernel.  Either the kernel is new enough to accept" +
				" entries=0 validation before the CAP check, or the task has" +
				" extra capabilities.  Treat io_uring surface as REACHABLE."
		}

	// Case 3: sysctl=2 (global disable).  Expected: EPERM from probe.
	case disabledLevel >= 2:
		conclusion = "io_uring is globally disabled (sysctl level ≥2)." +
			"  Probe outcome matches expectation — no io_uring escape surface."

	// Case 4: probe was blocked (seccomp ENOSYS/ERRNO) regardless of sysctl.
	case verdict == VerdictBlocked:
		if errNo == syscall.ENOSYS {
			conclusion = "io_uring_setup returned ENOSYS — either the kernel" +
				" was built without CONFIG_IO_URING=y, or a seccomp filter" +
				" injected ENOSYS.  Surface is NOT reachable."
		} else if errNo == syscall.EPERM || errNo == syscall.EACCES {
			conclusion = fmt.Sprintf("io_uring_setup blocked with %s — likely"+
				" io_uring_disabled≥2 enforcement OR seccomp RET_ERRNO injector."+
				"  Surface is NOT reachable.", errnoDisp)
		} else {
			conclusion = fmt.Sprintf("io_uring_setup blocked with unusual errno"+
				" %s.  Treat as seccomp-filtered; surface NOT reachable.",
				errnoDisp)
		}

	// Case 5: ambiguous (shouldn't happen in practice).
	default:
		conclusion = "ambiguous result — combine sysctl + probe manually."
	}

	if exploitable {
		fmt.Printf("\t%s %s\n", "[!]", conclusion)
	} else {
		fmt.Printf("\t%s %s\n", colour, conclusion)
	}

	// ---- 4. extra operator breadcrumbs --------------------------------
	// Point the operator at the specific kernel version / CVEs that use
	// io_uring as a primitive, since that's what a post-exploitation step
	// would look up next.
	if exploitable {
		fmt.Printf("\tinfo  : common io_uring exploitation vectors worth checking:\n")
		fmt.Printf("\t        - pipe_buffer primitive (CVE-2022-0847 DirtyPipe lookalikes)\n")
		fmt.Printf("\t        - io_uring-fixed-buffer UAF / overwrites\n")
		fmt.Printf("\t        - msg_zerocopy cross-netns leaks\n")
		fmt.Printf("\t        - IORING_OP_SENDMSG on raw sockets (CAP_NET_RAW adjacency)\n")
	}
	if disabledLevel == 0 && verdict == VerdictBlocked && sysctlTrim != "" {
		// Sysctl says "open" but seccomp says "closed".  That's a defence-in-depth
		// win worth calling out explicitly, since the operator might not realize
		// the runtime added an extra layer.
		fmt.Printf("\tinfo  : DEFENCE-IN-DEPTH — sysctl permits io_uring but the"+
			" container runtime's seccomp profile blocked it anyway.\n")
	}

	return nil
}

func init() {
	RegisterContextPrereqCheck(CategorySecurity, "system.io_uring",
		"io_uring surface audit: /proc/sys/kernel/io_uring_disabled + io_uring_setup(0,NULL) probe (T49)",
		[]string{"InContainer"},
		CheckIoUring)
}
