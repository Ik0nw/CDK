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
	"syscall"
	"unsafe"
)

// T46: security.seccomp_advanced — probe seccomp(2) feature-set that
// T41 (seccomp_deep_inspect) doesn't cover.
//
// The 12-syscall T41 probe answers: "which escape-relevant syscalls
// reached the kernel?"  This probe answers the complementary
// questions an attacker asks AFTER learning a BPF filter is active:
//
//   1. Which seccomp return-actions does this KERNEL support at all?
//      (KILL_PROCESS? USER_NOTIF? TRACE? if not, bypass options open.)
//   2. Is SECCOMP_USER_NOTIF / ioctl(SECCOMP_USER_NOTIF_FLAG_CONTINUE)
//      available?  A USER_NOTIF agent means a userland process is
//      proxying syscall decisions — agents have bugs and state leaks.
//   3. Are the FLAG_* bits on SECCOMP_SET_MODE_FILTER supported?
//      (NEW_LISTENER → agent proxy; TSYNC → multi-thread sync races
//      for thread bypass; SPEC_ALLOW → speculation barriers disabled.)
//
// All probes are read-only / NULL-arg / invalid-flag probes.  We never
// install a real filter.
//
// op values (from linux/seccomp.h):
//   SECCOMP_SET_MODE_STRICT   = 0
//   SECCOMP_SET_MODE_FILTER   = 1
//   SECCOMP_GET_ACTION_AVAIL  = 5  // since 4.14
//   SECCOMP_GET_NOTIF_SIZES   = 6  // since 5.0
//
// return-action values (low 16 bits of the SECCOMP_RET_* constants):
const (
	SECCOMP_RET_KILL_PROCESS = 0x80000000 // 5.11+
	SECCOMP_RET_KILL_THREAD  = 0x00000000 // original
	SECCOMP_RET_ERRNO        = 0x00050000 // standard
	SECCOMP_RET_TRAP         = 0x00030000
	SECCOMP_RET_USER_NOTIF   = 0x7fc00000 // 5.0+
	SECCOMP_RET_TRACE        = 0x7ff00000
	SECCOMP_RET_LOG          = 0x7ffc0000 // 4.14+
)

// SECCOMP_SET_MODE_FILTER flags:
const (
	_FILTER_FLAG_TSYNC        = 1 << 0
	_FILTER_FLAG_NEW_LISTENER = 1 << 3 // 5.0+ (user-notif listener)
	_FILTER_FLAG_SPEC_ALLOW   = 1 << 4 // 5.14+ (Speculative Store Bypass disabled on filter-exec paths)
)

type seccompActionDef struct {
	Name  string
	Value uint32
	Note  string
}

// Ordered from strictest → most permissive.  An attacker wants to see
// KILL_PROCESS absent + USER_NOTIF / TRACE present — the latter two
// have well-known bypass / hijack primitives.
var seccompActionTable = []seccompActionDef{
	{"KILL_PROCESS", SECCOMP_RET_KILL_PROCESS, "5.11+, strict gate (process-scoped kill)"},
	{"KILL_THREAD",  SECCOMP_RET_KILL_THREAD,  "standard (thread-scoped kill)"},
	{"ERRNO",        SECCOMP_RET_ERRNO,        "standard"},
	{"TRAP",         SECCOMP_RET_TRAP,         "standard (SIGSYS trap)"},
	{"USER_NOTIF",   SECCOMP_RET_USER_NOTIF,   "5.0+ — seccomp agent syscall proxy present"},
	{"TRACE",        SECCOMP_RET_TRACE,        "standard (PTRACE interaction vector)"},
	{"LOG",          SECCOMP_RET_LOG,          "4.14+ — audit-only, no enforcement"},
}

// seccomp() wrapper — hits the kernel directly (RawSyscall6).
// args: op, flags, *args
func rawSeccomp(op uintptr, flags uintptr, args unsafe.Pointer) (int, syscall.Errno) {
	r1, _, errno := syscall.RawSyscall6(
		nr_seccomp,
		op, flags, uintptr(args),
		0, 0, 0,
	)
	return int(r1), errno
}

func secAdvOut() *os.File { return os.Stdout }

// ProbeSeccompAdvanced implements the T46 check.
//
// Design note on side-effect-freedom:
//   - SECCOMP_GET_ACTION_AVAIL (op=5): reads one u32 (action) via *args,
//     returns 0 on supported, EOPNOTSUPP on unsupported.  Read-only.
//   - SECCOMP_GET_NOTIF_SIZES (op=6): reads a struct seccomp_notif_sizes
//     into *args.  We pass NULL so the kernel fills -EFAULT and returns
//     the sizes on the return path only if the op is supported.  ENOSYS
//     means kernel < 5.0.  Read-only.
//   - FLAG probes: op=SECCOMP_SET_MODE_FILTER with the candidate flags
//     OR'd together and args=NULL.  The kernel validates the flag bits
//     THEN checks args; EFAULT = flags accepted (valid), EINVAL = flag
//     not supported.  No filter is ever installed.
func ProbeSeccompAdvanced() {
	fmt.Fprintln(secAdvOut(), "security.seccomp_advanced — seccomp(2) capabilities:")
	fmt.Fprintln(secAdvOut(), "\t(7 actions + notif sizes + set-mode filter flags)")

	// -----------------------------------------------------------------
	// Table 1 — per-action availability via SECCOMP_GET_ACTION_AVAIL.
	// -----------------------------------------------------------------
	fmt.Fprintln(secAdvOut(), "\tactions supported via SECCOMP_GET_ACTION_AVAIL (op=5):")
	supported := 0
	strictCnt := 0
	hasUserNotif := false
	hasKillProcess := false
	for _, a := range seccompActionTable {
		actionVal := a.Value
		_, errno := rawSeccomp(5, 0, unsafe.Pointer(&actionVal))
		var verdict, color, tag string
		if errno == 0 {
			supported++
			verdict = "YES"
			color = "GREEN"
			switch a.Name {
			case "USER_NOTIF":
				hasUserNotif = true
				tag = "→ seccomp agent syscall proxy present"
			case "TRACE":
				tag = "→ ptrace vector may hijack filter decisions"
			case "LOG":
				tag = "→ logged only, no enforcement impact"
			}
			if a.Name == "KILL_PROCESS" {
				hasKillProcess = true
				color = "AMBER"
				tag = "→ process-wide kill gate enabled"
				strictCnt++
			}
			if a.Name == "KILL_THREAD" {
				strictCnt++
			}
		} else if errno == syscall.EOPNOTSUPP {
			verdict = "NO "
			color = "  ?  "
			tag = fmt.Sprintf("(kernel: %v)", errno)
		} else {
			verdict = "NO "
			color = "  ?  "
			tag = fmt.Sprintf("(errno=%v)", errno)
		}
		fmt.Fprintf(secAdvOut(), "\t\t[%s] %-12s = %-3s — %s %s\n",
			color, a.Name, verdict, a.Note, tag)
	}

	// -----------------------------------------------------------------
	// Probe 2 — SECCOMP_GET_NOTIF_SIZES (op=6).
	//   NULL args → returns struct sizes on success, -EFAULT on
	//   copy_to_user failure (still indicates feature present).
	// -----------------------------------------------------------------
	_, eSizes := rawSeccomp(6, 0, nil)
	hasNotifSizes := false
	switch eSizes {
	case 0:
		hasNotifSizes = true
		fmt.Fprintln(secAdvOut(), "\t\t[GREEN] SECCOMP_GET_NOTIF_SIZES (op=6) OK — notif ioctl contract present")
	case syscall.EFAULT:
		hasNotifSizes = true
		fmt.Fprintln(secAdvOut(), "\t\t[GREEN] SECCOMP_GET_NOTIF_SIZES reached kernel (got EFAULT on NULL args — feature present)")
	case syscall.ENOSYS:
		fmt.Fprintln(secAdvOut(), "\t\t[  ?  ] SECCOMP_GET_NOTIF_SIZES = ENOSYS — kernel < 5.0 (no notif support)")
	default:
		fmt.Fprintf(secAdvOut(), "\t\t[  ?  ] SECCOMP_GET_NOTIF_SIZES unexpected errno=%v\n", eSizes)
	}

	// -----------------------------------------------------------------
	// Probe 3 — FLAG validity on SECCOMP_SET_MODE_FILTER.
	//   Pass flags OR'd together + args=NULL.  Valid flag bits → EFAULT
	//   (after flag validation); invalid bits → EINVAL.
	//   ENOSYS means kernel < 3.5 (no SECCOMP_SET_MODE_FILTER).
	// -----------------------------------------------------------------
	flagBits := [...]struct {
		Name  string
		Value uintptr
		Desc  string
	}{
		{"TSYNC",         _FILTER_FLAG_TSYNC,         "multi-thread sync vector"},
		{"NEW_LISTENER",  _FILTER_FLAG_NEW_LISTENER,  "user-notif listener (seccomp agent proxy)"},
		{"SPEC_ALLOW",    _FILTER_FLAG_SPEC_ALLOW,    "disable speculative-exec barriers on filter-path"},
	}
	fmt.Fprintln(secAdvOut(), "\tSET_MODE_FILTER flag support (single-bit probes):")
	flagSupp := make(map[string]bool)
	for _, f := range flagBits {
		_, errno := rawSeccomp(1, f.Value, nil)
		// Expected: if flag is valid, args=NULL fails validation with
		// EFAULT (after flags are accepted).  If flag unknown, EINVAL.
		var verdict, color string
		switch errno {
		case syscall.EFAULT:
			verdict = "VALID"
			color = "  ?  "
			flagSupp[f.Name] = true
		case syscall.EINVAL:
			verdict = "UNSUPPORTED"
			color = "  ?  "
			flagSupp[f.Name] = false
		default:
			verdict = fmt.Sprintf("UNEXPECTED-%v", errno)
			color = "  ?  "
		}
		// NEW_LISTENER = USER_NOTIF support — attacker-relevant.
		if f.Name == "NEW_LISTENER" && flagSupp[f.Name] {
			color = "GREEN"
		}
		// SPEC_ALLOW not supported = speculation barriers still in place
		// on filter-hit paths; that's GOOD for isolation, so AMBER.
		if f.Name == "SPEC_ALLOW" && !flagSupp[f.Name] {
			color = "AMBER"
		}
		fmt.Fprintf(secAdvOut(), "\t\t[%s] %-12s = %s — %s\n", color, f.Name, verdict, f.Desc)
	}

	// -----------------------------------------------------------------
	// Summary + advisory.
	// -----------------------------------------------------------------
	fmt.Fprintf(secAdvOut(), "\t  summary: actions=%d/7 strict_gates=%d user_notif=%v notif_sizes_abi=%v\n",
		supported, strictCnt, hasUserNotif, hasNotifSizes)

	switch {
	case hasUserNotif && !hasKillProcess:
		fmt.Fprintln(secAdvOut(), "\t  advisory: [GREEN] USER_NOTIF supported but KILL_PROCESS absent.")
		fmt.Fprintln(secAdvOut(), "\t            Seccomp policy is agent-driven; consider USER_NOTIF hijack + LOG/TRACE bypass paths.")
	case !hasUserNotif && hasKillProcess:
		fmt.Fprintln(secAdvOut(), "\t  advisory: [AMBER] KILL_PROCESS gate is present; USER_NOTIF is not.")
		fmt.Fprintln(secAdvOut(), "\t            Filter profile is strict-by-default; focus ERRNO/TRACE return vectors for information leaks.")
	case hasUserNotif && hasKillProcess:
		fmt.Fprintln(secAdvOut(), "\t  advisory: [  ?  ] BOTH KILL_PROCESS + USER_NOTIF present.")
		fmt.Fprintln(secAdvOut(), "\t            Need actual filter behavior (see security.seccomp_deep_inspect) — both strict and open can produce this combo.")
	default:
		fmt.Fprintln(secAdvOut(), "\t  advisory: [  ?  ] Kernel < 5.x vintage; only KILL_THREAD/ERRNO/TRAP/LOG.")
		fmt.Fprintln(secAdvOut(), "\t            Classic 2015-2020 seccomp bypass playbook applies.")
	}
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.seccomp_advanced",
		"Probe seccomp(2) actions support (KILL_PROCESS / USER_NOTIF / TRACE) + notif sizes + TSYNC/SPEC_ALLOW flags [F7]",
		[]string{"InContainer"},
		func() { ProbeSeccompAdvanced() },
	)
}
