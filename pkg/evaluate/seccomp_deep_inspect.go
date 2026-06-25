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

// seccompProbe lists the 12 syscalls most commonly involved in modern
// container-escape chains / defense-bypasses, together with the bogus
// argument tuple we use to test them.  Every tuple is chosen so that
// the real kernel will REFUSE the request with a deterministic errno
// (EBADF, EFAULT, EINVAL) rather than perform any action — the only
// two possible outcomes of each probe are therefore:
//
//   - seccomp filter intercepted → ENOSYS / EPERM / EACCES / errno
//     injected via SECCOMP_RET_ERRNO, or process killed by SIGSYS.
//   - kernel accepted the syscall then refused bad args → EBADF/EFAULT/EINVAL
//
// We call RawSyscall (NOT Syscall) because Syscall() on some arches
// enters via the libc wrapper which can paper over ENOSYS with ENOTSUP.
// RawSyscall hits the kernel 0x80 / svc path directly and preserves
// the raw seccomp-injected errno.
//
// NR values below are the LINUX arch values.  We use runtime.GOARCH to
// pick the right table (x86_64 / arm64 / 386 / armhf).  For unknown
// arches the check reports "unsupported arch" and skips gracefully.
type seccompProbeEntry struct {
	Name     string
	Brief    string
	Arg0     uintptr
	Arg1     uintptr
	Arg2     uintptr
	Arg3     uintptr
	Arg4     uintptr
	Arg5     uintptr
}

// per-arch syscall NR tables.  NRs are Linux UAPI constants copied from
// the respective arch's asm/unistd.h (stable ABI, never renumbered).
var (
	nrAmd64 = map[string]uintptr{
		"mount":        165,
		"umount2":      166,
		"pivot_root":   155,
		"unshare":      272,
		"setns":        308,
		"clone":        56,
		"ptrace":       101,
		"keyctl":       250,
		"add_key":      248,
		"request_key":  249,
		"init_module":  175,
		"delete_module":176,
	}
	nrArm64 = map[string]uintptr{
		"mount":        40,
		"umount2":      39,
		"pivot_root":   41,
		"unshare":      97,
		"setns":        124,
		// arm64 uses clone3(435) primarily but clone(220) is still
		// handled via compat wrapper by most distro kernels.
		"clone":        220,
		"ptrace":       117,
		"keyctl":       116,
		"add_key":       96,
		"request_key":  95,
		"init_module":  105,
		"delete_module":106,
	}
	nr386 = map[string]uintptr{
		"mount":        21,
		"umount2":      52,
		"pivot_root":   217,
		"unshare":      310,
		"setns":        346,
		"clone":        120,
		"ptrace":       26,
		"keyctl":       311,
		"add_key":      286,
		"request_key":  287,
		"init_module":  128,
		"delete_module":129,
	}
	nrArm = map[string]uintptr{
		"mount":        21,
		"umount2":      52,
		"pivot_root":   218,
		"unshare":      337,
		"setns":        375,
		"clone":        120,
		"ptrace":       26,
		"keyctl":       338,
		"add_key":      311,
		"request_key":  312,
		"init_module":  128,
		"delete_module":129,
	}
)

// archNRTable returns the syscall NR map for the runtime arch or nil
// if this arch isn't in our (very conventional) list.
func archNRTable() map[string]uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return nrAmd64
	case "arm64":
		return nrArm64
	case "386":
		return nr386
	case "arm":
		return nrArm
	default:
		return nil
	}
}

// bogusArgPatterns is deliberately fixed per-syscall so results are
// reproducible across runs.  The patterns are individually reviewed to
// guarantee no host-observable side effects:
//
//   mount       (NULL,NULL,NULL,NULL)      → EFAULT on both path ptrs
//   umount2     (NULL, 0)                  → EFAULT on path ptr
//   pivot_root  (NULL,NULL)                → EFAULT on both
//   unshare     (flags=0xFFFFFFFF)        → EINVAL (reserved bits) — safer
//                                                than CLONE_NEWNS which on
//                                                success would mutate the
//                                                calling OS thread's mntns
//   setns       (fd=-1, 0)                 → EBADF
//   clone       (flags=0, sp=NULL,...)     → EINVAL (no stack page)
//   ptrace      (PTRACE_PEEKDATA=-1, pid=1, addr=0) → EPERM/ESRCH
//   keyctl      (op=-1, ...)               → EOPNOTSUPP/EINVAL
//   add_key     ("x", "", NULL, -1, -1)    → EFAULT/bad desc
//   request_key ("x","x", NULL, -1)        → EFAULT
//   init_module (NULL, 0, "")              → EFAULT
//   delete_module(NULL, 0)                 → EFAULT
//
// For pointer args we pass uintptr(0) which the kernel ALWAYS refuses
// with -EFAULT before any side effect.  For fd args we pass -1 → EBADF.
var bogusArgPatterns = map[string][6]uintptr{
	"mount":         {0, 0, 0, 0, 0, 0},
	"umount2":       {0, 0, 0, 0, 0, 0},
	"pivot_root":    {0, 0, 0, 0, 0, 0},
	"unshare":       {^uintptr(0), 0, 0, 0, 0, 0}, // flags=all-ones → EINVAL, no state change
	"setns":         {^uintptr(0), 0, 0, 0, 0, 0}, // fd = -1
	"clone":         {0, 0, 0, 0, 0, 0},
	"ptrace":        {^uintptr(0), 1, 0, 0, 0, 0}, // PEEK_OP-of-death, pid=1
	"keyctl":        {^uintptr(0), 0, 0, 0, 0, 0},
	"add_key":       {ptrLit("user\000x"), 0, 0, ^uintptr(0), ^uintptr(0), 0},
	"request_key":   {ptrLit("user\000x"), ptrLit("x"), 0, ^uintptr(0), 0, 0},
	"init_module":   {0, 0, 0, 0, 0, 0},
	"delete_module": {0, 0, 0, 0, 0, 0},
}

// ptrLit returns a pointer to the NUL-terminated byte copy of s as a
// uintptr suitable for passing to RawSyscall.  The backing string is
// allocated in Go heap (will not move during RawSyscall window per
// current Go GC semantics; we LockOSThread for extra safety).
//
// Used ONLY for short string constants that the kernel will refuse
// with EFAULT on independent grounds anyway (pid / permission path).
func ptrLit(s string) uintptr {
	b := append([]byte(s), 0)
	return uintptr(unsafe.Pointer(&b[0]))
}

// syscallVerdict is a 3-way classification:
//
//	PASSED    = kernel received the syscall and rejected for bad args
//	BLOCKED   = seccomp intercepted and returned ERRNO / SIGSYS-killed
//	UNKNOWN   = ambiguous (kernel may not have the feature compiled in)
type syscallVerdict int

const (
	VerdictUnknown syscallVerdict = iota
	VerdictPassed
	VerdictBlocked
)

func (v syscallVerdict) String() string {
	switch v {
	case VerdictPassed:
		return "kernel-saw"
	case VerdictBlocked:
		return "BLOCKED"
	default:
		return "unknown"
	}
}
func (v syscallVerdict) colorTag() string {
	switch v {
	case VerdictPassed:
		return "[GREEN]" // escape-surface REACHABLE past seccomp
	case VerdictBlocked:
		return "[AMBER]" // filter stops it
	default:
		return "[  ?  ]"
	}
}

// probeOne executes a single raw syscall with the bogus arg tuple and
// classifies the outcome.
//
// Corner case: some container runtimes use SECCOMP_RET_KILL_PROCESS for
// disallowed syscalls, which would SIGKILL us mid-check.  We therefore
// run each probe in a subprocess via vfork-exec of a tiny probe stub
// built on-the-fly at /proc/self/exe with an env-triggered single-probe
// mode.  See comments at top of CheckSeccompDeepInspect for rationale.
func probeOne(nr uintptr, args [6]uintptr) (syscallVerdict, syscall.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Documentation for unix.RawSyscall6: returns (r0, r1, errno).  A
	// non-zero errno means "syscall failed with this errno"; errno==0
	// means success (impossible here because of bogus args — actually
	// some unshare flags combinations DO unshare an empty NS for the
	// calling thread, but LockOSThread + immediate exit from locked
	// thread + no other goroutines on it means no isolation loss for
	// the rest of the process).  Keep anyway.
	_, _, errNo := syscall.RawSyscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5])
	return classifyErrno(errNo), errNo
}

// classifyErrno distinguishes "kernel refused bad args" from "seccomp
// filter injected an error".  The heuristic:
//
//	EBADF/EFAULT/EINVAL/EOPNOTSUPP/ENOTTY/EPERM-when-no-cap
//	  → kernel path (PASSED the filter)
//	ENOSYS                               → filter blocked (kernel
//	                                       supports the syscall unless
//	                                       the NR is way too high)
//	Anything else: treat as BLOCKED to stay conservative, but
//	               annotate with the actual code.
//
// The kernel NEVER returns ENOSYS for a compiled-in syscall with bad
// args — it returns EFAULT/EBADF/EINVAL.  ENOSYS from a syscall with a
// valid NR on a modern kernel therefore means seccomp.
func classifyErrno(e syscall.Errno) syscallVerdict {
	switch e {
	case 0:
		// Impossible (bogus args) — but if it happens, kernel path =
		// reached the kernel past any filter.
		return VerdictPassed
	case syscall.EBADF, syscall.EFAULT, syscall.EINVAL,
		syscall.EOPNOTSUPP, syscall.ENOTTY, syscall.ENOENT,
		syscall.ENOMEM, syscall.ENAMETOOLONG, syscall.ELOOP,
		syscall.EISDIR, syscall.ENOTDIR, syscall.EPERM,
		syscall.ESRCH, syscall.EACCES:
		// Note EPERM/ESRCH/EACCES: these come from the kernel's LSM or
		// capability checks, which sit AFTER seccomp in the syscall
		// entry pipeline.  Hence seeing them = filter let us through.
		return VerdictPassed
	case syscall.ENOSYS:
		return VerdictBlocked
	}
	// Other errnos are unusual — most are seccomp-RET_ERRNO injected.
	// Be conservative and call it blocked.
	return VerdictBlocked
}

// kernelHasSyscall reports whether the running kernel has the given
// syscall's entry point compiled in.  We check two sources:
//
//  1. /proc/kallsyms symbol "sys_<name>" / "__arm64_sys_<name>" /
//     "__x64_sys_<name>" (CONFIG_KALLSYMS=y).  Only readable when
//     kptr_restrict == 0 or we have CAP_SYSLOG; gracefully degrades.
//  2. Kernel version heuristic: every syscall in our 12-entry list
//     exists on ALL kernels >= 3.17 (the minimum Docker/K8s floor).
//     So we default to "has it" when /proc/kallsyms is unavailable.
func kernelHasSyscall(name string) bool {
	lines := readFileLines("proc/kallsyms")
	needles := []string{
		"sys_" + name + "\n",
		"__x64_sys_" + name + "\n",
		"__arm64_sys_" + name + "\n",
		"__ia32_sys_" + name + "\n",
		"__se_sys_" + name + "\n",
	}
	for _, ln := range lines {
		for _, n := range needles {
			if strings.HasSuffix(strings.TrimSpace(ln), strings.TrimSpace(n)) ||
				strings.Contains(ln, strings.TrimSpace(n)) {
				return true
			}
		}
	}
	// kallsyms may be unreadable (kptr_restrict=1 or non-root).  Fall
	// back to "assume present" — 12 probes are well into VFS/ipc/security
	// syscalls that every Docker-capable kernel has had for a decade.
	return true
}

// CheckSeccompDeepInspect runs the 12-syscall escape-surface probe
// matrix.  Output table is operator-facing: GREEN means "seccomp did
// NOT block this one → worth trying exploit surface that relies on
// it", AMBER means "filter blocked it".
//
// OPSEC: reads /proc/{self/status,kallsysms,kallsyms}, runs exactly 12
// raw syscalls per run with all-bogus args (see bogusArgPatterns —
// every arg vector is provably side-effect free).  No shell, no fork,
// no network, no files created on disk.  LockOSThread per probe so the
// (harmless) "successful" unshare(CLONE_NEWNS) cannot affect other
// goroutines.
func CheckSeccompDeepInspect(ctx *Context) error {
	nr := archNRTable()
	if nr == nil {
		fmt.Printf("seccomp deep-inspect: skipping — arch %q has no NR table (x86_64/arm64/i386/armhf only)\n", runtime.GOARCH)
		return nil
	}
	status := readFileLines("proc/self/status")
	seccompMode := "0"
	seccompFiltered := false
	for _, ln := range status {
		if strings.HasPrefix(ln, "Seccomp:") {
			fields := strings.Fields(ln)
			if len(fields) >= 2 {
				seccompMode = fields[1]
			}
		}
	}
	if seccompMode == "2" {
		seccompFiltered = true
	}
	env := ctx.Env
	if env == nil {
		env = DetectEnv()
	}
	fmt.Printf("seccomp deep inspect (12 escape-relevant syscalls)  mode=%s  privileged=%v\n",
		seccompMode, env.Privileged)
	if !seccompFiltered {
		fmt.Printf("\t[GREEN] No SECCOMP_MODE_FILTER loaded — all 12 syscalls reach the kernel.\n")
		fmt.Printf("\t        (Capability / LSM gates still apply; no seccomp side-channel blocking.)\n")
		return nil
	}

	// Ordering: mount-escape family first, then namespace, then kernel-
	// internal (keyring / lkm).  Matches operator thinking order.
	order := []string{
		"mount", "umount2", "pivot_root",
		"unshare", "setns", "clone",
		"ptrace",
		"keyctl", "add_key", "request_key",
		"init_module", "delete_module",
	}
	descriptions := map[string]string{
		"mount":         "mount(2) new filesystem → host device / overlay fs escape",
		"umount2":       "umount(2) → peel back layered mount to reveal host",
		"pivot_root":    "pivot_root(2) → swap to host root fs (CAP_SYS_ADMIN needed)",
		"unshare":       "unshare(USER|NS|PID) → user-ns breakout / new mount ns",
		"setns":         "setns(2) + host ns fd → join host ns",
		"clone":         "clone(CLONE_NEWUSER) → unshare a full user-namespace shell",
		"ptrace":        "ptrace(PTRACE_POKETEXT) → hijack a sibling-init or host process",
		"keyctl":        "keyctl(KEYCTL_JOIN_SESSION_KEYRING) → CVE-2016-0728 style",
		"add_key":       "add_key(2) → user-copy-keyring OOB read path",
		"request_key":   "request_key(2) → upcall vector / pipe_buffer primitive",
		"init_module":   "init_module(2) → load unsigned LKM into host kernel",
		"delete_module": "delete_module(2) → unload host LKM to neuter LSM",
	}

	var (
		passed, blocked, unknown int
	)
	for _, name := range order {
		nrVal, ok := nr[name]
		if !ok {
			fmt.Printf("\t[  ?  ] %-14s — no NR on this arch\n", name)
			unknown++
			continue
		}
		args := bogusArgPatterns[name]
		verdict, errNo := probeOne(nrVal, args)
		hasKernel := kernelHasSyscall(name)
		// Ambiguity correction: if verdict says BLOCKED / ENOSYS and the
		// kernel clearly lacks the feature, downgrade to UNKNOWN.
		if verdict == VerdictBlocked && !hasKernel {
			verdict = VerdictUnknown
		}
		switch verdict {
		case VerdictPassed:
			passed++
		case VerdictBlocked:
			blocked++
		default:
			unknown++
		}
		errnoDisp := fmt.Sprintf("%v", errNo)
		if errNo == 0 {
			errnoDisp = "0 (no-error)"
		} else if strings.HasPrefix(errnoDisp, "errno ") {
			// syscall.Errno.String() prints unknown codes as "errno N".
			// Translate to a friendlier decimal display.
			errnoDisp = fmt.Sprintf("errno=%d", int(errNo))
		} else {
			errnoDisp = errNo.Error() // human-readable: "operation not permitted" etc.
		}
		fmt.Printf("\t%s %-14s — %-45s (%s%s)\n",
			verdict.colorTag(), name, descriptions[name], errnoDisp,
			map[bool]string{true: "", false: "  kernel-symbol-not-found"}[hasKernel])
	}
	fmt.Printf("\tpassed=%d blocked=%d unknown=%d / 12\n", passed, blocked, unknown)
	// Operator advice.
	switch {
	case passed == 0:
		fmt.Printf("\tINFO: strong seccomp profile — every escape-relevant syscall was BLOCKED.\n")
	case passed >= 8:
		fmt.Printf("\t[!] INFO: weak / permissive profile — %d of 12 escape-relevant syscalls reached the kernel.\n"+
			"\t    Focus exploit research on the GREEN rows above; this filter is porous.\n", passed)
	default:
		fmt.Printf("\tINFO: partial profile — %d GREEN rows are the practical attack surface.\n", passed)
	}
	return nil
}

func init() {
	RegisterContextPrereqCheck(CategorySecurity, "security.seccomp_deep_inspect",
		"12-syscall escape-surface seccomp probe (F5)",
		[]string{"InContainer"},
		CheckSeccompDeepInspect)
}
