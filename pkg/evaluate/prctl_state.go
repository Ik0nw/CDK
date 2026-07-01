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
	"syscall"
)

// prctl GET option constants (linux/uapi/linux/prctl.h).
// Hard-coded rather than imported from x/sys/unix so the evaluate
// package keeps its zero-cgo cross-compile property on darwin hosts.
const (
	prGetDumpable       = 3  // PR_GET_DUMPABLE
	prGetKeepcaps       = 7  // PR_GET_KEEPCAPS
	prGetSeccomp        = 21 // PR_GET_SECCOMP
	prGetSecurebits     = 27 // PR_GET_SECUREBITS
	prGetNoNewPrivs     = 39 // PR_GET_NO_NEW_PRIVS
	prGetChildSubreaper = 51 // PR_GET_CHILD_SUBREAPER
)

// securebits bit field names (subset — only the bits an operator
// actually cares about when auditing container-escape surfaces).
var securebitNames = []struct {
	mask uintptr
	name string
}{
	{0x01, "SECBIT_NOROOT"},          // setuid 0 does not grant caps
	{0x02, "SECBIT_NOROOT_LOCKED"},   // NOROOT locked against change
	{0x04, "SECBIT_NO_SETUID_FIXUP"}, // no caps fixup on set*uid
	{0x08, "SECBIT_NO_SETUID_FIXUP_LOCKED"},
	{0x10, "SECBIT_KEEP_CAPS"},       // KEEPCAPS from user-space
	{0x20, "SECBIT_KEEP_CAPS_LOCKED"},
	{0x40, "SECBIT_NO_CAP_AMBIENT_RAISE"}, // ambient caps cannot grow
	{0x80, "SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED"},
}

// prctlSpec describes a single GET query: its prctl option value,
// a short mnemonic, and a human-readable purpose string.
type prctlSpec struct {
	Opt     uintptr
	Name    string
	Purpose string
}

// prctlQueries is the ordered list of six prctl GET operations the
// T45 check performs.  The order is chosen from most container-relevant
// (dumpable / keepcaps directly change exploit calculus) to most
// informational (subreaper).
var prctlQueries = []prctlSpec{
	{prGetDumpable, "PR_GET_DUMPABLE",
		"Controls ptrace attach, core dumps, and /proc/<pid>/map_files read"},
	{prGetKeepcaps, "PR_GET_KEEPCAPS",
		"Whether permitted capabilities survive UID 0 -> non-0 transitions"},
	{prGetSeccomp, "PR_GET_SECCOMP",
		"Seccomp mode: 0=off, 1=strict, 2=filter (BPF)"},
	{prGetSecurebits, "PR_GET_SECUREBITS",
		"Securebits mask — hardening flags for setuid/setgid semantics"},
	{prGetNoNewPrivs, "PR_GET_NO_NEW_PRIVS",
		"execve() may NOT gain new privileges; required for seccomp-bpf"},
	{prGetChildSubreaper, "PR_GET_CHILD_SUBREAPER",
		"Process inherits orphaned descendants (like PID 1 / init)"},
}

// prctlSyscallNr returns the Linux syscall number for prctl(2) on the
// current architecture, or 0 if unknown.  Numbers sourced from
// linux/arch/<ARCH>/tools/syscall.tbl and kept in sync with the values
// used by pkg/evaluate/lsm_enumerate.go::probeLandlock.
func prctlSyscallNr() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 157
	case "arm64":
		return 167
	case "386", "arm":
		return 172
	default:
		return 0
	}
}

// rawPrctlGet executes prctl(option, 0, 0, 0, 0) via RawSyscall6 and
// returns (retval, errno).  The calling thread is pinned to its OS
// thread because several prctl options are per-thread attributes.
//
// OPSEC: all six queries are pure reads with zero kernel side effects.
func rawPrctlGet(nr, option uintptr) (uintptr, syscall.Errno) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r1, _, errNo := syscall.RawSyscall6(nr, option, 0, 0, 0, 0, 0)
	return r1, errNo
}

// interpretPrctl returns a short operator-facing annotation for the
// given prctl name + return value pair.  Empty string means "default /
// nothing unusual".
func interpretPrctl(name string, val uintptr) string {
	switch name {
	case "PR_GET_DUMPABLE":
		switch val {
		case 0:
			return "— CANNOT core-dump; ptrace from non-parent is blocked"
		case 1:
			return "— default (can dump + parent ptrace OK)"
		case 2:
			return "— ptrace(read) only for processes with matching real UID"
		default:
			return fmt.Sprintf("— unusual value %d", val)
		}

	case "PR_GET_KEEPCAPS":
		if val != 0 {
			return "— DANGER: permitted caps survive setuid(non-zero); exploit-friendly"
		}
		return "— default (caps dropped on UID 0 → non-0)"

	case "PR_GET_SECCOMP":
		switch val {
		case 0:
			return "— no seccomp restrictions; maximal syscall surface"
		case 1:
			return "— STRICT mode (only read/write/_exit/sigreturn)"
		case 2:
			return "— BPF FILTER mode (container runtime default — also check seccomp_deep)"
		default:
			return fmt.Sprintf("— unknown mode %d", val)
		}

	case "PR_GET_SECUREBITS":
		active := []string{}
		for _, sb := range securebitNames {
			if val&sb.mask != 0 {
				active = append(active, sb.name)
			}
		}
		if len(active) == 0 {
			return "— 0x0 (all securebits clear; default unhardened)"
		}
		return fmt.Sprintf("— 0x%x = [%s]", val, joinSecurebits(active))

	case "PR_GET_NO_NEW_PRIVS":
		if val != 0 {
			return "— set; execve() cannot escalate privs (seccomp-bpf prereq OK)"
		}
		return "— clear; setuid binaries work as usual"

	case "PR_GET_CHILD_SUBREAPER":
		if val != 0 {
			return "— subreaper=1; adopts orphaned descendants (init-like)"
		}
		return "— not a subreaper (default)"
	}
	return ""
}

func joinSecurebits(bits []string) string {
	out := ""
	for i, b := range bits {
		if i > 0 {
			out += ", "
		}
		out += b
	}
	return out
}

// PrctlState queries six process-wide / thread-wide prctl(2) GET options
// using direct RawSyscall6 to the SYS_PRCTL vector, then reports each
// result together with a container-security-relevant annotation.
//
// Why six options: container-escape primitives are shaped at the margin
// by per-process knobs that are invisible to /proc-based reconnaissance.
//   - KEEPCAPS + dumpable=0 changes whether a setuid(non-root) shell
//     that races a host process can retain CAP_SYS_ADMIN or be ptraced.
//   - NO_NEW_PRIVS is required before seccomp-bpf / landlock can apply
//     to a process, so it tells the operator whether the runtime
//     actually applied a filter or silently fell back.
//   - SECUREBITS cover fine-grained SUID hardening that the stock
//     capabilities check ignores.
//   - CHILD_SUBREAPER lets the CDK operator spot cases where an init
//     replacement process (supervisord, tini, entrypoint) sits inside
//     the container and will silently inherit double-forked orphans —
//     a favoured primitive for surviving PID-1 kill semantics.
//
// OPSEC guarantee: every option is a pure GET query; RawSyscall6 is
// invoked with args2..6 = 0 so no kernel state changes.  The thread is
// LockOSThread'd only because prctl attributes are per-thread on Linux
// (keeping the query self-consistent — not because we mutate anything).
func PrctlState(ctx *Context) error {
	nr := prctlSyscallNr()
	if nr == 0 {
		fmt.Printf("prctl_state: no SYS_PRCTL number known for arch=%q; skipping\n",
			runtime.GOARCH)
		return nil
	}

	fmt.Printf("prctl(2) per-process state — %d GET queries via RawSyscall6\n",
		len(prctlQueries))

	okCount := 0
	amberCount := 0
	for _, q := range prctlQueries {
		val, errNo := rawPrctlGet(nr, q.Opt)
		if errNo != 0 {
			fmt.Printf("\t[ SK ] %-26s errno=%d   (%s)\n",
				q.Name, int(errNo), q.Purpose)
			continue
		}
		okCount++

		tag := "[ .. ]"
		anno := interpretPrctl(q.Name, val)
		switch q.Name {
		case "PR_GET_KEEPCAPS":
			if val != 0 {
				tag = "[AMBR]"
				amberCount++
			}
		case "PR_GET_SECCOMP":
			if val == 0 {
				tag = "[AMBR]"
				amberCount++
			}
		case "PR_GET_SECUREBITS":
			// No hardened securebits at all → amber.
			if val == 0 {
				tag = "[AMBR]"
				amberCount++
			}
		case "PR_GET_DUMPABLE":
			// dumpable=2 (SUID_DUMP_USER) is interesting but not inherently
			// risky; only flag value=1 inside a container that also runs
			// untrusted sidecars.  Leave neutral.
		case "PR_GET_NO_NEW_PRIVS":
			if val == 0 {
				// Worth an amber in container context because it means
				// seccomp-bpf CANNOT be enforced on exec chains yet.
				tag = "[AMBR]"
				amberCount++
			}
		case "PR_GET_CHILD_SUBREAPER":
			// Purely informational.
		}

		fmt.Printf("\t%s %-26s = %-6d %s\n",
			tag, q.Name, val, anno)
	}

	fmt.Printf("\t%d/%d queries succeeded; %d amber flags\n",
		okCount, len(prctlQueries), amberCount)
	if amberCount >= 3 {
		fmt.Printf("\tINFO: 3+ amber flags — process has an unusually " +
			"permissive prctl state.\n" +
			"\t      Combine with capabilities + seccomp_deep before " +
			"rating exploit surface.\n")
	}
	return nil
}

func init() {
	RegisterContextPrereqCheck(CategorySecurity, "security.prctl_state",
		"6 prctl GET options queried via RawSyscall6 (dumpable/keepcaps/seccomp/securebits/nnp/subreaper)",
		[]string{"InContainer"},
		PrctlState)
}
