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
	"syscall"
)

// T48: security.ebpf_recon — eBPF / kernel pointer-disclosure / IMA / BTF
// visibility gates.
//
// Answers the attacker question: "Can I use eBPF as a kernel exploit
// primitive, and does this kernel leak pointer / BTF information to
// unprivileged processes inside the container?"
//
// Probes (all read-only / NULL-arg syscalls / file reads):
//   - /proc/sys/kernel/unprivileged_bpf_disabled
//        0 = all users can create BPF progs/maps → huge exposure
//        1 = CAP_BPF required  (default recent kernels)
//        2 = root-only + disable later → strict
//   - /proc/sys/kernel/kptr_restrict
//        0 = /proc/kallsyms shows real addresses, %pK format prints them
//        1 = hashed / zeros for non-root
//        2 = always zeroed
//   - /proc/sys/kernel/dmesg_restrict  (0 = all read, 1 = CAP_SYSLOG only)
//   - /proc/sys/kernel/perf_event_paranoid (-1=no restrictions → perf opens all)
//   - /sys/kernel/security/lsm contains "bpf" substring? → LSM-BPF active
//   - /sys/kernel/security/ima/policy readable? → IMA measurement enforce
//   - /sys/kernel/btf/vmlinux readable? → full kernel type database available
//   - bpf(BPF_PROG_GET_NEXT_ID, NULL_attr, 0) — NULL probe:
//        ENOSYS = BPF not compiled in
//        EPERM  = unpriv bpf disabled  (still reachable via cap_bpf)
//        EFAULT = bpf() works (struct was NULL, kernel accepted command →
//                 OPEN bpf attack surface for CAP_BPF containers)
//
// bpf(2) syscall signature from linux/bpf.h:
//   long sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);

const (
	// bpf command opcodes (linux/bpf.h), subset we probe:
	_BPF_PROG_GET_NEXT_ID = 11 // returns next program ID after attr.start_id
)

func bpfOut() *os.File { return os.Stdout }

// readSysctlInt reads a single-integer /proc/sys file.  Returns -1 if unreadable.
func readSysctlInt(path string) int {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return v
}

// rawBpf hits the bpf() syscall with NULL attr + size=0.  Returns (ret, errno).
// No side effects for PROG_GET_NEXT_ID with NULL/size=0: kernel returns
// -EFAULT on copy_from_user failure, but has already validated the cmd
// number and size field.  If the syscall number itself is invalid (BPF not
// compiled in), ENOSYS is returned regardless of args.
func rawBpfProbe() (int, syscall.Errno) {
	r1, _, errno := syscall.RawSyscall6(
		nr_bpf,
		uintptr(_BPF_PROG_GET_NEXT_ID),
		0, // attr = NULL
		0, // size = 0
		0, 0, 0,
	)
	return int(r1), errno
}

// fileOrDirExists returns true if path is readable (access ok, any type ok).
func pathReadable(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func fileFirstNLines(path string, n int) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.SplitN(string(data), "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return lines
}

// EnumerateEBPFRecon implements T48.
func EnumerateEBPFRecon() {
	fmt.Fprintln(bpfOut(), "security.ebpf_recon — eBPF / kernel pointer / IMA visibility gates:")

	// Table 1 — sysctl kernel.*
	unprivBpf := readSysctlInt("/proc/sys/kernel/unprivileged_bpf_disabled")
	kptrRestrict := readSysctlInt("/proc/sys/kernel/kptr_restrict")
	dmesgRestrict := readSysctlInt("/proc/sys/kernel/dmesg_restrict")
	perfParanoid := readSysctlInt("/proc/sys/kernel/perf_event_paranoid")
	modprobe := readSysctlPathString("/proc/sys/kernel/modprobe")
	_ = modprobe

	signals := []struct {
		Label string
		Val   interface{}
		// colour function based on value — returns green/ambery/?
		Colour func() string
		Notes  func() string
	}{
		{
			Label: "unprivileged_bpf_disabled",
			Val:   unprivBpf,
			Colour: func() string {
				switch unprivBpf {
				case -1: return "  ?  "
				case 0:  return "GREEN"
				case 1:  return "AMBER"
				case 2:  return "AMBER"
				default: return "  ?  "
				}
			},
			Notes: func() string {
				switch unprivBpf {
				case -1: return "(file unreadable)"
				case 0:  return "UNRESTRICTED — any user can load BPF programs/maps (2023-2025 LPE vector family)"
				case 1:  return "CAP_BPF required (standard for 5.16+)"
				case 2:  return "IRREVERSIBLE — disabled until reboot"
				default: return ""
				}
			},
		},
		{
			Label: "kptr_restrict",
			Val:   kptrRestrict,
			Colour: func() string {
				switch kptrRestrict {
				case -1: return "  ?  "
				case 0:  return "GREEN"
				case 1:  return "  ?  "
				case 2:  return "AMBER"
				default: return "  ?  "
				}
			},
			Notes: func() string {
				switch kptrRestrict {
				case -1: return "(file unreadable)"
				case 0:  return "DIRECT KASLR LEAK — /proc/kallsyms shows real addresses; %pK prints raw pointers"
				case 1:  return "non-root sees hashed or zeroed %pK"
				case 2:  return "always zeroed — no pointer leak via %p"
				default: return ""
				}
			},
		},
		{
			Label: "dmesg_restrict",
			Val:   dmesgRestrict,
			Colour: func() string {
				switch dmesgRestrict {
				case -1: return "  ?  "
				case 0:  return "GREEN"
				case 1:  return "  ?  "
				default: return "  ?  "
				}
			},
			Notes: func() string {
				switch dmesgRestrict {
				case -1: return "(file unreadable)"
				case 0:  return "dmesg readable by all — often leaks kernel symbols/addresses"
				case 1:  return "CAP_SYSLOG required (standard Debian/Ubuntu)"
				default: return ""
				}
			},
		},
		{
			Label: "perf_event_paranoid",
			Val:   perfParanoid,
			Colour: func() string {
				if perfParanoid == -1 || perfParanoid == 0 || perfParanoid == 1 {
					return "GREEN"
				}
				return "AMBER"
			},
			Notes: func() string {
				switch {
				case perfParanoid == -1: return "PERF NO RESTRICTIONS — CPU perf counters open to all (KASLR via PMC)"
				case perfParanoid <= 1:   return "low — CPU perf / kernel stack walks may be available"
				case perfParanoid == 2:   return "default — some kernel PMUs gated"
				case perfParanoid >= 3:   return "strict — no raw hardware PMU access"
				default:                  return ""
				}
			},
		},
	}

	for _, s := range signals {
		fmt.Fprintf(bpfOut(), "\t\t[%s] %-24s = %-3v — %s\n",
			s.Colour(), s.Label, s.Val, s.Notes())
	}

	// ---------------------------------------------------------------------
	// Table 2 — /sys visibility & LSM-bpf presence
	// ---------------------------------------------------------------------
	fmt.Fprintln(bpfOut(), "\t/sys & LSM visibility:")

	lsmBpfPresent := false
	if lsmData, err := ioutil.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsmBpfPresent = strings.Contains(string(lsmData), "bpf")
	}
	colour := "  ?  "
	switch {
	case lsmBpfPresent:
		colour = "AMBER"
		fmt.Fprintf(bpfOut(), "\t\t[%s] LSM-bpf /sys/kernel/security/lsm: YES — BPF LSM hooks are enforcing\n", colour)
	default:
		colour = "GREEN"
		fmt.Fprintf(bpfOut(), "\t\t[%s] LSM-bpf: NOT in /sys/kernel/security/lsm — only capabilities/seccomp/Landlock/IMA apply\n", colour)
	}

	ima := "UNKNOWN"
	imaColour := "  ?  "
	if !pathReadable("/sys/kernel/security/ima/policy") {
		ima = "NOT READABLE"
		imaColour = "GREEN"
	} else {
		lines := fileFirstNLines("/sys/kernel/security/ima/policy", 3)
		if lines == nil {
			ima = "READABLE (EMPTY) — IMA enabled but no policy"
			imaColour = "  ?  "
		} else {
			ima = fmt.Sprintf("READABLE (%d non-empty lines) — IMA policy ACTIVE", len(lines))
			imaColour = "AMBER"
		}
	}
	fmt.Fprintf(bpfOut(), "\t\t[%s] IMA policy (/sys/kernel/security/ima/policy): %s\n", imaColour, ima)

	btfColour := "  ?  "
	btfMsg := ""
	switch {
	case !pathReadable("/sys/kernel/btf/vmlinux"):
		btfColour = "  ?  "
		btfMsg = "not present — kernel may be !CONFIG_DEBUG_INFO_BTF (may make exploit offsets harder)"
	case fileSizeGt("/sys/kernel/btf/vmlinux", 0):
		btfColour = "GREEN"
		btfMsg = fmt.Sprintf("readable & non-empty (%d bytes) — FULL KERNEL TYPE DATABASE available for exploit development",
			fileSize("/sys/kernel/btf/vmlinux"))
	default:
		btfColour = "  ?  "
		btfMsg = "exists but empty?"
	}
	fmt.Fprintf(bpfOut(), "\t\t[%s] BTF (/sys/kernel/btf/vmlinux): %s\n", btfColour, btfMsg)

	// ---------------------------------------------------------------------
	// Table 3 — bpf() syscall reachability probe
	// ---------------------------------------------------------------------
	fmt.Fprintln(bpfOut(), "\tbpf(2) syscall NULL probe (BPF_PROG_GET_NEXT_ID with NULL attr / size 0):")
	_, bpfErrno := rawBpfProbe()
	var bpfColour, bpfVerdict, bpfAdvice string
	switch bpfErrno {
	case 0:
		bpfColour = "GREEN"
		bpfVerdict = "SUCCESS (!)"
		bpfAdvice = "PROG_GET_NEXT_ID with 0 args succeeded — CAP_BPF already held or no perms gate"
	case syscall.ENOSYS:
		bpfColour = "  ?  "
		bpfVerdict = "ENOSYS — kernel compiled without CONFIG_BPF_SYSCALL"
		bpfAdvice = "(no eBPF attack surface)"
	case syscall.EPERM:
		bpfColour = "AMBER"
		bpfVerdict = "EPERM — syscall is reachable but gated by CAP_BPF / LSM / sysctl"
		bpfAdvice = "standard for containers without CAP_BPF; check capabilities for BPF bit."
	case syscall.EFAULT:
		bpfColour = "GREEN"
		bpfVerdict = "EFAULT (NULL attr accepted by cmd dispatch)"
		bpfAdvice = "bpf() is reachable — NULL attr was copied then rejected; cmd dispatch succeeded"
	case syscall.EINVAL:
		bpfColour = "GREEN"
		bpfVerdict = "EINVAL (size=0 rejected)"
		bpfAdvice = "bpf() is reachable — size validation ran before copy_from_user; syscall available"
	default:
		bpfColour = "  ?  "
		bpfVerdict = fmt.Sprintf("errno=%v", bpfErrno)
		bpfAdvice = "(unexpected errno — treat as reachable unless ENOSYS)"
	}
	fmt.Fprintf(bpfOut(), "\t\t[%s] %s — %s\n", bpfColour, bpfVerdict, bpfAdvice)

	// ---------------------------------------------------------------------
	// Summary.
	// ---------------------------------------------------------------------
	fmt.Fprintln(bpfOut(), "\t  ---")
	score := 0
	if unprivBpf == 0 {
		score++
	}
	if kptrRestrict == 0 || kptrRestrict == 1 {
		score++
	}
	if dmesgRestrict == 0 {
		score++
	}
	if perfParanoid >= -1 && perfParanoid <= 1 {
		score++
	}
	if lsmBpfPresent {
		score-- // reduces effective eBPF LPE (LSM enforces)
	}
	if bpfErrno == syscall.EFAULT || bpfErrno == syscall.EINVAL || bpfErrno == 0 {
		score++
	}
	if btfColour == "GREEN" {
		score++
	}
	fmt.Fprintf(bpfOut(), "\t  eBPF / pointer-leak surface summary score = %d (higher = bigger surface)\n", score)
	switch {
	case score >= 4:
		fmt.Fprintln(bpfOut(), "\t  [GREEN] SUMMARY: STRONG eBPF / leak attack surface — prioritize kernel pointer / BPF LPE paths.")
	case score >= 1:
		fmt.Fprintln(bpfOut(), "\t  [  ?  ] SUMMARY: MODERATE surface — gates present but some leaks open.")
	default:
		fmt.Fprintln(bpfOut(), "\t  [AMBER] SUMMARY: WEAK surface — eBPF gated, pointer leaks closed, BTF absent.")
	}
}

// readSysctlPathString reads arbitrary path and returns trimmed contents.
func readSysctlPathString(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func fileSizeGt(path string, n int64) bool {
	return fileSize(path) > n
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.ebpf_recon",
		"eBPF visibility (unpriv_bpf) + kptr/dmesg/perf leaks + LSM-bpf presence + IMA + BTF + bpf(2) NULL probe [F14]",
		[]string{"InContainer"},
		func() { EnumerateEBPFRecon() },
	)
}
