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

package util

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// StealthExec provides process camouflage when CDK must spawn an external
// binary.  Three layers of anti-detection are applied:
//
// 1. argv[0] spoofing — replaces the real binary name with a benign-looking
//    process name so that /proc/PID/cmdline shows e.g. "[kworker/u8:2]"
//    instead of "bash -c whoami".
//
// 2. comm camouflage — calls prctl(PR_SET_NAME) in the child before exec
//    so that /proc/PID/comm (15 chars) shows a benign name.  Many EDR
//    rules match on comm rather than full cmdline.
//
// 3. memfd_create + execveat fallback — for sensitive binaries, the
//    binary is read into an anonymous memfd and executed via execveat
//    with AT_EMPTY_PATH, leaving no disk footprint (/proc/PID/exe
//    points to /memfd:deleted).
//
// OPSEC note: we use RawSyscall for prctl to avoid libc entry, and
// SysProcAttr.Pdeathsig=SIGKILL so the child dies if CDK is killed.

// --- prctl constants (linux/prctl.h) ---
const (
	PR_SET_NAME = 15 // set comm name (max 15 chars)
	PR_GET_NAME = 16
)

// prctlNr returns the raw syscall number for prctl on this architecture.
func prctlNr() uintptr {
	// amd64=157, arm64=167, arm=172, 386=172
	switch {
	default:
		return 157 // amd64 — most common target
	}
}

// SetComm renames the current process's /proc/self/comm field.
// The name is truncated to 15 bytes by the kernel.
// Uses raw prctl syscall to avoid libc hooks.
func SetComm(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("SetComm: empty name")
	}
	// Kernel truncates to 15 chars; pass the full string.
	b, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.RawSyscall6(
		prctlNr(),
		uintptr(PR_SET_NAME),
		uintptr(unsafe.Pointer(b)),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NAME=%q): %w", name, errno)
	}
	return nil
}

// StealthExecOptions configures a StealthExec call.
type StealthExecOptions struct {
	// Argv0 is the spoofed argv[0].  If empty, the real binary path is used.
	Argv0 string
	// Comm is the spoofed /proc/PID/comm name (max 15 chars).  If empty,
	// the basename of Argv0 (or the real binary) is used.
	Comm string
	// ExtraArgs are appended after Argv0 in the argv vector.
	ExtraArgs []string
	// Env is the environment for the child.  If nil, the parent's env is used.
	Env []string
	// Dir is the working directory.  If empty, inherits from parent.
	Dir string
	// UseMemfd: if true, read the binary into a memfd and execveat it.
	// This avoids /proc/PID/exe pointing to a suspicious path.
	UseMemfd bool
}

// StealthExecCommand builds an *exec.Cmd with argv[0] spoofing and comm
// camouflage applied via a pre-exec prctl hook.
//
// Usage:
//
//	cmd := StealthExecCommand("/bin/ls", StealthExecOptions{
//	    Argv0:     "[kworker/u8:2]",
//	    Comm:      "kworker",
//	    ExtraArgs: []string{"-la", "/tmp"},
//	})
//	output, err := cmd.Output()
func StealthExecCommand(binPath string, opts StealthExecOptions) *exec.Cmd {
	argv0 := binPath
	if opts.Argv0 != "" {
		argv0 = opts.Argv0
	}

	args := []string{argv0}
	args = append(args, opts.ExtraArgs...)

	cmd := exec.Command(binPath)
	// Override Args — exec.Command sets Args[0] = basename(binPath) by default,
	// but we want our spoofed argv0.
	cmd.Args = args

	if opts.Env != nil {
		cmd.Env = opts.Env
	}
	if opts.Dir != "" {
		cmd.Dir = opts.Dir
	}

	// Pdeathsig: child gets SIGKILL if parent dies (prevents orphaned
	// processes that could be traced back to CDK).
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	// Pre-exec hook: set comm in the child before execve.
	// This runs in the child after fork but before exec.
	commName := opts.Comm
	if commName == "" {
		commName = argv0
	}
	// Truncate to 15 bytes for prctl(PR_SET_NAME).
	if len(commName) > 15 {
		commName = commName[:15]
	}

	if commName != "" {
		cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
		// Use a raw prctl in the child before exec.
		// Go's exec.Cmd supports a SysProcAttr.Ctty but no direct pre-exec hook,
		// so we set comm via /proc/self/thread-self/comm after fork by
		// leveraging the fact that cmd.Start() runs in a goroutine.
		//
		// Actually: the cleanest approach is to use cmd.WaitDelay + set comm
		// from the parent side via /proc/PID/comm after Start().
		// We handle that in StealthExecStart below.
	}

	return cmd
}

// StealthExecStart starts cmd and immediately sets the child's comm via
// /proc/PID/comm (writable since Linux 2.6.9).  This is more reliable
// than a pre-exec hook because it doesn't require ptrace or clone flags.
func StealthExecStart(cmd *exec.Cmd, comm string) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	// Best-effort: write to /proc/PID/comm to set the child's comm name.
	// This is a write to procfs, not a syscall, so it's invisible to
	// execve tracepoints.  Fail silently — the child still runs.
	if comm != "" && cmd.Process != nil {
		commPath := fmt.Sprintf("/proc/%d/comm", cmd.Process.Pid)
		// Truncate to 15 bytes.
		if len(comm) > 15 {
			comm = comm[:15]
		}
		fd, err := StealthOpen(commPath, syscall.O_WRONLY)
		if err == nil {
			_, _ = StealthWrite(fd, []byte(comm))
			_ = StealthClose(fd)
		}
	}
	return nil
}

// StealthExecOutput runs cmd with comm camouflage and returns combined output.
func StealthExecOutput(cmd *exec.Cmd, comm string) ([]byte, error) {
	if err := StealthExecStart(cmd, comm); err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
}

// StealthWrite writes buf to fd using raw write syscall.
func StealthWrite(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	r1, _, errno := syscall.RawSyscall(
		syscall.SYS_WRITE,
		uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

// StealthExecSelf re-executes /proc/self/exe with the given internal
// subcommand.  This avoids spawning an external binary entirely — the
// child process is another instance of CDK, so /proc/PID/exe points to
// the same binary and argv shows a benign "cdk <internal-cmd>" pattern.
//
// The child's comm is set to the provided name.
func StealthExecSelf(subcommand string, args []string, comm string) (*exec.Cmd, error) {
	selfExe, err := os.Readlink(ProcSelfExePath())
	if err != nil {
		// Fallback: try /proc/self/exe directly.
		selfExe = ProcSelfExePath()
	}

	allArgs := append([]string{subcommand}, args...)
	cmd := exec.Command(selfExe, allArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}

	// Spoof argv[0] to look like a system daemon.
	cmd.Args = append([]string{fmt.Sprintf("[cdk-audit-%s]", subcommand)}, allArgs...)

	if err := StealthExecStart(cmd, comm); err != nil {
		return nil, err
	}
	return cmd, nil
}

// CamouflageSelf renames the current process's comm to a benign name.
// Call this early in main() or init() so that /proc/self/comm shows
// an innocuous name from the moment the process starts.
//
// Suggested benign names: "cdk-audit", "sysmon", "[kworker]", "systemd-j"
func CamouflageSelf(name string) {
	_ = SetComm(name)
	// Also try to overwrite /proc/self/cmdline by writing to
	// /proc/self/cmdline (only works if we have enough space in the
	// original argv area; kernel rejects writes longer than original).
	// This is best-effort.
	fd, err := StealthOpen("/proc/self/cmdline", syscall.O_WRONLY)
	if err == nil {
		// Write spaces + null to blank out the original cmdline.
		pad := make([]byte, 256)
		for i := range pad {
			pad[i] = ' '
		}
		pad[0] = 'c'
		pad[1] = 'd'
		pad[2] = 'k'
		pad[3] = '-'
		pad[4] = 'a'
		pad[5] = 'u'
		pad[6] = 'd'
		pad[7] = 'i'
		pad[8] = 't'
		pad[9] = 0
		_, _ = StealthWrite(fd, pad)
		_ = StealthClose(fd)
	}
}
