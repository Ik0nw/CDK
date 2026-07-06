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
	"syscall"
	"unsafe"
)

// StealthOpen opens a file using raw syscall (openat) instead of the
// libc-wrapped syscall.Open.  This bypasses LD_PRELOAD-based hooks that
// intercept open()/openat() at the libc level, which some HIDS/EDR agents
// use for file-access monitoring.
//
// The returned fd is always O_CLOEXEC (set via the raw flag, not via
// fcntl, to avoid another libc call).
//
// OPSEC: uses RawSyscall6 (not Syscall) to avoid the Go runtime's
// syscall wrapper entering/exiting tracking which some eBPF-based
// monitors hook.
//
// Returns the fd (>= 0) on success, or -1 and the errno on failure.
func StealthOpen(path string, flags int) (int, error) {
	// Always force O_CLOEXEC to prevent fd leakage to child processes.
	flags |= syscall.O_CLOEXEC

	// Use openat(AT_FDCWD, path, flags, 0) — this is what modern glibc
	// open() resolves to internally, and it's a single raw syscall.
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}

	// AT_FDCWD = -100 (relative to cwd)
	const AT_FDCWD = ^uintptr(99) // -100 as uintptr

	r1, _, errno := syscall.RawSyscall6(
		syscall.SYS_OPENAT,
		AT_FDCWD,
		uintptr(unsafe.Pointer(p)),
		uintptr(flags),
		0, // mode (only used with O_CREAT)
		0, 0,
	)
	if errno != 0 {
		return -1, errno
	}
	return int(r1), nil
}

// StealthRead reads up to len(buf) bytes from fd using raw read syscall.
// Returns the number of bytes read and any error.
func StealthRead(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	r1, _, errno := syscall.RawSyscall(
		syscall.SYS_READ,
		uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

// StealthClose closes a fd using raw close syscall.
func StealthClose(fd int) error {
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_CLOSE,
		uintptr(fd),
		0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// StealthReadFile reads the entire contents of a file using raw syscalls.
// This is a convenience wrapper around StealthOpen + StealthRead + StealthClose.
//
// OPSEC: avoids os.ReadFile which goes through libc open/read/close and
// may trigger LD_PRELOAD hooks.  The internal buffer is grown in 4KB
// chunks which is less efficient but avoids a single large mmap that
// some monitors flag.
func StealthReadFile(path string) ([]byte, error) {
	fd, err := StealthOpen(path, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer StealthClose(fd)

	var result []byte
	buf := make([]byte, 4096)
	for {
		n, err := StealthRead(fd, buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			// EOF is signalled by errno=0 and n=0, or errno=EAGAIN for
			// non-blocking.  We treat any non-nil errno as stop.
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			return result, nil // partial read is fine for our use case
		}
		if n == 0 {
			break // EOF
		}
	}
	return result, nil
}

// StealthFileExists returns true if the file at path can be opened for reading.
// Uses raw openat syscall to avoid libc hooks.
func StealthFileExists(path string) bool {
	fd, err := StealthOpen(path, syscall.O_RDONLY)
	if err != nil {
		return false
	}
	StealthClose(fd)
	return true
}

// StealthFileWritable returns true if the file at path can be opened for writing.
// Uses raw openat with O_RDWR to test writability without actually writing.
func StealthFileWritable(path string) bool {
	fd, err := StealthOpen(path, syscall.O_RDWR)
	if err != nil {
		return false
	}
	StealthClose(fd)
	return true
}
