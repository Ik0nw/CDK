//go:build !linux
// +build !linux

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
	"errors"
	"os"
)

// Non-Linux stubs for stealth I/O helpers.  These fall back to the
// standard library since raw openat/read via RawSyscall6 is Linux-only.

func StealthOpen(path string, flags int) (int, error) {
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return -1, err
	}
	return int(f.Fd()), nil
}

func StealthRead(fd int, buf []byte) (int, error) {
	return os.NewFile(uintptr(fd), "stealth").Read(buf)
}

func StealthClose(fd int) error {
	return os.NewFile(uintptr(fd), "stealth").Close()
}

func StealthReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func StealthFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func StealthFileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		f.Close()
		return true
	}
	return false
}

// errUnsupported is returned by stubs that have no non-Linux equivalent.
var errUnsupported = errors.New("unsupported on this platform")
