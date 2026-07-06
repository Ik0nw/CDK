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
	"fmt"
	"os/exec"
)

// StealthExecOptions is a no-op on non-Linux platforms.
type StealthExecOptions struct {
	Argv0     string
	Comm      string
	ExtraArgs []string
	Env       []string
	Dir       string
	UseMemfd  bool
}

// SetComm is a no-op on non-Linux.
func SetComm(name string) error {
	return fmt.Errorf("SetComm: not supported on this platform")
}

// StealthExecCommand falls back to plain exec.Command on non-Linux.
func StealthExecCommand(binPath string, opts StealthExecOptions) *exec.Cmd {
	args := append([]string{binPath}, opts.ExtraArgs...)
	return exec.Command(binPath, args...)
}

// StealthExecStart is a no-op wrapper on non-Linux.
func StealthExecStart(cmd *exec.Cmd, comm string) error {
	return cmd.Start()
}

// StealthExecOutput runs cmd and returns combined output on non-Linux.
func StealthExecOutput(cmd *exec.Cmd, comm string) ([]byte, error) {
	return cmd.CombinedOutput()
}

// StealthWrite is a no-op on non-Linux.
func StealthWrite(fd int, buf []byte) (int, error) {
	return 0, fmt.Errorf("StealthWrite: not supported on this platform")
}

// StealthExecSelf is a no-op on non-Linux.
func StealthExecSelf(subcommand string, args []string, comm string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("StealthExecSelf: not supported on this platform")
}

// CamouflageSelf is a no-op on non-Linux.
func CamouflageSelf(name string) {
	// Not supported on non-Linux.
}
