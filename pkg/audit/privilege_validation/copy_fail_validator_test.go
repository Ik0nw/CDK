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

package privilege_escalation

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestCopyFailDecompressPayload verifies that the embedded zlib blob can be
// decompressed and that it begins with a valid ELF64 little-endian header.
func TestCopyFailDecompressPayload(t *testing.T) {
	payload, err := copyFailDecompressPayload()
	require.NoError(t, err)
	require.NotNil(t, payload)

	// Payload must be exactly 160 bytes (40 four-byte chunks).
	assert.Equal(t, 160, len(payload), "unexpected payload length")

	// Verify ELF magic: 0x7f 'E' 'L' 'F'
	assert.Equal(t, []byte{0x7f, 0x45, 0x4c, 0x46}, payload[:4], "ELF magic mismatch")

	// ELF class = 2 (ELFCLASS64)
	assert.Equal(t, byte(0x02), payload[4], "expected ELF64 class")

	// Data encoding = 1 (ELFDATA2LSB, little-endian)
	assert.Equal(t, byte(0x01), payload[5], "expected little-endian encoding")
}

// TestBuildAlgCmsg verifies the structure of a control-message record built
// by buildAlgCmsg: correct alignment, header fields, and data placement.
func TestBuildAlgCmsg(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	cmsg := buildAlgCmsg(unix.SOL_ALG, unix.ALG_SET_OP, data)

	// The buffer length must be at least header + data.
	assert.GreaterOrEqual(t, len(cmsg), syscall.SizeofCmsghdr+len(data),
		"cmsg buffer too short")

	// The buffer must be aligned to pointer size (8 bytes on 64-bit).
	assert.Equal(t, 0, len(cmsg)%8, "cmsg buffer not 8-byte aligned")

	// Verify that the header fields were written correctly.
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cmsg[0]))
	assert.Equal(t, int32(unix.SOL_ALG), hdr.Level, "cmsg level mismatch")
	assert.Equal(t, int32(unix.ALG_SET_OP), hdr.Type, "cmsg type mismatch")

	// The data bytes must follow the header without corruption.
	assert.Equal(t, data, cmsg[syscall.SizeofCmsghdr:syscall.SizeofCmsghdr+len(data)],
		"cmsg data mismatch")
}

// TestBuildAlgCmsgEmpty verifies that an empty data slice produces a valid,
// correctly-sized ancillary record.
func TestBuildAlgCmsgEmpty(t *testing.T) {
	cmsg := buildAlgCmsg(unix.SOL_ALG, unix.ALG_SET_IV, nil)

	assert.GreaterOrEqual(t, len(cmsg), syscall.SizeofCmsghdr, "empty cmsg too short")
	assert.Equal(t, 0, len(cmsg)%8, "empty cmsg not 8-byte aligned")
}

// TestCopyFailPluginRegistered 验证插件按预期名称注册，具备正确的检查类型，并提供非空描述。
func TestCopyFailPluginRegistered(t *testing.T) {
	check := copyFailCVE202631431S{}
	check.ExploitType = "privilege-escalation"

	assert.Equal(t, "privilege-escalation", check.GetExploitType())
	assert.NotEmpty(t, check.Desc())
	assert.Contains(t, check.Desc(), "CAP-2026-001")
}
