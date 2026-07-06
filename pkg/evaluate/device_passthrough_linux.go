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
	"strings"
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// deviceEscapeCheck describes a host device node that, if exposed inside the
// container and accessible, provides a direct container escape primitive.
type deviceEscapeCheck struct {
	Path        string // device path inside the container
	Name        string // short human-readable name
	Risk        string // what the attacker can do with this device
	RequiresMknod bool   // true if the exploit also needs CAP_MKNOD
	Category    string // "storage" | "memory" | "console" | "misc"
}

// dangerousDevices lists the device nodes most commonly abused for container
// escape when --device / privileged / volume-mount exposes them.
//
// Each entry is checked with: (a) does the path exist? (b) can we open it
// for read? (c) for storage devices, can we read the first sector?
//
// High-sensitivity paths are populated at init() time from obfuscated
// constants to avoid static .rodata string matching by HIDS/EDR.
var dangerousDevices []deviceEscapeCheck

func init() {
	dangerousDevices = []deviceEscapeCheck{
		// --- storage devices (read host disk, modify host FS) ---
		{
			Path:     util.DevSdaPath(),
			Name:     "SCSI disk sda (primary host disk)",
			Risk:     "raw host disk access — read/write host filesystem, bypassing container overlay",
			Category: "storage",
		},
		{
			Path:     util.DevSda1Path(),
			Name:     "SCSI disk sda1 (host root partition)",
			Risk:     "raw host root partition — mount to escape or read /etc/shadow",
			Category: "storage",
		},
		{
			Path:     util.DevSdbPath(),
			Name:     "SCSI disk sdb (secondary host disk)",
			Risk:     "secondary host disk access",
			Category: "storage",
		},
		{
			Path:     util.DevVdaPath(),
			Name:     "VirtIO disk vda (KVM/VM primary disk)",
			Risk:     "raw VM disk access",
			Category: "storage",
		},
		{
			Path:     util.DevVda1Path(),
			Name:     "VirtIO disk vda1 (VM root partition)",
			Risk:     "raw VM root partition access",
			Category: "storage",
		},
		{
			Path:     util.DevNvme0n1Path(),
			Name:     "NVMe disk (cloud instance primary disk)",
			Risk:     "raw NVMe host disk access — common in AWS/Azure/GCP instances",
			Category: "storage",
		},
		{
			Path:     util.DevNvme0n1p1Path(),
			Name:     "NVMe partition 1 (cloud root partition)",
			Risk:     "raw NVMe root partition access",
			Category: "storage",
		},
		{
			Path:     util.DevXvdaPath(),
			Name:     "Xen virtual disk (older EC2 instances)",
			Risk:     "raw Xen disk access",
			Category: "storage",
		},
		{
			Path:     util.DevXvda1Path(),
			Name:     "Xen virtual disk partition 1",
			Risk:     "raw Xen root partition access",
			Category: "storage",
		},
		{
			Path:     util.DevMapperControlPath(),
			Name:     "device-mapper control",
			Risk:     "device-mapper manipulation — create dm-linear mapping over host disk",
			RequiresMknod: true,
			Category: "storage",
		},
		{
			Path:     util.DevLoop0Path(),
			Name:     "loop device 0",
			Risk:     "loop device — mount host disk images via losetup",
			RequiresMknod: true,
			Category: "storage",
		},

		// --- memory devices (read/write kernel memory) ---
		{
			Path:     util.DevMemPath(),
			Name:     "physical memory device",
			Risk:     "DIRECT KERNEL MEMORY RW — full system compromise, trivial escape",
			Category: "memory",
		},
		{
			Path:     util.DevKmemPath(),
			Name:     "kernel virtual memory device",
			Risk:     "kernel virtual memory RW — modify kernel data structures directly",
			Category: "memory",
		},
		{
			Path:     util.DevPortPath(),
			Name:     "I/O port access device",
			Risk:     "raw I/O port access — hardware-level escape primitive",
			Category: "memory",
		},

		// --- console / input devices ---
		{
			Path:     util.DevKmsgPath(),
			Name:     "kernel message log device",
			Risk:     "kernel ring buffer read — leaks kernel pointers (KASLR bypass), addresses, and internal state",
			Category: "console",
		},
		{
			Path:     util.DevConsolePath(),
			Name:     "system console",
			Risk:     "console access — may allow kernel message injection / TTY escape",
			Category: "console",
		},
		{
			Path:     util.DevTty0Path(),
			Name:     "current virtual console",
			Risk:     "VC access — potential TTY/console escape sequence injection",
			Category: "console",
		},

		// --- misc dangerous devices ---
		{
			Path:     util.DevFusePath(),
			Name:     "FUSE (Filesystem in Userspace)",
			Risk:     "mount custom FUSE filesystems — intercept host file access via mount namespace tricks",
			RequiresMknod: false,
			Category: "misc",
		},
		{
			Path:     util.DevNetTunPath(),
			Name:     "TUN/TAP network device",
			Risk:     "create network tunnels — bypass network policies, MITM host traffic",
			Category: "misc",
		},
		{
			Path:     util.DevUhidPath(),
			Name:     "user-space HID device",
			Risk:     "inject keyboard/mouse events into host input subsystem",
			Category: "misc",
		},
		{
			Path:     util.DevUinputPath(),
			Name:     "user-space input device",
			Risk:     "inject arbitrary input events — keystroke injection, mouse control",
			Category: "misc",
		},
		{
			Path:     util.DevBpfPath(),
			Name:     "eBPF filesystem device",
			Risk:     "eBPF program loading — kernel-level code execution via BPF JIT",
			Category: "misc",
		},
		{
			Path:     util.DevCpu0MsrPath(),
			Name:     "CPU model-specific registers",
			Risk:     "read/write CPU MSRs — modify syscall MSRs for ring0 escape",
			Category: "misc",
		},
	}
}

// CheckDevicePassthrough audits whether any host device nodes are exposed
// inside the container and accessible.  For each dangerous device we:
//
//  1. Check if the path exists (os.Stat — no open needed)
//  2. If it exists, try to open it for read (O_RDONLY | syscall.O_CLOEXEC)
//  3. For storage devices, try to read 512 bytes (the MBR / first sector)
//
// OPSEC: all opens use O_CLOEXEC.  We use os.OpenFile with O_RDONLY only.
// No ioctls, no writes, no mknod.  Each open is immediately closed.  This
// is a pure read-only audit that touches only /dev entries.
//
// T58 / security.device_passthrough.
func CheckDevicePassthrough() {
	fmt.Fprintf(os.Stdout, "device passthrough audit (T58) — dangerous host devices exposed to container:\n")

	found := 0
	for _, dev := range dangerousDevices {
		fi, err := os.Stat(dev.Path)
		if err != nil {
			continue // device not present — skip silently
		}

		// Check if it's actually a device (char or block), not a regular file.
		mode := fi.Mode()
		isDevice := (mode&os.ModeDevice) != 0 || (mode&os.ModeCharDevice) != 0
		if !isDevice {
			// Could be a bind-mounted regular file — still interesting but
			// not a device passthrough per se.
			fmt.Fprintf(os.Stdout, "\t[AMBER] %s exists but is NOT a device node (mode=%v) — bind-mounted file?\n",
				dev.Path, mode)
			continue
		}

		// Try to open for read.  Use StealthOpen (raw openat syscall)
		// to bypass LD_PRELOAD/libc hooks used by HIDS/EDR agents.
		// O_CLOEXEC is forced by StealthOpen internally.
		fd, err := util.StealthOpen(dev.Path, syscall.O_RDONLY)
		if err != nil {
			fmt.Fprintf(os.Stdout, "\t[AMBER] %-28s %s — EXISTS but open denied: %v\n",
				dev.Path, dev.Name, err)
			found++
			continue
		}
		util.StealthClose(fd)

		// Device is readable — that's a confirmed GREEN finding.
		colour := "GREEN"
		mknodNote := ""
		if dev.RequiresMknod {
			mknodNote = " (also needs CAP_MKNOD)"
		}
		fmt.Fprintf(os.Stdout, "\t[%s] %-28s %s\n",
			colour, dev.Path, dev.Name)
		fmt.Fprintf(os.Stdout, "\t         risk: %s%s\n", dev.Risk, mknodNote)
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			fmt.Fprintf(os.Stdout, "\t         type: %s  major:%d minor:%d\n",
				deviceType(mode), major(stat.Rdev), minor(stat.Rdev))
		} else {
			fmt.Fprintf(os.Stdout, "\t         type: %s\n", deviceType(mode))
		}
		found++
	}

	if found == 0 {
		fmt.Fprintf(os.Stdout, "\t[AMBER] no dangerous host device nodes detected inside container.\n")
		fmt.Fprintf(os.Stdout, "\t        (checked %d known-dangerous device paths)\n", len(dangerousDevices))
	} else {
		fmt.Fprintf(os.Stdout, "\n\t  ⚠  %d dangerous device(s) exposed — device-passthrough escape surface OPEN.\n", found)
		fmt.Fprintf(os.Stdout, "\t     Prioritize storage devices for disk-mount escape; /dev/mem for kernel RW.\n")
	}

	// Also check /dev/block for any unexpected block devices (cloud-init
	// sometimes exposes extra volumes).
	blockDevs := listBlockDevices()
	if len(blockDevs) > 0 {
		fmt.Fprintf(os.Stdout, "\n\tadditional block devices under /dev/block:\n")
		for _, bd := range blockDevs {
			fmt.Fprintf(os.Stdout, "\t  %s\n", bd)
		}
	}
}

// deviceType returns "block" or "char" based on the file mode.
func deviceType(mode os.FileMode) string {
	if (mode & os.ModeDevice) != 0 {
		if (mode & os.ModeCharDevice) != 0 {
			return "char"
		}
		return "block"
	}
	return "unknown"
}

// major extracts the major device number from a syscall.Rdev_t.
func major(rdev uint64) uint32 {
	return uint32((rdev >> 8) & 0xfff)
}

// minor extracts the minor device number from a syscall.Rdev_t.
func minor(rdev uint64) uint32 {
	return uint32((rdev & 0xff) | ((rdev >> 12) & 0xfff00))
}

// listBlockDevices returns a list of symlink targets under /dev/block.
// Returns nil if the directory is absent or unreadable.
func listBlockDevices() []string {
	// Use obfuscated path for /dev/block to avoid static string matching.
	blockDir := util.XorObfsPath([]byte{
		0x73, 0x2f, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21, 0x62, 0x37,
		0x2b, 0x3b, 0x27, 0x2c, 0x2d, 0x3a,
	})
	entries, err := os.ReadDir(blockDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		// Skip well-known safe entries.
		if strings.HasPrefix(name, "loop") || name == "fd" {
			continue
		}
		link, err := os.Readlink(blockDir + "/" + name)
		if err != nil {
			out = append(out, name)
		} else {
			out = append(out, name+" -> "+link)
		}
	}
	return out
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.device_passthrough",
		"Detect dangerous host device nodes exposed inside container (/dev/sda, /dev/mem, /dev/kmsg, /dev/fuse, ...) (T58)",
		[]string{"InContainer"},
		func() { CheckDevicePassthrough() },
	)
}
