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
	"runtime"
	"strings"
	"syscall"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckIoplEscape audits the I/O port access escape surface.
//
// CAP_SYS_RAWIO grants the ability to:
//   - Call iopl(2) / ioperm(2) to access raw I/O ports
//   - Access /dev/port directly
//   - Access /dev/mem and /dev/kmem physical memory
//   - Perform raw SCSI generic commands
//
// With I/O port access from inside a container, an attacker can:
//   - Program the PCI configuration space to find host devices
//   - Access host physical memory via /dev/mem (if also present)
//   - Use inb/outb to manipulate host hardware directly
//   - Bypass container isolation entirely (hardware-level access)
//
// Detection approach:
//  1. Check for CAP_SYS_RAWIO in /proc/self/status.
//  2. Test if /dev/port is accessible (raw I/O port device).
//  3. Test if iopl(3) syscall succeeds (enables all I/O ports).
//  4. Check /proc/sys/kernel/dmesg_restrict (hardware info leak).
//  5. Check if we can mmap /dev/mem (physical memory access).
//
// OPSEC: read-only checks.  iopl(3) probe is done on a dedicated thread
// and immediately restored with iopl(0).  All file opens use StealthOpen.
// We do NOT actually read/write I/O ports — we only test capability.
//
// T71 / security.iopl_escape.
func CheckIoplEscape() {
	fmt.Fprintf(os.Stdout, "I/O port escape surface (T71) — CAP_SYS_RAWIO, iopl(), /dev/port, /dev/mem:\n")

	findings := 0

	// --- Signal 1: CAP_SYS_RAWIO ---
	hasRawIO := hasCapability("cap_sys_rawio")
	if hasRawIO {
		fmt.Fprintf(os.Stdout, "\t[GREEN] CAP_SYS_RAWIO present — can use iopl()/ioperm() and access /dev/port\n")
		fmt.Fprintf(os.Stdout, "\t         enables raw hardware I/O from inside the container\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] CAP_SYS_RAWIO absent\n")
	}

	// --- Signal 2: /dev/port accessibility ---
	devPortPath := util.DevPortPath()
	portAccessible := stealthFileReadable(devPortPath)
	if portAccessible {
		fmt.Fprintf(os.Stdout, "\t[GREEN] %s readable — raw I/O port access from container!\n", devPortPath)
		fmt.Fprintf(os.Stdout, "\t         escape: inb/outb via /dev/port to manipulate host hardware\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] %s not readable\n", devPortPath)
	}

	// --- Signal 3: iopl(3) syscall probe ---
	// iopl(3) enables I/O privilege level 3 (all ports).
	// We test on a locked OS thread and immediately restore.
	if hasRawIO {
		ioplResult := probeIopl()
		switch ioplResult {
		case 0:
			fmt.Fprintf(os.Stdout, "\t[GREEN] iopl(3) SUCCEEDED — full I/O port access enabled!\n")
			fmt.Fprintf(os.Stdout, "\t         escape: direct inb/outb assembly instructions work\n")
			findings++
		case syscall.EPERM:
			fmt.Fprintf(os.Stdout, "\t[AMBER] iopl(3) returned EPERM (seccomp blocking?)\n")
		default:
			fmt.Fprintf(os.Stdout, "\t[AMBER] iopl(3) failed: %v\n", ioplResult)
		}
	}

	// --- Signal 4: /dev/mem mmap test ---
	devMemPath := util.DevMemPath()
	memReadable := stealthFileReadable(devMemPath)
	if memReadable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] %s readable — host physical memory accessible!\n", devMemPath)
		fmt.Fprintf(os.Stdout, "\t         escape: mmap physical address 0 → read host kernel memory\n")
		findings++
	} else {
		fmt.Fprintf(os.Stdout, "\t[AMBER] %s not readable\n", devMemPath)
	}

	// --- Signal 5: /dev/kmem ---
	devKmemPath := util.DevKmemPath()
	kmemReadable := stealthFileReadable(devKmemPath)
	if kmemReadable {
		fmt.Fprintf(os.Stdout, "\t[GREEN] %s readable — kernel virtual memory accessible!\n", devKmemPath)
		findings++
	}

	// --- Signal 6: dmesg_restrict ---
	dmesgRestrictPath := util.DmesgRestrictPath()
	dmesgVal := stealthReadFirstLine(dmesgRestrictPath)
	if dmesgVal != "" {
		val := strings.TrimSpace(dmesgVal)
		fmt.Fprintf(os.Stdout, "\t     kernel.dmesg_restrict = %s\n", val)
		if val == "0" {
			fmt.Fprintf(os.Stdout, "\t[AMBER] dmesg unrestricted — kernel ring buffer leaks hardware addresses\n")
		}
	}

	// --- Signal 7: Check for PCI config space access ---
	// /proc/bus/pci or /sys/bus/pci access would allow PCI device enumeration.
	pciConfigPath := util.ProcBusPciPath()
	if stealthFileExists(pciConfigPath) {
		fmt.Fprintf(os.Stdout, "\t[AMBER] %s accessible — PCI config space enumeration possible\n", pciConfigPath)
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if findings >= 2 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d I/O port escape indicators — hardware-level container escape VIABLE.\n", findings)
		fmt.Fprintf(os.Stdout, "\t     CAP_SYS_RAWIO + accessible /dev/port or /dev/mem = full host compromise.\n")
	} else if findings == 1 {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] 1 I/O port indicator detected.\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no I/O port escape vectors detected.\n")
	}
}

// probeIopl tests whether iopl(3) succeeds.  It runs on a locked OS
// thread and restores iopl(0) before returning, so the process's I/O
// privilege level is not permanently changed.
func probeIopl() syscall.Errno {
	// Use a channel to get the result from the locked thread.
	resultCh := make(chan syscall.Errno, 1)

	go func() {
		// Lock this goroutine to its OS thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Try iopl(3) — enable I/O privilege level 3.
		// On x86_64, iopl is syscall 172.
		const sysIopl = 172
		_, _, errno := syscall.RawSyscall(uintptr(sysIopl), 3, 0, 0)

		if errno == 0 {
			// Restore iopl(0) immediately.
			syscall.RawSyscall(uintptr(sysIopl), 0, 0, 0)
		}

		resultCh <- errno
	}()

	return <-resultCh
}

// stealthFileReadable returns true if the file can be opened O_RDONLY.
func stealthFileReadable(path string) bool {
	fd, err := util.StealthOpen(path, syscall.O_RDONLY)
	if err == nil {
		util.StealthClose(fd)
		return true
	}
	return false
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.iopl_escape",
		"Detect I/O port escape: CAP_SYS_RAWIO, iopl(), /dev/port, /dev/mem, /dev/kmem (T71)",
		[]string{"InContainer"},
		func() { CheckIoplEscape() },
	)
}
