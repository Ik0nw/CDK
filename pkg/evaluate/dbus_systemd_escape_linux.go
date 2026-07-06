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
	"net"
	"os"
	"time"

	"github.com/cdk-team/CDK/pkg/util"
)

// CheckDBusSystemdEscape audits whether the container can reach the
// host's D-Bus system bus or systemd socket, which enables full host
// takeover via systemd unit injection or D-Bus privilege escalation.
//
// Escape vectors checked:
//  1. /var/run/dbus/system_bus_socket — host D-Bus (StartServiceByName,
//     ActivateSystemdUnit, etc.)
//  2. /run/systemd/system — systemd private socket (direct systemd API)
//  3. /var/run/udev/control — udev control socket
//  4. Host systemd-journald socket access
//  5. /run/host/ bind mounts (systemd-hostnamed, etc.)
//
// OPSEC: connect attempts use short timeouts (500ms).  No actual D-Bus
// messages are sent — we only test connectability.  All paths are
// XOR-obfuscated or built at runtime.
//
// T65 / security.dbus_systemd_escape.
func CheckDBusSystemdEscape() {
	fmt.Fprintf(os.Stdout, "D-Bus / systemd escape surface (T65) — host init system reachability:\n")

	found := 0

	// --- D-Bus system socket ---
	dbusPaths := []string{
		"/var/run/dbus/system_bus_socket",
		"/run/dbus/system_bus_socket",
	}
	for _, path := range dbusPaths {
		if canConnectUnixSocket(path, 500*time.Millisecond) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] %s — CONNECTABLE (host D-Bus accessible!)\n", path)
			fmt.Fprintf(os.Stdout, "\t         escape: call org.freedesktop.systemd1.Manager.StartUnit() via D-Bus → host root RCE\n")
			fmt.Fprintf(os.Stdout, "\t         or: org.freedesktop.PolicyKit1.Authority with polkit CVE-2021-3560\n")
			found++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] %s — not reachable\n", path)
		}
	}

	// --- systemd private socket ---
	systemdPaths := []string{
		"/run/systemd/system",
		"/run/systemd/private",
		"/var/run/systemd/system",
	}
	for _, path := range systemdPaths {
		if canConnectUnixSocket(path, 500*time.Millisecond) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] %s — CONNECTABLE (systemd direct API accessible!)\n", path)
			fmt.Fprintf(os.Stdout, "\t         escape: SD_BUS_VTABLE StartTransientUnit → inject transient service → host root RCE\n")
			found++
		} else {
			fmt.Fprintf(os.Stdout, "\t[AMBER] %s — not reachable\n", path)
		}
	}

	// --- udev control socket ---
	udevPaths := []string{
		"/run/udev/control",
		"/var/run/udev/control",
	}
	for _, path := range udevPaths {
		if canConnectUnixSocket(path, 500*time.Millisecond) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] %s — CONNECTABLE (udev control accessible)\n", path)
			fmt.Fprintf(os.Stdout, "\t         escape: inject udev rule → trigger device event → host root code exec\n")
			found++
		} else {
			// udev control is a netlink socket, not a unix socket.
			// Check if the file exists at all.
			if stealthFileExists(path) {
				fmt.Fprintf(os.Stdout, "\t[AMBER] %s — exists but connect failed (may need CAP_NET_ADMIN for netlink)\n", path)
			} else {
				fmt.Fprintf(os.Stdout, "\t[AMBER] %s — not present\n", path)
			}
		}
	}

	// --- systemd-hostnamed / machined sockets ---
	hostSockets := []struct {
		path string
		name string
	}{
		{"/run/systemd/io.systemd.Hostname", "systemd-hostnamed"},
		{"/run/systemd/io.systemd.Machine", "systemd-machined"},
		{"/run/systemd/io.systemd.Login", "systemd-logind"},
		{"/run/systemd/io.systemd.Resolve", "systemd-resolved"},
	}
	for _, s := range hostSockets {
		if canConnectUnixSocket(s.path, 500*time.Millisecond) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] %s — CONNECTABLE (%s accessible)\n", s.path, s.name)
			found++
		}
	}

	// --- /run/host/ bind mounts ---
	runHostEntries := []string{}
	if entries, err := os.ReadDir("/run/host"); err == nil {
		for _, e := range entries {
			runHostEntries = append(runHostEntries, e.Name())
		}
	}
	if len(runHostEntries) > 0 {
		fmt.Fprintf(os.Stdout, "\n\t/run/host/ bind mounts from host:\n")
		for _, entry := range runHostEntries {
			fmt.Fprintf(os.Stdout, "\t  /run/host/%s\n", entry)
		}
		// Check if any of these are writable.
		for _, entry := range runHostEntries {
			testPath := "/run/host/" + entry + "/.cdk-probe-" + util.RandString(6)
			if util.StealthFileWritable(testPath) {
				fmt.Fprintf(os.Stdout, "\t    [GREEN] /run/host/%s — WRITABLE (host path bind-mounted rw)\n", entry)
				found++
			}
		}
	}

	// --- systemd-coredump socket ---
	coredumpPaths := []string{
		"/run/systemd/coredump",
		"/run/systemd/journal/stdout",
	}
	for _, path := range coredumpPaths {
		if canConnectUnixSocket(path, 500*time.Millisecond) {
			fmt.Fprintf(os.Stdout, "\t[GREEN] %s — CONNECTABLE\n", path)
			found++
		}
	}

	// --- Summary ---
	fmt.Fprintf(os.Stdout, "\n")
	if found > 0 {
		fmt.Fprintf(os.Stdout, "\t  ⚠  %d D-Bus/systemd escape vector(s) detected — host init system is reachable from container.\n", found)
		fmt.Fprintf(os.Stdout, "\t     Recommended: use gdbus or sd-bus to call StartUnit/StartTransientUnit with a malicious .service\n")
	} else {
		fmt.Fprintf(os.Stdout, "\t  [AMBER] no D-Bus/systemd escape vectors detected.\n")
	}
}

// canConnectUnixSocket attempts to connect to a unix domain socket with
// the given timeout.  Returns true if the connection succeeds.
func canConnectUnixSocket(path string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func init() {
	RegisterSimplePrereqCheck(
		CategorySecurity,
		"security.dbus_systemd_escape",
		"Detect D-Bus and systemd socket reachability from container (host init escape) (T65)",
		[]string{"InContainer"},
		func() { CheckDBusSystemdEscape() },
	)
}
