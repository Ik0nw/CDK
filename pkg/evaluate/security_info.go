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
	"bufio"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// namespaceTypes lists the Linux namespaces relevant to container isolation.
var namespaceTypes = []string{"cgroup", "ipc", "mnt", "net", "pid", "uts"}

// CheckNamespaceIsolation compares /proc/1/ns/<ns> and /proc/self/ns/<ns> for
// each namespace type. If the symlink targets differ, the namespace is isolated.
func CheckNamespaceIsolation() {
	log.Println("Namespace isolation status:")
	for _, ns := range namespaceTypes {
		initTarget, err1 := os.Readlink(fmt.Sprintf("/proc/1/ns/%s", ns))
		selfTarget, err2 := os.Readlink(fmt.Sprintf("/proc/self/ns/%s", ns))
		if err1 != nil || err2 != nil {
			log.Printf("\t%s: unable to read namespace links", ns)
			continue
		}
		if initTarget != selfTarget {
			fmt.Printf("\t%s: isolated (%s)\n", ns, selfTarget)
		} else {
			fmt.Printf("\t%s: NOT isolated (shared with host, %s)\n", ns, selfTarget)
		}
	}
}

// CheckSeccompStatus reads the Seccomp field from /proc/self/status and reports
// whether Seccomp is disabled (0), strict (1), or filter (2) mode.
func CheckSeccompStatus() {
	data, err := ioutil.ReadFile("/proc/self/status")
	if err != nil {
		log.Printf("seccomp: unable to read /proc/self/status: %v", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Seccomp:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				log.Println("seccomp: malformed Seccomp line")
				return
			}
			switch parts[1] {
			case "0":
				log.Println("Seccomp: disabled")
			case "1":
				log.Println("Seccomp: strict mode (1)")
			case "2":
				log.Println("Seccomp: filter mode (2)")
			default:
				log.Printf("Seccomp: unknown value %s", parts[1])
			}
			return
		}
	}
	log.Println("Seccomp: field not found in /proc/self/status (kernel may not support Seccomp)")
}

// CheckSeccompKernelSupport reports whether the running kernel was compiled with
// Seccomp support by checking for the Seccomp field in /proc/self/status and,
// optionally, the kernel config.
func CheckSeccompKernelSupport() {
	// The presence of the "Seccomp:" line in /proc/self/status indicates support.
	data, err := ioutil.ReadFile("/proc/self/status")
	if err != nil {
		log.Printf("seccomp: unable to read /proc/self/status: %v", err)
		return
	}
	if strings.Contains(string(data), "Seccomp:") {
		log.Println("Seccomp: kernel supports Seccomp")
	} else {
		log.Println("Seccomp: kernel does NOT support Seccomp")
	}

	// Additional confirmation via kernel config when available.
	if val, ok := readKernelConfigOption("CONFIG_SECCOMP"); ok {
		log.Printf("Seccomp: kernel config CONFIG_SECCOMP=%s", val)
	}
}

// CheckSELinux detects whether SELinux is present and enforcing.
func CheckSELinux() {
	// /sys/fs/selinux/enforce exists only when SELinux is compiled in and mounted.
	enforceFile := "/sys/fs/selinux/enforce"
	data, err := ioutil.ReadFile(enforceFile)
	if err != nil {
		log.Println("SELinux: not detected (no selinuxfs)")
		return
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		log.Println("SELinux: enforcing")
	case "0":
		log.Println("SELinux: permissive (loaded but not enforcing)")
	default:
		log.Printf("SELinux: unexpected enforce value %q", strings.TrimSpace(string(data)))
	}

	// Show the container's SELinux label if available.
	if label, err := ioutil.ReadFile("/proc/self/attr/current"); err == nil {
		trimmed := strings.TrimRight(string(label), "\x00\n")
		log.Printf("SELinux: container label: %s", trimmed)
	}
}

// CheckAppArmor inspects kernel compile options, boot parameters, runtime
// status, and the active AppArmor profile for the current process.
func CheckAppArmor() {
	// 1. Kernel compile option.
	if val, ok := readKernelConfigOption("CONFIG_SECURITY_APPARMOR"); ok {
		log.Printf("AppArmor: kernel config CONFIG_SECURITY_APPARMOR=%s", val)
	} else {
		log.Println("AppArmor: kernel config not available")
	}

	// 2. Boot parameters.
	if cmdline, err := ioutil.ReadFile("/proc/cmdline"); err == nil {
		params := string(cmdline)
		if strings.Contains(params, "apparmor=1") || strings.Contains(params, "security=apparmor") {
			log.Printf("AppArmor: enabled via boot parameters (%s)", strings.TrimSpace(params))
		} else if strings.Contains(params, "apparmor=0") {
			log.Println("AppArmor: disabled via boot parameter apparmor=0")
		} else {
			log.Println("AppArmor: no explicit AppArmor boot parameter found")
		}
	}

	// 3. Runtime status.
	if data, err := ioutil.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		if strings.TrimSpace(string(data)) == "Y" {
			log.Println("AppArmor: module is enabled (runtime)")
		} else {
			log.Println("AppArmor: module is loaded but disabled (runtime)")
		}
	} else {
		log.Println("AppArmor: module not loaded")
	}

	// 4. Container AppArmor profile.
	if label, err := ioutil.ReadFile("/proc/self/attr/current"); err == nil {
		trimmed := strings.TrimRight(string(label), "\x00\n")
		if trimmed == "" || trimmed == "unconfined" {
			log.Println("AppArmor: container is unconfined (no profile attached)")
		} else {
			log.Printf("AppArmor: container profile: %s", trimmed)
		}
	} else {
		log.Println("AppArmor: unable to read container profile")
	}
}

// readKernelConfigOption searches the kernel config (compressed or plain) for
// the given option key and returns its value along with a boolean indicating
// whether the key was found.
func readKernelConfigOption(key string) (string, bool) {
	// Prefer /proc/config.gz (available when CONFIG_IKCONFIG_PROC=y).
	if f, err := os.Open("/proc/config.gz"); err == nil {
		defer f.Close()
		if gz, err := gzip.NewReader(f); err == nil {
			defer gz.Close()
			scanner := bufio.NewScanner(gz)
			for scanner.Scan() {
				if val, ok := matchConfigLine(scanner.Text(), key); ok {
					return val, true
				}
			}
			return "", false
		}
	}

	// Fall back to /boot/config-<uname -r>.
	uname, err := ioutil.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", false
	}
	configPath := "/boot/config-" + strings.TrimSpace(string(uname))
	f2, err := os.Open(configPath)
	if err != nil {
		return "", false
	}
	defer f2.Close()
	scanner := bufio.NewScanner(f2)
	for scanner.Scan() {
		if val, ok := matchConfigLine(scanner.Text(), key); ok {
			return val, true
		}
	}
	return "", false
}

// matchConfigLine checks whether a kernel config line sets the given key and
// returns the value (e.g. "y", "m", "n", or a quoted string).
func matchConfigLine(line, key string) (string, bool) {
	// Kernel config lines look like: CONFIG_FOO=y or # CONFIG_FOO is not set
	if strings.HasPrefix(line, key+"=") {
		return strings.TrimPrefix(line, key+"="), true
	}
	if line == "# "+key+" is not set" {
		return "n", true
	}
	return "", false
}

func init() {
	RegisterSimplePrereqCheck(CategorySecurity, "security.namespace_isolation",
		"Check container namespace isolation", []string{"InContainer"}, CheckNamespaceIsolation)
	RegisterSimplePrereqCheck(CategorySecurity, "security.seccomp_status",
		"Check Seccomp status", []string{"InContainer"}, CheckSeccompStatus)
	RegisterSimplePrereqCheck(CategorySecurity, "security.seccomp_support",
		"Check kernel Seccomp support", []string{"InContainer"}, CheckSeccompKernelSupport)
	RegisterSimplePrereqCheck(CategorySecurity, "security.selinux",
		"Check SELinux status", []string{"InContainer"}, CheckSELinux)
	RegisterSimplePrereqCheck(CategorySecurity, "security.apparmor",
		"Check AppArmor status and container profile", []string{"InContainer"}, CheckAppArmor)
}
