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
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/cdk-team/CDK/pkg/util"
	"github.com/cdk-team/CDK/pkg/util/capability"
)

// capOut() returns the writer that GetProcCapabilities should use for
// diagnostic output. The evaluate engine swaps the *values* of os.Stdout
// and os.Stderr during check execution (JSON mode), but a package-level
// variable initialised once would hold a copy of the original *os.File
// and write outside the JSON envelope. Therefore we dereference os.Stdout
// at call time, every time. Defence-in-depth: we also never use
// fatih/color helpers (util.RedBold etc.) from this unit — those write
// through their own package-level globals that fd-swap may miss in edge
// cases.
func capOut() *os.File { return os.Stdout }

func GetProcCapabilities() bool {
	data, err := util.StealthReadFile(util.ProcSelfStatusPath())
	if err != nil {
		log.Println(err)
		return false
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	log.Println("Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):")

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Cap") {
			fmt.Fprintf(capOut(), "\t%s\n", line)
		}
	}

	pattern := regexp.MustCompile(`(?i)capeff:\s*?[a-z0-9]+\s`)
	params := pattern.FindStringSubmatch(string(data))

	for _, matched := range params {

		// make capabilities readable
		lst := strings.Split(matched, ":")
		if len(lst) == 2 {

			capStr := strings.TrimSpace(lst[1])
			caps, err := capability.CapHexParser(capStr)

			fmt.Fprintf(capOut(), "\tCap decode: 0x%s = %s\n", capStr, capability.CapListToString(caps))

			addCaps := getAddCaps(caps)
			if len(addCaps) > 0 {
				fmt.Fprintf(capOut(), "\tAdded capability list: %s\n", capability.CapListToString(addCaps))
			}

			if err != nil {
				log.Printf("[-] capability.CapHexParser: %v\n", err)
				return false
			}

			fmt.Fprintf(capOut(), "[*] Maybe you can leverage the Capabilities below:\n")
			for _, c := range caps {
				switch c {
				case "CAP_DAC_READ_SEARCH":
					fmt.Fprintln(capOut(), "[!] CAP_DAC_READ_SEARCH enabled. You can read files from host. Use 'cdk run cap-dac-boundary' ... for exploitation.")
				case "CAP_SYS_MODULE":
					fmt.Fprintln(capOut(), "[!] CAP_SYS_MODULE enabled. You can escape the container via loading kernel module. More info at https://xcellerator.github.io/posts/docker_escape/.")
				case "CAP_SYS_ADMIN":
					fmt.Fprintln(capOut(), "Critical - SYS_ADMIN Capability Found. Try 'cdk run cgroup-devices-boundary/cgroup-boundary/...'.")
				}
			}
		}

		if strings.Contains(matched, "3fffffffff") {
			fmt.Fprintln(capOut(), "Critical - Possible Privileged Container Found.")
			return true
		}
	}

	return false
}

func getAddCaps(currentCaps []string) []string {
	var addCaps []string
	for _, c := range currentCaps {
		if !util.StringContains(capability.DockerDefaultCaps, c) {
			addCaps = append(addCaps, c)
		}
	}
	return addCaps
}

func init() {
	RegisterSimplePrereqCheck(
		CategoryCommands,
		"commands.capabilities",
		"Inspect process capabilities",
		[]string{"InContainer"},
		func() {
			GetProcCapabilities()
		},
	)
}
