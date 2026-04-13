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
	"log"
	"os"
	"strings"
)

// kataIndicators lists kernel command-line substrings that are exclusive to
// Kata Containers guest VMs.  The presence of any one of them is sufficient
// to conclude that the process is running inside a Kata sandbox.
var kataIndicators = []string{
	"systemd.unit=kata-containers.target",
	"agent.log=",
	"agent.debug_console",
	"agent.cdh_api_timeout=",
}

// CheckKataContainer inspects /proc/cmdline for boot parameters that are
// exclusive to Kata Containers guest VMs and reports whether the current
// environment appears to be a Kata sandbox.
func CheckKataContainer() {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		log.Printf("kata: unable to read /proc/cmdline: %v", err)
		return
	}

	cmdline := string(data)
	log.Printf("kata: /proc/cmdline: %s", strings.TrimSpace(cmdline))

	var matched []string
	for _, indicator := range kataIndicators {
		if strings.Contains(cmdline, indicator) {
			matched = append(matched, indicator)
		}
	}

	if len(matched) > 0 {
		log.Println("kata: Kata Containers environment detected!")
		for _, m := range matched {
			log.Printf("kata: matched indicator: %s", m)
		}
	} else {
		log.Println("kata: no Kata Containers indicators found in /proc/cmdline")
	}
}

func init() {
	RegisterSimpleCheck(CategorySecurity, "security.kata_container", "Check if running inside a Kata Container", CheckKataContainer)
}
