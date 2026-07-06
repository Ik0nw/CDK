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
	"github.com/cdk-team/CDK/conf"
	"github.com/cdk-team/CDK/pkg/util"
	"log"
	"strings"
)

// commandExists checks whether a named binary is available in common system
// paths. Uses StealthFileExists to avoid libc PATH resolution hooks.
func commandExists(name string) bool {
	paths := []string{
		"/usr/bin/" + name,
		"/bin/" + name,
		"/usr/sbin/" + name,
		"/sbin/" + name,
		"/usr/local/bin/" + name,
		"/usr/local/sbin/" + name,
	}
	for _, p := range paths {
		if util.StealthFileExists(p) {
			return true
		}
	}
	return false
}

func SearchAvailableCommands() {
	ans := []string{}
	for _, cmd := range conf.LinuxCommandChecklist {
		if commandExists(cmd) {
			ans = append(ans, cmd)
		}
	}
	log.Printf("available commands:\n\t%s\n", strings.Join(ans, ","))
}

func init() {
	RegisterSimplePrereqCheck(CategoryCommands, "commands.available", "Enumerate available commands",
		[]string{"InContainer"}, SearchAvailableCommands)
}
