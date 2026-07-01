//go:build !no_connect_back
// +build !no_connect_back

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

package remote_control

import (
	"log"
	"net"
	"time"

	"github.com/cdk-team/CDK/pkg/audit/base"

	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/plugin"
)

func ReverseShell(connectString string) {
	if len(connectString) == 0 { //valid input: "192.168.0.23:2233"
		log.Fatal("invalid audit handshake remote addr: ", connectString)
	}
	conn, err := net.DialTimeout("tcp", connectString, 3*time.Second)
	if err != nil {
		log.Fatal("fail to connect remote addr: ", connectString)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("CDK-AUDIT-HANDSHAKE\n"))
	log.Printf("connectivity handshake completed with %s", connectString)
}

// plugin interface
type reverseShellS struct{ base.BaseExploit }

func (p reverseShellS) Desc() string {
	return "send a short connectivity handshake to an authorized audit endpoint, usage: cdk run connect-back-shell <ip:port>"
}
func (p reverseShellS) Run() bool {
	args := cli.Args["<args>"].([]string)
	if len(args) != 1 {
		log.Println("Invalid input args.")
		log.Fatal(p.Desc())
	}
	ReverseShell(args[0])
	return true
}

func init() {
	exploit := reverseShellS{}
	exploit.ExploitType = "remote-control"
	plugin.RegisterExploit("connect-back-shell", exploit)
}
