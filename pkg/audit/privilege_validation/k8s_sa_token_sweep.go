//go:build !no_k8s_sa_token_sweep
// +build !no_k8s_sa_token_sweep

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

import (
	"fmt"
	"log"
	"strings"

	"github.com/cdk-team/CDK/pkg/audit/base"

	"github.com/cdk-team/CDK/conf"
	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/errors"
	"github.com/cdk-team/CDK/pkg/plugin"
	"github.com/cdk-team/CDK/pkg/tool/kubectl"
	"github.com/cdk-team/CDK/pkg/util"
)

var k8sCreateSystemPodAPI = "/api/v1/namespaces/default/pods"
var k8sGetSATokenPodConf = `{
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {
		"name": "cdk-rbac-validator-create-pod",
		"namespace": "default",
		"labels": {
			"audit.cdk/owner": "cdk",
			"audit.cdk/component": "sa-token-validator"
		}
	},
	"spec": {
		"automountServiceAccountToken": true,
		"containers": [{
			"args": ["-c", "test -s ${SA_TOKEN_PATH} && echo token-mounted || echo token-missing; sleep 30"],
			"command": ["${SHELL_PATH}"],
			"image": "ubuntu",
			"name": "ubuntu"
		}],
		"hostNetwork": true,
		"serviceAccountName": "${TARGET_SERVICE_ACCOUNT}"
	}
}`

func GetK8sSATokenViaCreatePod(tokenPath string, targetServiceAccount string, rhost string, rport string) error {

	// get api-server connection conf in ENV
	log.Println("getting K8s api-server API addr.")
	addr, err := kubectl.ApiServerAddr()
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "err found while getting K8s apiserver address."}
	}
	fmt.Println("\tFind K8s api-server in ENV:", addr)

	// create a short-lived labeled pod with target serviceaccount token mounted
	log.Printf("Trying to create a labeled pod to validate service-account:%s token mount state; no token is sent to remote endpoints\n", targetServiceAccount)

	opts := kubectl.K8sRequestOption{
		TokenPath: "",
		Server:    addr,
		Api:       k8sCreateSystemPodAPI,
		Method:    "POST",
		PostData:  "",
		Anonymous: false,
	}

	switch tokenPath {
	case "default":
		opts.TokenPath = conf.K8sSATokenDefaultPath
	case "anonymous":
		opts.TokenPath = ""
		opts.Anonymous = true
	default:
		opts.TokenPath = tokenPath
	}

	opts.PostData = strings.Replace(k8sGetSATokenPodConf, "${TARGET_SERVICE_ACCOUNT}", targetServiceAccount, -1)
	opts.PostData = strings.Replace(opts.PostData, "${SHELL_PATH}", util.ShellPath(), -1)
	opts.PostData = strings.Replace(opts.PostData, "${SA_TOKEN_PATH}", conf.K8sSATokenDefaultPath, -1)

	log.Println("Request Body: ", util.RedactSensitive(opts.PostData))

	resp, err := kubectl.ServerAccountRequest(opts)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "err found while requesting K8s apiserver."}
	}
	log.Println("api-server response:")
	fmt.Println(util.RedactSensitive(resp))
	util.WriteAuditManifest("pod", "cdk-rbac-validator-create-pod", opts.PostData)

	return nil
}

// plugin interface
type K8sGetSATokenViaCreatePodS struct{ base.BaseExploit }

func (p K8sGetSATokenViaCreatePodS) Desc() string {
	return "Create a labeled validation pod to check target service-account token mount state without exfiltrating token data, usage: cdk run k8s-sa-token-sweep (default|anonymous|<service-account-token-path>) <target-service-account> <ip> <port>"
}
func (p K8sGetSATokenViaCreatePodS) Run() bool {
	args := cli.Args["<args>"].([]string)
	if len(args) != 4 {
		log.Println("invalid input args.")
		log.Fatal(p.Desc())
	}

	token := args[0]
	targetServiceAccount := args[1]
	remoteIP := args[2]
	remotePort := args[3]

	err := GetK8sSATokenViaCreatePod(token, targetServiceAccount, remoteIP, remotePort)
	if err != nil {
		log.Println("check failed.")
		log.Println(err)
		return false
	}

	return true
}

func init() {
	exploit := K8sGetSATokenViaCreatePodS{}
	exploit.ExploitType = "privilege-escalation"
	exploit.ActivePrereqs = []string{"HasK8sAPI"}
	plugin.RegisterExploit("k8s-sa-token-sweep", exploit)
}
