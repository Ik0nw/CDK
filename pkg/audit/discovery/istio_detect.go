//go:build !no_istio_detect
// +build !no_istio_detect

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

package discovery

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cdk-team/CDK/pkg/audit/base"
	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/plugin"
	"github.com/cdk-team/CDK/pkg/util"
)

type istioCheckS struct{ base.BaseExploit }

func (p istioCheckS) Desc() string {
	return "Check whether an internal echo endpoint shows Istio sidecar headers. Usage: cdk run istio-detect <internal-echo-url>"
}

type isioHeader struct {
	XAmznTraceId         string `json:"X-Amzn-Trace-Id"`
	XB3Sampled           string `json:"X-B3-Sampled"`
	XB3Spanid            string `json:"X-B3-Spanid"`
	XB3Traceid           string `json:"X-B3-Traceid"`
	XEnvoyAttemptCount   string `json:"X-Envoy-Attempt-Count"`
	XEnvoyPeerMetadata   string `json:"X-Envoy-Peer-Metadata"`
	XEnvoyPeerMetadataId string `json:"X-Envoy-Peer-Metadata-Id"`
}

type response struct {
	Header isioHeader `json:"headers"`
}

func (p istioCheckS) Run() bool {
	args := cli.Args["<args>"].([]string)
	if len(args) != 1 {
		log.Println("istio-detect skipped: provide an internal echo endpoint explicitly")
		log.Println(p.Desc())
		return false
	}
	target := args[0]
	if !allowedAuditHTTPURL(target) {
		log.Printf("istio-detect refused non-internal endpoint %q; set CDK_ALLOW_PUBLIC_PROBE=1 only for an authorized audit peer", target)
		return false
	}

	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		log.Printf("cannot fetch %s: %v", target, err)
		return false
	}
	defer resp.Body.Close()

	var result response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		log.Printf("cannot decode JSON from %s: %v; response=%s", target, err, util.RedactSensitive(string(bodyBytes)))
		return false
	}

	if strings.Contains(result.Header.XEnvoyPeerMetadataId, "sidecar") {
		log.Println("the shell is in a istio(service mesh) network.")
		log.Printf("X-Envoy-Peer-Metadata-Id is %s.", util.RedactSensitive(result.Header.XEnvoyPeerMetadataId))
		log.Printf("X-Envoy-Peer-Metadata is %s.", util.RedactSensitive(result.Header.XEnvoyPeerMetadata))
		return true
	}
	log.Println("the shell is not in a istio(service mesh) network.")
	return false
}

func allowedAuditHTTPURL(raw string) bool {
	if os.Getenv("CDK_ALLOW_PUBLIC_PROBE") == "1" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.Trim(u.Hostname(), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local") {
		return true
	}
	if !strings.Contains(host, ".") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func init() {
	exploit := istioCheckS{}
	exploit.ExploitType = "discovery"
	exploit.ActivePrereqs = []string{"HasIstioSidecar"}
	plugin.RegisterExploit("istio-detect", exploit)
}
