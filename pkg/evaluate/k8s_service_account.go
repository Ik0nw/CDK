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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/cdk-team/CDK/conf"
	"github.com/cdk-team/CDK/pkg/tool/kubectl"
)

// CheckPrivilegedK8sServiceAccount first decodes any mounted SA token
// (JWT header + payload, no signature validation — this is reconnaissance
// only) so operators can see the identity / namespace / audience even when
// there is no reachable kube-apiserver.  It then attempts a handful of
// anonymous and authorised API-server probes to estimate privilege.
func CheckPrivilegedK8sServiceAccount(tokenPath string) bool {
	priv := decodeAndPrintSAToken(tokenPath)

	resp, err := kubectl.ServerAccountRequest(
		kubectl.K8sRequestOption{
			TokenPath: "",
			Server:    "",
			Api:       "/apis",
			Method:    "get",
			PostData:  "",
			Anonymous: false,
		})
	if err != nil {
		fmt.Printf("\tcould not reach kube-apiserver for live privilege probe: %v\n", err)
		fmt.Println("\t(reconnaissance-only SA token decode was printed above; no network reachability to APIServer.)")
		return priv
	}
	if len(resp) > 0 && strings.Contains(resp, "APIGroupList") {
		fmt.Println("\tservice-account credentials accepted by apiserver (APIGroupList returned)")

		// check if the current service-account can list namespaces
		log.Println("trying to list namespaces")
		resp, err := kubectl.ServerAccountRequest(
			kubectl.K8sRequestOption{
				TokenPath: "",
				Server:    "",
				Api:       "/api/v1/namespaces",
				Method:    "get",
				PostData:  "",
				Anonymous: false,
			})
		if err != nil {
			fmt.Println(err)
			return priv
		}
		if len(resp) > 0 && strings.Contains(resp, "kube-system") {
			fmt.Println("\tsuccess, the service-account have a high authority (list-namespaces works).")
			fmt.Println("\tnow you can make your own request to takeover the entire k8s cluster with `./cdk kcurl` command\n\tgood luck and have fun.")
			return true
		} else {
			fmt.Println("\tlist-namespaces denied (or returned no kube-system)")
			fmt.Println("\tresponse preview: " + truncate(resp, 160))
			return priv
		}
	} else {
		fmt.Println("\tapiserver rejected SA credentials (or did not return APIGroupList)")
		fmt.Println("\tresponse preview: " + truncate(resp, 160))
		return priv
	}
}

// truncate returns s trimmed to maxRunes runes; it never panics on empty input.
func truncate(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "..."
}

// decodeAndPrintSAToken base64url-decodes the two JSON segments of the JWT
// mounted at tokenPath and prints a nicely-formatted operator summary.
// Header crypto fields (alg, kid) are validated-by-parsing only; we do NOT
// verify the signature (this is reconnaissance, not auth).
//
// Returns a boolean that hints whether the token conveys cluster-wide
// privilege so the caller can short-circuit its "high-authority" return
// value even when the API server is unreachable.
func decodeAndPrintSAToken(tokenPath string) bool {
	raw, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		fmt.Printf("\tSA token file unreadable: %v\n", err)
		return false
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		fmt.Println("\tSA token file present but empty")
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		fmt.Printf("\tSA token has unexpected format (%d dot-separated segments; expected JWT >= 2)\n", len(parts))
		return false
	}
	header, errH := decodeJWTsegment(parts[0])
	claims, errC := decodeJWTsegment(parts[1])
	if errH != nil || errC != nil {
		fmt.Printf("\tSA token base64 decode failed: header=%v payload=%v\n", errH, errC)
		return false
	}

	var saName, saNS, sub, iss string
	var aud []string
	var nbf, exp int64
	var groups []string
	clusterWideHint := false

	if v, ok := stringField(claims, "sub"); ok {
		sub = v
		// Standard K8s SA sub: "system:serviceaccount:<namespace>:<name>"
		if strings.HasPrefix(sub, "system:serviceaccount:") {
			segs := strings.Split(sub, ":")
			if len(segs) >= 4 {
				saNS = segs[2]
				saName = segs[3]
			}
		}
	}
	if v, ok := stringField(claims, "iss"); ok {
		iss = v
	}
	if ks, ok := mapField(claims, "kubernetes.io"); ok {
		if v, ok := stringField(ks, "namespace"); ok && saNS == "" {
			saNS = v
		}
		if pod, ok := mapField(ks, "pod"); ok {
			if v, ok := stringField(pod, "name"); ok {
				fmt.Printf("\tpod.name        : %s\n", v)
			}
			if v, ok := stringField(pod, "uid"); ok {
				fmt.Printf("\tpod.uid         : %s\n", v)
			}
		}
		if svc, ok := mapField(ks, "serviceaccount"); ok {
			if v, ok := stringField(svc, "name"); ok && saName == "" {
				saName = v
			}
			if v, ok := stringField(svc, "uid"); ok {
				fmt.Printf("\tserviceaccount.uid: %s\n", v)
			}
		}
	}
	aud = stringSliceField(claims, "aud")
	groups = stringSliceField(claims, "groups")
	nbf, _ = intField(claims, "nbf")
	exp, _ = intField(claims, "exp")

	// Privilege hints (recon only — not proof).
	for _, g := range groups {
		switch g {
		case "system:masters", "system:cluster-admins":
			clusterWideHint = true
		}
	}
	// Default SA has almost no privilege and is safe to flag explicitly.
	if saName == "default" && len(groups) == 0 {
		clusterWideHint = false
	}

	fmt.Println("\tService-account token (JWT, reconnaissance decode — no signature check):")
	if saNS != "" {
		fmt.Printf("\tnamespace       : %s\n", saNS)
	}
	if saName != "" {
		fmt.Printf("\tserviceaccount  : %s\n", saName)
	}
	if sub != "" {
		fmt.Printf("\tsub             : %s\n", sub)
	}
	if iss != "" {
		fmt.Printf("\tiss             : %s\n", iss)
	}
	if len(aud) > 0 {
		fmt.Printf("\taud             : %s\n", strings.Join(aud, ", "))
	}
	if nbf > 0 {
		fmt.Printf("\tnbf             : %s\n", time.Unix(nbf, 0).UTC().Format(time.RFC3339))
	}
	if exp > 0 {
		remaining := time.Until(time.Unix(exp, 0))
		fmt.Printf("\texp             : %s  (remaining %v)\n",
			time.Unix(exp, 0).UTC().Format(time.RFC3339), remaining.Round(time.Second))
	}
	if len(groups) > 0 {
		sorted := append([]string(nil), groups...)
		sort.Strings(sorted)
		fmt.Printf("\tgroups          : %s\n", strings.Join(sorted, ", "))
	}
	if v, ok := stringField(header, "alg"); ok {
		fmt.Printf("\theader.alg      : %s\n", v)
	}
	if v, ok := stringField(header, "kid"); ok {
		fmt.Printf("\theader.kid      : %s\n", v)
	}
	switch {
	case clusterWideHint:
		fmt.Println("\t⚠  privilege hint : groups include cluster-admin level — treat as high-authority token")
	case saName == "default":
		fmt.Println("\tℹ  privilege hint : default SA (no RBAC bindings by default — low privilege)")
	default:
		fmt.Println("\tℹ  privilege hint : custom SA; reach apiserver (/apis, /api/v1/namespaces) for RBAC scope")
	}
	return clusterWideHint
}

// --- small JSON helpers (stdlib only; no external dependencies) ------------

func decodeJWTsegment(seg string) (map[string]interface{}, error) {
	// JWT segments use base64url without padding.
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		// Some issuers emit padded base64url; fall back.
		raw, err = base64.URLEncoding.DecodeString(padBase64(seg))
		if err != nil {
			return nil, fmt.Errorf("base64url decode: %w", err)
		}
	}
	var out map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return out, nil
}

func padBase64(s string) string {
	switch len(s) % 4 {
	case 0:
		return s
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

func stringField(m map[string]interface{}, k string) (string, bool) {
	v, ok := m[k]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func mapField(m map[string]interface{}, k string) (map[string]interface{}, bool) {
	v, ok := m[k]
	if !ok {
		return nil, false
	}
	sub, ok := v.(map[string]interface{})
	return sub, ok
}

func stringSliceField(m map[string]interface{}, k string) []string {
	v, ok := m[k]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case string:
		return []string{x}
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func intField(m map[string]interface{}, k string) (int64, bool) {
	v, ok := m[k]
	if !ok {
		return 0, false
	}
	switch x := v.(type) {
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	case float64:
		return int64(x), true
	}
	return 0, false
}

func init() {
	RegisterSimplePrereqCheck(
		CategoryK8sServiceAccount,
		"k8s.privileged_service_account",
		"Check Kubernetes service account privileges",
		[]string{"HasK8sSA"},
		func() {
			CheckPrivilegedK8sServiceAccount(conf.K8sSATokenDefaultPath)
		},
	)
}
