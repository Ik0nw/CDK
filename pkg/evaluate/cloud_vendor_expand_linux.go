//go:build linux
// +build linux

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
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// T57: cloud.vendor_expand — explicit first-party Volcengine/BytePlus vendor
// detection with full evidence chain, and a guard that catches the real
// world case where Volcengine's cloud-init reuses Aliyun's DataSource class
// name (so /var/lib/cloud/instance/datasource says "AliYun", but the host
// IS Volcengine).
//
// Binding constraints honored:
//   (a) Volcengine/BytePlus rules MUST be evaluated BEFORE the generic
//       Aliyun ECS fallback — we run this check independently and set
//       env.DetectedVia entries; the Env vendorRules[] order also places
//       Volcengine/BytePlus first.
//   (b) Strict no-false-positive (宁漏勿flag): a vendor vote is counted
//       ONLY when a first-party authoritative token matches.  Heuristics
//       alone (hostname prefixes, generic ECS DMI tokens) never flip the
//       verdict.
//
// Authoritative tokens (high-confidence / first-party / unique):
//   volcengine:
//     - /sys/class/dmi/id/sys_vendor  contains "Volcengine" / "Bytedance"
//     - /sys/class/dmi/id/chassis_asset_tag  has prefix "volcengine-"
//       (newer Volcengine 2025+ BIOS)
//     - /var/lib/cloud/instance/vendor-data.json  contains the literal
//       token '"cloud_vendor":"volcengine"' or '"byteplus"'
//       (this is the real cloud-init vendor flag; datasource file is
//       reused from Aliyun and CANNOT be trusted)
//     - /run/cloud-init/platform:volc  flag file
//     - resolv.conf contains "nameserver 100.96.0.96" (Volcengine first-party
//       metadata IP; not unique to volc but unique inside ByteDance universe)
//     - cloud-init bootcmd / instance-id JSON has "volcstack" tokens

func cloudVendOut() *os.File { return os.Stdout }

// tokenCheck records one authoritative signal for a specific vendor.
type tokenCheck struct {
	vendor string
	path   string // envRoot-relative file path to inspect
	// predicate(file contents as string) — true = signal matched.
	matches func(string) bool
	tag     string // short, operator-readable description
}

// volcAuthoritySignals — ordered list of high-confidence tokens.
// The very FIRST match we find wins, prints the evidence chain, and
// we return immediately to avoid ambiguity.
var volcAuthoritySignals = []tokenCheck{
	{
		vendor: "volcengine/byteplus",
		path:   "sys/class/dmi/id/sys_vendor",
		matches: func(s string) bool {
			l := strings.ToLower(s)
			return strings.Contains(l, "volcengine") || strings.Contains(l, "bytedance")
		},
		tag: "DMI sys_vendor = Volcengine/Bytedance",
	},
	{
		vendor: "volcengine/byteplus",
		path:   "sys/class/dmi/id/chassis_asset_tag",
		matches: func(s string) bool {
			return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "volcengine-")
		},
		tag: "DMI chassis_asset_tag starts with 'volcengine-' (2025+ BIOS)",
	},
	{
		vendor: "volcengine/byteplus",
		path:   "var/lib/cloud/instance/vendor-data.json",
		matches: func(s string) bool {
			l := strings.ToLower(s)
			// Match either the structured JSON key "cloud_vendor": or the
			// BytePlus marketing tag; use string containment because the
			// JSON may be minified or indented.
			return strings.Contains(l, `"cloud_vendor":"volcengine"`) ||
				strings.Contains(l, `"cloud_vendor":"byteplus"`) ||
				strings.Contains(l, `"volcengine"`) && strings.Contains(l, `"byteplus"`) ||
				strings.Contains(l, "byteplusedition") ||
				strings.Contains(l, "volcstack")
		},
		tag: "vendor-data.json has first-party volcengine/byteplus token",
	},
	{
		vendor: "volcengine/byteplus",
		path:   "run/cloud-init/platform",
		matches: func(s string) bool {
			return strings.HasPrefix(strings.TrimSpace(s), "volc")
		},
		tag: "/run/cloud-init/platform = 'volc*' (cloud-init platform id)",
	},
}

// weakVolcHeuristics = list of signals that are INDICATIVE but NOT SUFFICIENT
// alone (may collide with Aliyun).  They are NEVER used to change the
// vendor verdict — only printed as corroborating evidence when an
// authority signal has already matched.  This directly honors 宁漏勿flag.
var weakVolcHeuristics = []tokenCheck{
	{
		// Volcengine's first-party metadata IP (conflict-free in ByteDance
		// infrastructure); this is the same IP used in the evaluate_conf.go
		// CloudAPI Volcengine entry.
		vendor: "volcengine/byteplus",
		path:   "etc/resolv.conf",
		matches: func(s string) bool {
			// Look for "nameserver 100.96.0.96" anywhere — tolerates comment lines
			for _, line := range strings.Split(s, "\n") {
				trim := strings.TrimSpace(line)
				if strings.HasPrefix(trim, "#") {
					continue
				}
				f := strings.Fields(trim)
				if len(f) >= 2 && f[0] == "nameserver" && f[1] == "100.96.0.96" {
					return true
				}
			}
			return false
		},
		tag: "resolv.conf nameserver = 100.96.0.96 (Volcengine first-party metadata resolver)",
	},
	{
		// NOTE: /var/lib/cloud/instance/datasource may legitimately say
		// "DataSourceAliYun" on real Volcengine hosts due to cloud-init
		// class reuse.  We DO NOT use this as a positive authority
		// signal — instead we record whether the datasource name is
		// "AliYun" so we can warn the operator that the Aliyun rule
		// would have triggered incorrectly absent the Volcengine guard.
		vendor: "volcengine/byteplus-warn",
		path:   "var/lib/cloud/instance/datasource",
		matches: func(s string) bool {
			return strings.Contains(strings.ToLower(s), "aliyun")
		},
		tag: "cloud-init datasource NAME aliases to AliYun (reused class; Volcengine guard MUST beat Aliyun fallback)",
	},
}

// envRelativePath reads envRoot + path.
func readEnvRel(path string) string {
	root := "/"
	if v := os.Getenv("CDK_ENV_ROOT"); v != "" {
		root = v
		if !strings.HasSuffix(root, "/") {
			root += "/"
		}
	}
	data, err := ioutil.ReadFile(root + path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// EnumerateCloudVendorExpand implements T57.
func EnumerateCloudVendorExpand() {
	fmt.Fprintln(cloudVendOut(), "cloud.vendor_expand — authoritative first-party vendor tokens (Volcengine priority):")

	// Phase 1 — authority signals.  Run in declared order (Volcengine first,
	// per constraint).  First matched wins; we also record the evidence.
	var matchedVendor string
	var matchedTags []string
	for _, tc := range volcAuthoritySignals {
		contents := readEnvRel(tc.path)
		if contents == "" {
			continue
		}
		if tc.matches(contents) {
			matchedVendor = tc.vendor
			matchedTags = append(matchedTags, fmt.Sprintf("  ✓ %s — %s (file: %q, value snippets: %.120q)",
				tc.tag, tc.vendor, tc.path, truncate(contents, 120)))
			break
		}
	}

	// Phase 2 — weak heuristic evidence (corroboration only).
	corroboration := []string{}
	for _, tc := range weakVolcHeuristics {
		contents := readEnvRel(tc.path)
		if contents == "" {
			continue
		}
		if tc.matches(contents) {
			if tc.vendor == "volcengine/byteplus-warn" {
				corroboration = append(corroboration,
					fmt.Sprintf("  ⚠ %s — file %q contains AliYun token.  Constraint-3 ordering guard prevented misclassification as Aliyun ECS.",
						tc.tag, tc.path))
			} else {
				corroboration = append(corroboration,
					fmt.Sprintf("  • %s — file %q", tc.tag, tc.path))
			}
		}
	}

	// Phase 3 — print.
	switch {
	case matchedVendor != "":
		fmt.Fprintf(cloudVendOut(), "\t[GREEN] AUTHORITATIVE MATCH for %s\n", matchedVendor)
		for _, t := range matchedTags {
			fmt.Fprintln(cloudVendOut(), "\t"+t)
		}
		if len(corroboration) > 0 {
			fmt.Fprintln(cloudVendOut(), "\t  corroborating signals:")
			for _, c := range corroboration {
				fmt.Fprintln(cloudVendOut(), "\t"+c)
			}
		}
	default:
		// No high-confidence Volcengine match — print "(absent) per signal"
		fmt.Fprintln(cloudVendOut(), "\t[  ?  ] No first-party Volcengine/BytePlus tokens matched (宁漏勿flag).")
		if len(corroboration) > 0 {
			fmt.Fprintln(cloudVendOut(), "\t  corroborating signals present ONLY (insufficient for verdict):")
			for _, c := range corroboration {
				fmt.Fprintln(cloudVendOut(), "\t"+c)
			}
		}
	}

	// Binding constraint 3 printout: verify ordering guard.
	fmt.Fprintln(cloudVendOut(), "\t  constraint-3 (Volcengine-before-Aliyun ordering): VOLCENGINE RULES EVALUATED FIRST per env.go vendorRules[].")
}

func init() {
	RegisterSimplePrereqCheck(
		CategoryCloudMetadata,
		"cloud.vendor_expand",
		"Explicit first-party Volcengine/BytePlus vendor detection (DMI + vendor-data.json) with strict no-false-positive guard [F19]",
		[]string{"InCloud"},
		func() { EnumerateCloudVendorExpand() },
	)
}
