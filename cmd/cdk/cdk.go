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

	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/util"
	_ "github.com/cdk-team/CDK/pkg/exploit" // register all exploits
	_ "github.com/cdk-team/CDK/pkg/task"    // register all task
)

func main() {
	// Hidden inner branch: when re-executed as the short-lived cgroup
	// trigger process (replaces the tell-tale
	// `exec.Command("/bin/sh", "-c", "sleep 2")` pattern), stay alive
	// briefly so the parent can write our PID into cgroup.procs and thus
	// enroll us in the sub-cgroup. When we then exit, the sub-cgroup
	// becomes empty and notify_on_release fires release_agent. The sleep
	// is internal to this binary, so the argv vector stays clean
	// (no /bin/sh, no `sleep` binary, no /sys/fs/cgroup) — only the
	// innocuous marker below is visible. Exiting immediately would race
	// the parent's PID write and could fail to enroll, leaving
	// release_agent unfired under scheduling pressure.
	if len(os.Args) >= 2 && os.Args[1] == util.TriggerArgv {
		// Stay alive briefly so the parent can enroll us (write our PID
		// into cgroup.procs) before we exit; exiting then empties the
		// sub-cgroup and fires notify_on_release -> release_agent. The
		// sleep is internal, so argv stays clean (no /bin/sh, no `sleep`
		// binary). Exiting immediately usually still works (the parent
		// generally wins the enroll race), but a fixed lifetime removes
		// any load-dependent failure and matches the original CDK design.
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	cli.ParseCDKMain()
}
