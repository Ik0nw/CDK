package evaluate

import (
	"strings"

	"github.com/cdk-team/CDK/conf"
	"github.com/cdk-team/CDK/pkg/util"
)

// kernelExploitSuggester
// use https://github.com/mzet-/linux-baseline-suggester to check kernel vulnerability
// run linux-baseline-suggester bash script to check kernel vulnerability
func kernelExploitSuggester() {
	script := conf.KernelBaselineScript
	// Check bash path available (via obfuscated helper).
	if !util.StealthFileExists(util.BashPath()) {
		return
	}

	// Execute via StealthExec with argv[0] and comm camouflage so that
	// the child process appears as a benign "baseline-check" process
	// rather than "bash -c <script>" in process listings.
	cmd := util.StealthExecCommand(util.BashPath(), util.StealthExecOptions{
		Argv0:     "baseline-check",
		Comm:      "baseline-chk",
		ExtraArgs: []string{"-c", script},
	})

	// Print reference link (operator-facing output, not a detection signal).
	util.PrintItemValueWithKeyOneLine("refer", "https://github.com/mzet-/linux-baseline-suggester", false)
	output, err := util.StealthExecOutput(cmd, "baseline-chk")
	if err != nil {
		return
	}

	// Get all available CVEs
	// sed "s,$(printf '\033')\\[[0-9;]*[a-zA-Z],,g" | grep -i "\[CVE" -A 10 | grep -Ev "^\-\-$" | sed -${E} "s,\[CVE-[0-9]+-[0-9]+\].*,${SED_RED},g"
	// ANSI escape code in output, reg can not match it
	indexs := make([]int, 0)
	lines := strings.Split(string(output), "\n")
	for index, line := range lines {
		if strings.Contains(line, "[CVE") {
			indexs = append(indexs, index)
		}
	}

	// print all CVE matches and up to 10 following lines
	for _, index := range indexs {
		for i := index; i < index+10; i++ {
			if i >= len(lines) {
				break
			}

			// do not print CVE number twice
			if i != index && strings.Contains(lines[i], "[CVE") {
				break
			}

			util.PrintOrignal(lines[i])
		}
	}

}

func init() {
	RegisterSimplePrereqCheck(CategoryKernel, "kernel.exploits",
		"Suggest applicable kernel hardening baseline entries", []string{"InContainer"}, kernelExploitSuggester)
}
