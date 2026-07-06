package kubectl

import (
	"bytes"
	_ "embed"
	"os"
	"path/filepath"

	"github.com/cdk-team/CDK/pkg/util"
)

//go:embed assets/kubectl-amd64
var kubectlBinary []byte

func ExtractKubectl() (string, error) {
	tmpDir, err := os.MkdirTemp("", ".bin")
	if err != nil {
		return "", err
	}

	kubectlPath := filepath.Join(tmpDir, "kubectl")

	err = os.WriteFile(kubectlPath, kubectlBinary, 0755)
	if err != nil {
		return "", err
	}

	return kubectlPath, nil
}

func ExecKubectl(kubectlPath string, args []string) (out string, errStr string) {

	// Use StealthExec with argv[0] spoofing so kubectl appears as
	// "k8s-helper" in /proc/PID/cmdline rather than the full
	// extracted temp path with "kubectl" arguments.
	cmd := util.StealthExecCommand(kubectlPath, util.StealthExecOptions{
		Argv0:     "k8s-helper",
		Comm:      "k8s-helper",
		ExtraArgs: args,
	})

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := util.StealthExecStart(cmd, "k8s-helper")
	if err != nil {
		errStr = err.Error()
		return out, errStr
	}
	err = cmd.Wait()

	out = stdout.String()
	errStr = stderr.String()

	if err != nil {
		errStr = err.Error() + "\n" + errStr
		return out, errStr
	}

	return out, errStr

}
