package evaluate

import (
	"os"
	"path/filepath"
	"testing"
)

// overrideEnvRoot installs a temporary directory as the root for all
// /proc /sys /etc reads inside env.go during a single test.
//
// Implementation note: detection helpers use a package-level `envRoot`
// variable (initialised to "/") as prefix for all absolute paths.
// overrideEnvRoot returns a cleanup func that restores it.
func overrideEnvRoot(t *testing.T, fixtureDir string) func() {
	t.Helper()
	orig := envRoot
	abs, err := filepath.Abs(fixtureDir)
	if err != nil {
		t.Fatalf("abs fixtureDir: %v", err)
	}
	envRoot = abs
	return func() { envRoot = orig }
}

// ensure envRoot variable compiles (defined in env.go).
var _ = envRoot

// buildFixture writes a scenario's proc/sys/etc tree into dir based on
// the named scenario.  Returns dir (for use with overrideEnvRoot).
func buildFixture(t *testing.T, scenario string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(path, content string) {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	switch scenario {
	case "bare-metal":
		// No docker env, plain /proc/1/cgroup init.scope, no SA, no cloud.
		write("proc/1/cgroup", "0::/init.scope\n")
		write("proc/1/sched", "systemd (1, #threads: 1)\n")
		write("proc/self/cgroup", "0::/user.slice/user-1000.slice\n")
		write("etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t2\n")
		write("sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")

	case "docker-linux-cgroupv2":
		// Docker Desktop / containerd Linux container, cgroup v2, non-privileged.
		write(".dockerenv", "")
		write("proc/1/cgroup", "0::/docker/abcdef123456\n")
		write("proc/1/sched", "bash (12345, #threads: 1)\n") // PID inside container != 1 on host
		write("proc/self/cgroup", "0::/docker/abcdef123456\n")
		write("etc/resolv.conf", "nameserver 127.0.0.11\noptions ndots:0\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t2\n")
		write("sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory hugetlb pids rdma misc\n")
		// docker socket absent from this fixture.

	case "k8s-pod-with-sa":
		// K8s pod: docker env + cgroup + SA token + cluster DNS.
		write(".dockerenv", "")
		write("proc/1/cgroup", "12:devices:/kubepods/besteffort/podXXX/abc\n")
		write("proc/1/sched", "pause (1, #threads: 1)\n")
		write("proc/self/cgroup", "12:devices:/kubepods/besteffort/podXXX/abc\n")
		write("etc/resolv.conf",
			"search default.svc.cluster.local svc.cluster.local cluster.local\n"+
				"nameserver 10.96.0.10\noptions ndots:5\n")
		write("var/run/secrets/kubernetes.io/serviceaccount/token",
			"eyJhbGciOiJSUzI1NiIsImtpZCI6InplcDIifQ.notempty")
		write("var/run/secrets/kubernetes.io/serviceaccount/namespace", "default\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t2\n")
		write("sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")

	case "k8s-pod-no-sa":
		// automountServiceAccountToken = false
		write(".dockerenv", "")
		write("proc/1/cgroup", "12:devices:/kubepods/podYYY/abc\n")
		write("proc/self/cgroup", "12:devices:/kubepods/podYYY/abc\n")
		write("etc/resolv.conf",
			"search default.svc.cluster.local svc.cluster.local cluster.local\n"+
				"nameserver 10.96.0.10\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t2\n")
		write("sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
		// No SA token tree.

	case "volcengine-ecs":
		// Bare VM, Volcengine.  Not a container, so cgroup v1 init-only.
		write("proc/1/cgroup", "12:devices:/\n")
		write("proc/1/sched", "systemd (1, #threads: 1)\n")
		write("proc/self/cgroup", "12:devices:/user.slice\n")
		write("etc/resolv.conf", "nameserver 100.96.0.96\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t0\n")
		// DMI markers for Volcengine.
		write("sys/class/dmi/id/sys_vendor", "Volcengine\n")
		write("sys/class/dmi/id/product_name", "BytePlus ECS\n")
		write("var/lib/cloud/instance/datasource", "DataSourceVolc: http://100.96.0.96\n")
		// No cgroup.controllers → cgroup v1 inferred.

	case "aws-ec2":
		write("proc/1/cgroup", "12:devices:/\n")
		write("proc/1/sched", "systemd (1, #threads: 1)\n")
		write("proc/self/cgroup", "12:devices:/user.slice\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t0\n")
		write("sys/class/dmi/id/product_uuid", "EC2F19B3-ABCD-1234-5678-90ABCDEF1234\n")
		write("sys/class/dmi/id/product_version", "20170311\n")
		write("var/lib/cloud/instance/datasource", "DataSourceEc2Local\n")

	case "cgroupv1-non-priv":
		// cgroup v1 container (no cgroup.controllers file), non-privileged.
		write(".dockerenv", "")
		write("proc/1/cgroup",
			"12:devices:/docker/abc\n"+
				"11:memory:/docker/abc\n"+
				"10:cpu,cpuacct:/docker/abc\n")
		write("proc/self/cgroup",
			"12:devices:/docker/abc\n"+
				"11:memory:/docker/abc\n")
		write("proc/self/status", capEffLine("00000000a80425fb")+"Seccomp:\t2\n")
		// No /sys/fs/cgroup/cgroup.controllers.

	case "privileged-container":
		write(".dockerenv", "")
		write("proc/1/cgroup", "12:devices:/docker/priv\n")
		write("proc/self/cgroup", "12:devices:/docker/priv\n")
		// Full capabilities: CapEff = 3fffffffff (40 bits, all 1s).
		write("proc/self/status", capEffLine("0000003fffffffff")+"Seccomp:\t0\n")
		write("sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")

	default:
		t.Fatalf("unknown scenario %q", scenario)
	}
	return dir
}

// capEffLine builds a fragment of /proc/self/status containing CapEff plus
// the standard surrounding context lines (Name, Uid, …) so line-based
// parsing works like the real file.
func capEffLine(capEff string) string {
	return "Name:\tcdk\n" +
		"Umask:\t0022\n" +
		"State:\tS (sleeping)\n" +
		"CapInh:\t0000000000000000\n" +
		"CapPrm:\t" + capEff + "\n" +
		"CapEff:\t" + capEff + "\n" +
		"CapBnd:\t" + capEff + "\n" +
		"CapAmb:\t0000000000000000\n" +
		"NoNewPrivs:\t0\n"
}

type envExpect struct {
	name   string
	env    *Env   // fields we care about; nil values = don't check
	vendor string // CloudVendor exact match; "" = don't care
	viaKey string // non-empty ⇒ assert env.DetectedVia has this key
}

func TestDetectEnv_Scenarios(t *testing.T) {
	cases := []struct {
		scenario string
		expect   envExpect
	}{
		{"bare-metal", envExpect{
			env: &Env{
				InContainer: false, HasDockerSock: false, HasContainerdSock: false,
				HasK8sSA: false, InClusterDNS: false, InCloud: false,
				HasCgroupV1: false, HasCgroupV2: true, Privileged: false,
			},
			vendor: "",
		}},
		{"docker-linux-cgroupv2", envExpect{
			env: &Env{
				InContainer: true, HasDockerSock: false, HasContainerdSock: false,
				HasK8sSA: false, InClusterDNS: false, InCloud: false,
				HasCgroupV1: false, HasCgroupV2: true, Privileged: false,
			},
			viaKey: "InContainer",
		}},
		{"k8s-pod-with-sa", envExpect{
			env: &Env{
				InContainer: true, HasK8sSA: true, InClusterDNS: true,
				InCloud: false, HasCgroupV1: false, HasCgroupV2: true,
				Privileged: false,
			},
			viaKey: "HasK8sSA",
		}},
		{"k8s-pod-no-sa", envExpect{
			env: &Env{
				InContainer: true, HasK8sSA: false, InClusterDNS: true,
				InCloud: false, HasCgroupV1: false, HasCgroupV2: true,
				Privileged: false,
			},
		}},
		{"volcengine-ecs", envExpect{
			env: &Env{
				InContainer: false, InCloud: true,
				HasCgroupV1: true, HasCgroupV2: false, Privileged: false,
			},
			vendor: "volcengine/byteplus",
			viaKey: "InCloud",
		}},
		{"aws-ec2", envExpect{
			env:    &Env{InCloud: true},
			vendor: "aws",
		}},
		{"cgroupv1-non-priv", envExpect{
			env: &Env{
				InContainer: true, HasCgroupV1: true, HasCgroupV2: false,
				Privileged: false,
			},
		}},
		{"privileged-container", envExpect{
			env: &Env{
				InContainer: true, HasCgroupV1: false, HasCgroupV2: true,
				Privileged: true,
			},
			viaKey: "Privileged",
		}},
	}

	for _, c := range cases {
		t.Run(c.scenario, func(t *testing.T) {
			fixture := buildFixture(t, c.scenario)
			cleanup := overrideEnvRoot(t, fixture)
			defer cleanup()

			got := DetectEnv()
			if got == nil {
				t.Fatal("DetectEnv = nil")
			}

			// Flag-by-flag comparison of non-nil expected fields.
			if c.expect.env != nil {
				checks := []struct {
					name string
					want bool
					gotF bool
				}{
					{"InContainer", c.expect.env.InContainer, got.InContainer},
					{"HasDockerSock", c.expect.env.HasDockerSock, got.HasDockerSock},
					{"HasContainerdSock", c.expect.env.HasContainerdSock, got.HasContainerdSock},
					{"HasK8sSA", c.expect.env.HasK8sSA, got.HasK8sSA},
					{"InClusterDNS", c.expect.env.InClusterDNS, got.InClusterDNS},
					{"InCloud", c.expect.env.InCloud, got.InCloud},
					{"HasCgroupV1", c.expect.env.HasCgroupV1, got.HasCgroupV1},
					{"HasCgroupV2", c.expect.env.HasCgroupV2, got.HasCgroupV2},
					{"Privileged", c.expect.env.Privileged, got.Privileged},
				}
				for _, c2 := range checks {
					if c2.want != c2.gotF {
						t.Errorf("flag %s: want=%v got=%v  (detected via: %q)",
							c2.name, c2.want, c2.gotF, got.DetectedVia[c2.name])
					}
				}
			}
			if c.expect.vendor != "" && c.expect.vendor != got.CloudVendor {
				t.Errorf("CloudVendor: want %q got %q", c.expect.vendor, got.CloudVendor)
			}
			if c.expect.viaKey != "" {
				if _, ok := got.DetectedVia[c.expect.viaKey]; !ok {
					t.Errorf("DetectedVia missing key %q; full map: %+v", c.expect.viaKey, got.DetectedVia)
				}
			}
		})
	}
}

func TestEnv_NoPanic(t *testing.T) {
	// DetectEnv on the *real* host (darwin) must not panic and should
	// yield all flags = false (we are not inside a Linux container).
	env := DetectEnv()
	if env == nil {
		t.Fatal("DetectEnv returned nil")
	}
	if env.InContainer {
		t.Logf("warning: darwin reports InContainer=true — double-check?")
	}
}

func TestMissingPrereqs_NilEnv(t *testing.T) {
	m := MissingPrereqs(nil, []string{"InContainer", "HasDockerSock"})
	if len(m) != 2 {
		t.Fatalf("expected 2 missing, got %v: %v", len(m), m)
	}
}

func TestMissingPrereqs_Known(t *testing.T) {
	env := &Env{InContainer: true, HasDockerSock: false}
	m := MissingPrereqs(env, []string{"InContainer", "HasDockerSock"})
	if len(m) != 1 || m[0] != "HasDockerSock" {
		t.Fatalf("want [HasDockerSock], got %v", m)
	}
}

func TestMissingPrereqs_Unknown(t *testing.T) {
	env := &Env{InContainer: true}
	m := MissingPrereqs(env, []string{"InContainer", "NoSuchFlag"})
	if len(m) != 1 || m[0] != "NoSuchFlag?" {
		t.Fatalf("want [NoSuchFlag?], got %v", m)
	}
}
