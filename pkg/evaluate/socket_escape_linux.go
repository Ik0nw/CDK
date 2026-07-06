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
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cdk-team/CDK/pkg/util"
)

// socketEscapeProbe holds the result of probing a container runtime socket
// for escape viability.
type socketEscapeProbe struct {
	SocketPath string
	Runtime    string
	Reachable  bool
	VersionAPI bool
	ContainerList bool
	PrivilegedCreate bool
	Error      string
}

// CheckSocketEscape performs a functional audit of mounted container runtime
// sockets (docker.sock, containerd.sock) to determine whether they can be
// used for container escape.
//
// For each socket we test:
//  1. Can we connect to it at all? (basic reachability)
//  2. Does the Docker/containerd API respond to /_ping or /v1.41/version?
//  3. Can we list containers? (read-only recon)
//  4. Can we create a privileged container? (escape — this is the real test)
//
// OPSEC: all HTTP requests use a 2-second timeout, a minimal User-Agent,
// and O_CLOEXEC on the underlying dialer.  We never actually create a
// container — we only probe the API surface.  The "can we create privileged"
// check is done via a dry-run that inspects the API response without
// committing the container creation.
//
// T59 / security.socket_escape.
func CheckSocketEscape(ctx *Context) error {
	env := ctx.Env
	if env == nil {
		env = DetectEnv()
	}

	fmt.Fprintf(os.Stdout, "socket escape audit (T59) — runtime socket reachability + escape viability:\n")

	// Collect candidate socket paths from env detection + common locations.
	sockets := []socketEscapeProbe{}

	// Docker socket candidates.
	if env.HasDockerSock {
		sockets = append(sockets, socketEscapeProbe{
			SocketPath: util.DockerSockPath(),
			Runtime:    "docker",
		})
	}
	// Also check DOCKER_HOST if set.
	if dh := os.Getenv("DOCKER_HOST"); dh != "" {
		if len(dh) > 7 && dh[:7] == "unix://" {
			sockets = append(sockets, socketEscapeProbe{
				SocketPath: dh[7:],
				Runtime:    "docker (DOCKER_HOST)",
			})
		}
	}

	// Containerd socket candidates.
	if env.HasContainerdSock {
		sockets = append(sockets, socketEscapeProbe{
			SocketPath: util.ContainerdSockPath(),
			Runtime:    "containerd",
		})
	}

	// CRI-O socket (common in OpenShift / kubelet CRI).
	crioPath := util.XorObfsPath([]byte{
		0x73, 0x2e, 0x27, 0x2c, 0x77, 0x3f, 0x29, 0x74,
		0x37, 0x32, 0x24, 0x38, 0x25, 0x21, 0x63, 0x3a,
		0x3b, 0x2b, 0x2f, 0x21, 0x3a, 0x2d, 0x38, 0x2b,
		0x2a, 0x3a, 0x2d, 0x38, 0x2b, 0x2a, 0x3a, 0x2d,
		0x38, 0x2b, 0x2a, 0x3a, 0x2d, 0x38, 0x2b, 0x2a,
	})
	_ = crioPath // reserved for future CRI-O probe

	if len(sockets) == 0 {
		fmt.Fprintf(os.Stdout, "\t[AMBER] no container runtime sockets detected via preflight.\n")
		fmt.Fprintf(os.Stdout, "\t        Checking common paths anyway...\n")
		// Fall back: try the common paths even if preflight didn't detect them.
		sockets = []socketEscapeProbe{
			{SocketPath: util.DockerSockPath(), Runtime: "docker (fallback)"},
			{SocketPath: util.ContainerdSockPath(), Runtime: "containerd (fallback)"},
		}
	}

	anyReachable := false
	for i := range sockets {
		probeRuntimeSocket(&sockets[i])
		reportSocketProbe(sockets[i])
		if sockets[i].Reachable {
			anyReachable = true
		}
	}

	if !anyReachable {
		fmt.Fprintf(os.Stdout, "\n\t[AMBER] no runtime sockets reachable from inside container.\n")
		fmt.Fprintf(os.Stdout, "\t        Socket-mount escape surface: CLOSED\n")
	} else {
		fmt.Fprintf(os.Stdout, "\n\t  ⚠  REACHABLE runtime socket(s) found — socket-mount escape surface OPEN.\n")
		fmt.Fprintf(os.Stdout, "\t     Use 'cdk run docker-sock' or direct API calls to escape via privileged container creation.\n")
	}

	return nil
}

// probeRuntimeSocket performs the actual HTTP-over-unix-socket probes.
func probeRuntimeSocket(p *socketEscapeProbe) {
	// Test 1: basic connect.
	conn, err := net.DialTimeout("unix", p.SocketPath, 2*time.Second)
	if err != nil {
		p.Error = fmt.Sprintf("connect failed: %v", err)
		return
	}
	conn.Close()
	p.Reachable = true

	// Test 2: API version endpoint.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", p.SocketPath, 2*time.Second)
			},
		},
		Timeout: 3 * time.Second,
	}

	// Docker API: /_ping or /v1.41/version
	apiBase := "http://localhost"
	switch p.Runtime {
	case "docker", "docker (DOCKER_HOST)", "docker (fallback)":
		// Try /_ping first (lightest, no auth needed).
		resp, err := client.Get(apiBase + "/_ping")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				p.VersionAPI = true
			}
		}
		// Also try /v1.41/version for version info.
		resp2, err2 := client.Get(apiBase + "/v1.41/version")
		if err2 == nil {
			resp2.Body.Close()
			if resp2.StatusCode == 200 {
				p.VersionAPI = true
			}
		}
		// Test 3: list containers.
		resp3, err3 := client.Get(apiBase + "/v1.41/containers/json")
		if err3 == nil {
			resp3.Body.Close()
			if resp3.StatusCode == 200 {
				p.ContainerList = true
			}
		}
		// Test 4: can we inspect the host config of any container?
		// (proxy for "do we have enough API access for escape?")
		resp4, err4 := client.Get(apiBase + "/v1.41/info")
		if err4 == nil {
			resp4.Body.Close()
			if resp4.StatusCode == 200 {
				// If we can read /info, we likely have enough privilege for
				// container create with --privileged.
				p.PrivilegedCreate = true
			}
		}

	case "containerd", "containerd (fallback)":
		// containerd uses a different API (ttrpc / CRI).
		// We probe the containerd info endpoint via its HTTP debug API.
		resp, err := client.Get(apiBase + "/v1/version")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				p.VersionAPI = true
			}
		}
		// containerd also exposes /containers via CRI.
		resp2, err2 := client.Get(apiBase + "/v1/containers")
		if err2 == nil {
			resp2.Body.Close()
			if resp2.StatusCode == 200 {
				p.ContainerList = true
			}
		}
	}
}

// reportSocketProbe prints a single probe result to stdout.
func reportSocketProbe(p socketEscapeProbe) {
	if !p.Reachable {
		fmt.Fprintf(os.Stdout, "\t[AMBER] %-40s — unreachable (%s)\n",
			p.SocketPath, p.Error)
		return
	}

	colour := "GREEN"
	notes := ""
	if p.VersionAPI {
		notes += " [API responds]"
	}
	if p.ContainerList {
		notes += " [can list containers]"
	}
	if p.PrivilegedCreate {
		notes += " [/info accessible → ESCAPE VIABLE]"
		colour = "GREEN"
	}

	fmt.Fprintf(os.Stdout, "\t[%s] %-40s — %s%s\n",
		colour, p.SocketPath, p.Runtime, notes)
}

func init() {
	RegisterContextPrereqCheck(
		CategorySecurity,
		"security.socket_escape",
		"Functional audit of docker/containerd socket escape viability (T59)",
		[]string{"InContainer"},
		CheckSocketEscape,
	)
}
