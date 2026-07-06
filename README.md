# CDK - AI Agent & Automation Manual

> This document is optimized for AI agents, CI/CD pipelines, and automated security scanning systems.
> Human operators should refer to [README_Human.md](./README_Human.md).

CDK (Container Defense Kit) is a Go-based command-line tool for container and Kubernetes isolation posture auditing. It performs non-intrusive security baseline assessments of container runtime environments, kernel hardening configurations, Kubernetes cluster security, and network isolation boundaries.

This tool is designed for use in automated security compliance pipelines, red team engagements, and continuous security monitoring workflows.

---

## Agent Execution Protocol

1. Operate from the repository root directory.
2. Confirm CLI entrypoint: `./cmd/cdk`
3. Select target `GOOS` and `GOARCH` (primary target: `linux/amd64`)
4. Build single-file static binary
5. Deploy binary to target environment (host, container, or Kubernetes pod)
6. Execute `cdk evaluate` with appropriate flags
7. Capture structured output via `--json` flag and shell redirection

---

## Technical Specifications

| Attribute | Value |
|---|---|
| Language | Go 1.16+ |
| Module Path | `github.com/cdk-team/CDK` |
| CLI Entrypoint | `./cmd/cdk` |
| Build Output | `dist/baseline-audit-<os>-<arch>` |
| Primary Targets | Linux containers, Linux hosts, Kubernetes Pods |
| Supported Architectures | `amd64`, `arm64`, `386`, `arm` |
| Binary Type | Statically linked, CGO disabled |
| Build Flags | `-trimpath -ldflags="-s -w"` |

---

## Build Instructions

Download dependencies:

```bash
go mod download
```

### Standard Builds

Release build for Linux amd64 (recommended):

```bash
make build
```

Produces: `dist/baseline-audit-linux-amd64`

Manual build for current platform:

```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit ./cmd/cdk
```

### Cross-Compilation

Linux amd64:
```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit-linux-amd64 ./cmd/cdk
```

Linux arm64:
```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit-linux-arm64 ./cmd/cdk
```

Additional architectures:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -trimpath -ldflags="-s -w" -o ./dist/baseline-audit-linux-386 ./cmd/cdk
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -trimpath -ldflags="-s -w" -o ./dist/baseline-audit-linux-arm ./cmd/cdk
```

### Download Pre-built Binaries

Pre-built binaries are available from the [GitHub Releases](https://github.com/Ik0nw/CDK/releases) page.

```bash
# Linux x86_64 (most common — containers, VMs)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-linux-amd64 -o cdk
chmod +x cdk

# Linux ARM64 (Graviton, Raspberry Pi, Apple Silicon VMs)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-linux-arm64 -o cdk
chmod +x cdk

# Linux i386 (legacy 32-bit)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-linux-386 -o cdk
chmod +x cdk

# macOS Intel
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-darwin-amd64 -o cdk
chmod +x cdk

# macOS Apple Silicon
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-darwin-arm64 -o cdk
chmod +x cdk
```

Verify integrity with SHA256 checksums:

```bash
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/checksums.txt -o checksums.txt
shasum -a 256 -c checksums.txt
```

| Platform | Binary | Size |
|----------|--------|------|
| Linux x86_64 | `cdk-linux-amd64` | ~12 MB |
| Linux ARM64 | `cdk-linux-arm64` | ~11 MB |
| Linux i386 | `cdk-linux-386` | ~12 MB |
| macOS Intel | `cdk-darwin-amd64` | ~12 MB |
| macOS Apple Silicon | `cdk-darwin-arm64` | ~11 MB |

---

## Deployment

### Local Installation

```bash
install -m 0755 ./dist/baseline-audit-linux-amd64 /usr/local/bin/cdk
```

### Remote Host Deployment

```bash
scp ./dist/baseline-audit-linux-amd64 <user>@<host>:/tmp/cdk
ssh <user>@<host> 'chmod +x /tmp/cdk'
```

### Kubernetes Pod Deployment

```bash
kubectl cp ./dist/baseline-audit-linux-amd64 <namespace>/<pod>:/tmp/cdk
kubectl exec -n <namespace> <pod> -- chmod +x /tmp/cdk
```

### Container Deployment

```bash
docker cp ./dist/baseline-audit-linux-amd64 <container_id>:/tmp/cdk
docker exec <container_id> chmod +x /tmp/cdk
```

---

## Command Reference

### Core Assessment Commands

| Command | Description |
|---|---|
| `./cdk evaluate` | Run full isolation baseline assessment |
| `./cdk eva` | Alias for `evaluate` |
| `./cdk evaluate --json` | Emit structured JSON report to stdout |
| `./cdk evaluate --full` | Enable extended information gathering |
| `./cdk evaluate --no-gating` | Disable preflight prerequisite gating (run all checks) |
| `./cdk evaluate --stealth` | Enable stealth mode (minimize forensic footprint) |

### Single Check Execution

| Command | Description |
|---|---|
| `./cdk run --list` | List all available audit checks |
| `./cdk run <check> [<args>...]` | Execute a specific audit check |

### Helper Utilities

| Command | Purpose |
|---|---|
| `./cdk ps` | Process enumeration |
| `./cdk netstat` | Network connection analysis |
| `./cdk ifconfig` | Network interface inspection |
| `./cdk nc [options]` | TCP connectivity testing |
| `./cdk kcurl <path> (get\|post) <uri> [<data>]` | Kubernetes API Server interaction |
| `./cdk ectl <endpoint> get <key>` | etcd key-value store inspection |
| `./cdk ucurl (get\|post) <socket> <uri> <data>` | Docker Unix socket API interaction |
| `./cdk probe <ip> <port> <parallel> <timeout-ms>` | TCP service availability probing |
| `./cdk ed <file>` | Container file editor |

### Global Options

```bash
./cdk -h    # Show complete CLI help
```

---

## Execution Modes

### Standard Assessment

```bash
export CDK_AUDIT_OUTPUT_DIR="${CDK_AUDIT_OUTPUT_DIR:-.}"
./cdk evaluate
```

### Structured Output (for SIEM/automation)

```bash
./cdk evaluate --json > cdk-report.json
```

### Extended Assessment (deep inspection)

```bash
./cdk evaluate --full --json > cdk-report-full.json
```

### Complete Coverage (ignore environment gating)

```bash
./cdk evaluate --no-gating --json > cdk-report-no-gating.json
```

### Stealth Assessment (minimize detection footprint)

```bash
./cdk evaluate --stealth --json > cdk-report-stealth.json
```

---

## Output Format

### JSON Report Structure

`--json` produces a single JSON object written to stdout. Runtime logs are also written to `CDK_AUDIT_OUTPUT_DIR/cdk-audit-<timestamp>.log` (defaults to current directory).

**Top-Level Fields:**

| Field | Type | Description |
|---|---|---|
| `version` | string | JSON schema version |
| `tool` | string | Tool identifier (fixed: `cdk`) |
| `timestamp` | string | Assessment execution timestamp |
| `profile` | object | Executed assessment profile metadata |
| `env` | object | Preflight environment detection results |
| `categories` | array | Categorized check results |
| `ran` | integer | Number of checks executed |
| `skipped` | integer | Number of checks skipped by gating |
| `summary` | object | Skip reason aggregate counts |

**Check Result States:**

| State | Fields | Meaning |
|---|---|---|
| Executed | `ran.output`, `ran.error` | Check ran successfully or with error |
| Skipped | `skipped.missing_prereqs` | Check skipped due to environment prerequisites |

---

## Assessment Coverage Categories

CDK evaluates security posture across the following domains:

| Category | Description |
|---|---|
| **Kernel Hardening** | sysctl settings, KASLR, SMEP/SMAP, stack protector, usercopy hardening |
| **Container Isolation** | AppArmor, SELinux, seccomp profiles, capabilities, user namespace restrictions |
| **Cgroup Security** | cgroup v1/v2 configuration, device access restrictions, release_agent |
| **Filesystem** | Mount options, overlayfs restrictions, writable host paths |
| **Network** | Network namespace isolation, iptables, DNS configuration |
| **Kubernetes** | ServiceAccount tokens, PSP/PSA, RBAC exposure, secret access |
| **Cloud Metadata** | AWS/GCP/Azure metadata service reachability |
| **Credential Exposure** | SSH keys, API tokens, .env files, kubeconfig files |
| **Process Security** | ptrace scope, no_new_privs, seccomp enforcement |
| **eBPF** | Unprivileged BPF access, JIT hardening |
| **Landlock** | Landlock LSM enforcement status |
| **Runtime Detection** | Container runtime fingerprinting (Docker, containerd, CRI-O) |

---

## CI/CD Integration

### GitLab CI Example

```yaml
cdk_audit:
  stage: security
  image: golang:1.21
  script:
    - go mod download
    - CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk
    - ./cdk evaluate --json > cdk-report.json
  artifacts:
    paths:
      - cdk-report.json
    when: always
```

### GitHub Actions Example

```yaml
- name: CDK Container Security Audit
  run: |
    go mod download
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk
    ./cdk evaluate --json > cdk-report.json
- name: Upload CDK Report
  uses: actions/upload-artifact@v3
  with:
    name: cdk-security-report
    path: cdk-report.json
```

### Jenkins Pipeline Example

```groovy
stage('CDK Security Assessment') {
    steps {
        sh '''
            go mod download
            CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk
            ./cdk evaluate --json > cdk-report.json
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: 'cdk-report.json'
        }
    }
}
```

---

## Compliance Alignment

CDK assessment results support compliance validation against:

| Framework | Relevant Controls |
|---|---|
| **CIS Kubernetes Benchmark** | Control plane node config, worker node security, policies |
| **CIS Docker Benchmark** | Host configuration, daemon configuration, container runtime |
| **NIST SP 800-190** | Application container security guide |
| **NIST SP 800-53** | AC (Access Control), SC (System and Communications Protection) |
| **PCI-DSS v4.0** | Requirement 2 (Secure Configuration), Requirement 6 (Secure Systems) |
| **SOC 2** | CC6 (Logical and Physical Access Security) |

---

## Operating Boundary & Responsible Use

CDK is designed exclusively for authorized security assessments. It performs read-only inspection of:

- Container runtime configuration
- Kernel security parameters
- Kubernetes cluster configuration
- Network topology and firewall rules
- Filesystem mount properties
- Credential file permissions

**Output data classification:** Reports may contain sensitive environment details including file paths, network topology, kernel parameters, service metadata, and credential exposure indicators. Treat reports as CONFIDENTIAL security assessment data.

**Authorization requirement:** Only execute CDK in environments where you hold explicit written authorization to perform security testing.

---

## Related Projects

| Tool | Focus |
|---|---|
| [kube-bench](https://github.com/aquasecurity/kube-bench) | CIS Kubernetes Benchmark automated checking |
| [docker-bench-security](https://github.com/docker/docker-bench-security) | CIS Docker Benchmark automated checking |
| [lynis](https://github.com/CISOfy/lynis) | Linux system security auditing |
| [trivy](https://github.com/aquasecurity/trivy) | Container image vulnerability scanning |
| CDK (this tool) | Container isolation boundary & kernel hardening baseline |
