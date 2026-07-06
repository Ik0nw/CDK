# Container Defense Kit (CDK)

> **CDK** — Container & Kubernetes Isolation Posture Assessment Tool
>
> Automated security baseline auditing for containerized environments.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/cdk-team/CDK)](https://goreportcard.com/report/github.com/cdk-team/CDK)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()

---

## Overview

CDK (Container Defense Kit) is a command-line security auditing tool designed to evaluate the isolation posture of containerized environments. It performs comprehensive, non-intrusive assessments of container runtime security, kernel hardening configurations, Kubernetes cluster security controls, and network isolation boundaries.

Built for security engineers, DevOps teams, and compliance auditors, CDK provides actionable insights into container security gaps and helps validate that isolation controls are properly configured and effective.

**AI agents and automation systems:** See the [AI Agent Manual](./README.md) for structured execution guidance.

---

## Key Capabilities

### 🔒 Kernel Hardening Assessment
Evaluates kernel security parameters including:
- Kernel Page Table Isolation (KPTI/PTI)
- Supervisor Mode Execution/Access Prevention (SMEP/SMAP)
- Kernel Address Space Layout Randomization (KASLR)
- GCC stack protector (regular/strong)
- Hardened usercopy
- Read-only kernel text and rodata
- Freelist hardening and randomization
- Page poisoning
- Refcount hardening
- FORTIFY_SOURCE
- I/O port access restrictions (devmem, IOMMU)

### 📦 Container Isolation Verification
Inspects container security boundaries:
- Linux Security Modules (AppArmor, SELinux, Landlock)
- Seccomp profile enforcement and coverage
- Linux capabilities audit (granted vs. dropped)
- User namespace restrictions
- No-new-privileges flag
- Root filesystem read-only status
- Privileged mode detection

### 🎛️ Cgroup Security Review
Analyzes cgroup configuration for security:
- Cgroup v1/v2 detection
- Device access control (devices.deny/allow)
- Release agent configuration (cgroup v1 escape vector)
- Subsystem availability and mount options

### 🌐 Network Security Analysis
Examines network isolation controls:
- Network namespace isolation
- iptables ruleset review
- DNS configuration exposure
- Host network mode detection
- Port exposure mapping

### ☸️ Kubernetes Security Posture
Assesses Kubernetes cluster security:
- ServiceAccount token exposure and permissions
- Pod Security Policy (PSP) / Pod Security Admission (PSA)
- RBAC configuration review
- Secret access validation
- ConfigMap data exposure
- CronJob security context

### ☁️ Cloud Metadata Protection
Tests cloud provider metadata service isolation:
- AWS IMDSv1/v2 reachability
- GCP metadata server access
- Azure instance metadata service (IMDS)
- Prevents SSRF-based credential theft vectors

### 🔑 Credential Exposure Scanning
Detects sensitive material in container environments:
- SSH private keys
- API tokens and secrets
- Environment variable leaks
- Kubernetes config files
- Cloud provider credentials
- .env files

### 🐚 Runtime Fingerprinting
Identifies container runtime characteristics:
- Docker, containerd, CRI-O detection
- Runtime version and configuration
- Container ID extraction
- Mount namespace analysis

---

## Quick Start

### Prerequisites

- Go 1.16 or newer
- Linux target environment (container, host, or Kubernetes pod)
- Appropriate authorization to perform security testing

### Build

```bash
# Clone the repository
git clone https://github.com/cdk-team/CDK.git
cd CDK

# Build for Linux amd64
make build

# Binary output: dist/baseline-audit-linux-amd64
```

### Download Pre-built Binaries

Pre-built binaries for all platforms are available on the [GitHub Releases](https://github.com/Ik0nw/CDK/releases) page.

```bash
# Linux x86_64 (containers, VMs, bare-metal)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-linux-amd64 -o cdk
chmod +x cdk

# Linux ARM64 (AWS Graviton, Raspberry Pi, Apple Silicon VMs)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-linux-arm64 -o cdk
chmod +x cdk

# macOS (Intel / Apple Silicon — for local testing)
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/cdk-darwin-arm64 -o cdk
chmod +x cdk
```

Verify SHA256 checksums:

```bash
curl -L https://github.com/Ik0nw/CDK/releases/latest/download/checksums.txt -o checksums.txt
shasum -a 256 -c checksums.txt
```

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `cdk-linux-amd64` |
| Linux ARM64 | `cdk-linux-arm64` |
| Linux i386 | `cdk-linux-386` |
| macOS Intel | `cdk-darwin-amd64` |
| macOS Apple Silicon | `cdk-darwin-arm64` |

### Deploy

```bash
# Install locally
install -m 0755 ./dist/baseline-audit-linux-amd64 /usr/local/bin/cdk

# Or copy into a container
docker cp ./dist/baseline-audit-linux-amd64 <container>:/tmp/cdk
docker exec <container> chmod +x /tmp/cdk
```

### Run

```bash
# Run full security assessment
./cdk evaluate

# Save structured JSON report
./cdk evaluate --json > cdk-security-report.json

# Run extended deep inspection
./cdk evaluate --full --json > cdk-deep-report.json
```

---

## Command Reference

### Core Assessment

| Command | Description |
|---|---|
| `cdk evaluate` | Run full isolation baseline assessment |
| `cdk eva` | Short alias for `evaluate` |
| `cdk evaluate --json` | Output structured JSON report |
| `cdk evaluate --full` | Enable extended information gathering |
| `cdk evaluate --no-gating` | Run all checks regardless of environment detection |
| `cdk evaluate --stealth` | Minimize forensic footprint during assessment |

### Targeted Checks

| Command | Description |
|---|---|
| `cdk run --list` | List all available audit checks |
| `cdk run <check> [args...]` | Execute a specific security check |

### Utility Tools

| Command | Purpose |
|---|---|
| `cdk ps` | Process enumeration and analysis |
| `cdk netstat` | Network connection listing |
| `cdk ifconfig` | Network interface details |
| `cdk nc` | TCP connectivity testing utility |
| `cdk kcurl` | Kubernetes API Server query tool |
| `cdk ectl` | etcd key-value store inspector |
| `cdk ucurl` | Docker Unix socket API client |
| `cdk probe` | TCP service availability scanner |
| `cdk ed` | Secure file editor for container environments |

---

## Understanding Output

### Human-Readable Format

Running `cdk evaluate` produces color-coded, categorized output showing:

```
🔒 Kernel Hardening
  ✅ KASLR: Enabled
  ✅ SMEP: Supported and active
  ⚠️ SMAP: Not detected
  ✅ Stack Protector: Strong mode

📦 Container Isolation
  ✅ AppArmor: Enforcing
  ✅ Seccomp: Filtering active
  ⚠️ Capabilities: SYS_ADMIN present
  ...
```

### JSON Report Format

The `--json` flag produces a machine-readable report suitable for SIEM integration, compliance tracking, and automated analysis:

```json
{
  "version": "2.0",
  "tool": "cdk",
  "timestamp": "2026-07-02T10:30:00Z",
  "profile": {
    "name": "default",
    "description": "Full isolation baseline assessment"
  },
  "env": {
    "in_container": true,
    "container_id": "abc123...",
    "runtime": "containerd",
    "kernel_version": "5.15.0"
  },
  "categories": [
    {
      "name": "kernel",
      "checks": [
        {
          "id": "kernel.kaslr",
          "name": "Kernel ASLR",
          "ran": {
            "output": "KASLR: enabled\n",
            "error": null
          }
        }
      ]
    }
  ],
  "ran": 45,
  "skipped": 12,
  "summary": {
    "missing_prereqs": {
      "NotInContainer": 8,
      "MissingCapability": 4
    }
  }
}
```

---

## Architecture

CDK is designed as a modular, extensible security auditing framework:

```
┌─────────────────────────────────────────────────┐
│                  CDK CLI                        │
│  (evaluate / run / tool commands)               │
├─────────────────────────────────────────────────┤
│              Preflight Gating                   │
│  (environment detection → check applicability)  │
├─────────────────────────────────────────────────┤
│            Check Engine                         │
│  (parallel execution, result aggregation)       │
├─────────────────────────────────────────────────┤
│          Security Check Modules                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Kernel   │ │ Container│ │ Kubernetes   │   │
│  │ Hardening│ │Isolation │ │ Security     │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Network  │ │  Cgroup  │ │  Credential  │   │
│  │  Analysis│ │ Security │ │   Exposure   │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
├─────────────────────────────────────────────────┤
│           Output Formatters                     │
│  (human-readable / JSON / structured logs)      │
└─────────────────────────────────────────────────┘
```

### Design Principles

1. **Non-Intrusive**: Read-only assessment by default; no system modifications
2. **Environment-Aware**: Preflight gating ensures checks only run in applicable environments
3. **Stealth-Capable**: Optional stealth mode minimizes forensic artifacts
4. **Modular**: Each security check is independently registered and versioned
5. **Portable**: Single static binary, no runtime dependencies, cross-architecture support

---

## Compliance Support

CDK assessment results help validate alignment with:

| Framework | Focus Area |
|---|---|
| **CIS Kubernetes Benchmark v1.8** | Worker node security, pod security, network policies |
| **CIS Docker Benchmark v1.6** | Host configuration, daemon security, runtime settings |
| **NIST SP 800-190** | Container image security, orchestration security, runtime security |
| **NIST SP 800-53 Rev. 5** | AC-3 (Access Enforcement), SC-7 (Boundary Protection) |
| **PCI-DSS v4.0** | Requirement 2.2 (Secure Configuration Standards) |
| **SOC 2 Type II** | CC6.1 (Logical Access Security) |

---

## Integration

### CI/CD Pipeline

CDK integrates seamlessly into automated security pipelines:

- **GitLab CI**: Run as a security stage job, archive JSON reports
- **GitHub Actions**: Use as a step in security workflows, upload as artifact
- **Jenkins**: Execute in pipeline stages, archive for compliance tracking
- **Argo CD / Tekton**: Include as a pre-deployment security gate

### SIEM Integration

JSON reports can be ingested by:
- Splunk (via HTTP Event Collector)
- Elasticsearch (via Filebeat or Logstash)
- Datadog Security Monitoring
- AWS Security Hub (via custom findings import)

### Ticketing / Workflow

Map findings to:
- Jira tickets for remediation tracking
- ServiceNow change requests
- Slack/Teams notifications for critical findings

---

## Comparison with Similar Tools

| Feature | CDK | kube-bench | docker-bench | lynis |
|---|---|---|---|---|
| Kernel hardening audit | ✅ | ❌ | ❌ | ✅ |
| Container isolation checks | ✅ | ✅ | ✅ | ✅ |
| Cgroup security analysis | ✅ | ❌ | ❌ | ❌ |
| eBPF security assessment | ✅ | ❌ | ❌ | ❌ |
| Landlock LSM detection | ✅ | ❌ | ❌ | ❌ |
| Kubernetes SA token audit | ✅ | ✅ | ❌ | ❌ |
| Cloud metadata testing | ✅ | ❌ | ❌ | ❌ |
| Runtime fingerprinting | ✅ | ❌ | ✅ | ❌ |
| Stealth mode | ✅ | ❌ | ❌ | ❌ |
| Single static binary | ✅ | ✅ | ❌ (shell) | ✅ |
| JSON output | ✅ | ✅ | ❌ | ✅ |

---

## Frequently Asked Questions

**Q: Is CDK safe to run in production?**
A: Yes. CDK performs read-only inspection by default. No system modifications are made during standard `evaluate` execution. The `--stealth` flag further minimizes operational impact.

**Q: What permissions does CDK need?**
A: Most checks work with standard user permissions. Some kernel parameter reads and capability inspections require elevated privileges for full coverage. CDK's preflight gating automatically skips checks that require unavailable permissions.

**Q: How long does an assessment take?**
A: A typical full evaluation completes in 5-30 seconds, depending on system resources and number of applicable checks.

**Q: Can CDK detect container escape vulnerabilities?**
A: CDK assesses the security controls that prevent container escapes — capabilities, seccomp, AppArmor, user namespace restrictions, cgroup configuration, and writable host paths. It identifies configurations that would make escape feasible, rather than actively exploiting them.

**Q: Does CDK support air-gapped environments?**
A: Yes. CDK is a fully self-contained static binary with no network dependencies for its core assessment functionality.

---

## Contributing

We welcome contributions from the security community:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-check`)
3. Make your changes following existing code patterns
4. Ensure builds pass for all target architectures
5. Submit a Pull Request with a clear description of the security check or improvement

### Adding a New Security Check

Security checks are registered via the plugin system. See `pkg/evaluate/` for examples of the check registration pattern:

```go
func init() {
    RegisterSimplePrereqCheck(CategoryKernel, "my.new.check",
        "Description of what this check validates",
        []string{"InContainer"}, myCheckFunction)
}
```

---

## License

CDK is released under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

---

## Responsible Use

**CDK is for authorized security testing only.**

- Only run CDK in environments where you hold explicit written authorization
- Treat assessment reports as confidential security data
- Report discovered vulnerabilities to the appropriate system owners
- Do not use CDK for unauthorized access or malicious purposes

The CDK project assumes no liability for misuse of this tool. Security practitioners are expected to operate within legal and ethical boundaries.

---

## Support & Community

- **Issues**: Report bugs and feature requests via [GitHub Issues](https://github.com/cdk-team/CDK/issues)
- **Security Reports**: Email security-related concerns to the project maintainers
- **Documentation**: Additional guides in [`docs/`](./docs/)
