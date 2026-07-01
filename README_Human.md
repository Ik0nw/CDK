# README_Human - Container Defense Kit (CDK)

> This file is for human readers.
> AI agents and automation systems should use [README.md](./README.md).

CDK (Container Defense Kit) is a command-line tool for auditing container and Kubernetes isolation posture. It collects environment signals, checks security boundaries, and reports findings that help operators understand container runtime, kernel, Kubernetes, credential, and network exposure.

## What CDK is for

- Container and Kubernetes isolation baseline auditing
- Runtime and kernel hardening visibility
- Capability, LSM, seccomp, user namespace, and cgroup inspection
- ServiceAccount, metadata, and credential exposure review
- Single-check audit execution when targeted validation is needed

## Quick start

Build a Linux amd64 binary:

```bash
make build
install -m 0755 ./dist/baseline-audit-linux-amd64 ./cdk
```

Run the default evaluation:

```bash
./cdk evaluate
```

Save a JSON report:

```bash
./cdk evaluate --json > cdk-report.json
```

Run extended information gathering:

```bash
./cdk evaluate --full --json > cdk-report-full.json
```

## Build targets

| Target | Command |
|---|---|
| Default Linux amd64 | `make build` |
| Current platform | `go build -trimpath -ldflags="-s -w" -o baseline-audit ./cmd/cdk` |
| Linux amd64 | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o baseline-audit-linux-amd64 ./cmd/cdk` |
| Linux arm64 | `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o baseline-audit-linux-arm64 ./cmd/cdk` |

## Core commands

| Command | Meaning |
|---|---|
| `./cdk evaluate` | Run the default isolation baseline evaluation |
| `./cdk eva` | Alias of `evaluate` |
| `./cdk evaluate --json` | Emit one structured JSON report to stdout |
| `./cdk evaluate --full` | Enable extended information gathering |
| `./cdk evaluate --no-gating` | Disable preflight prerequisite gating |
| `./cdk run --list` | List available single audit checks |
| `./cdk run <check> [<args>...]` | Run one audit check |
| `./cdk -h` | Show CLI help |

## Reading JSON output

`--json` writes a single JSON object to stdout. Redirect stdout to save a report:

```bash
./cdk evaluate --json > cdk-report.json
```

Runtime logs are written to `CDK_AUDIT_OUTPUT_DIR/cdk-audit-<timestamp>.log`. If `CDK_AUDIT_OUTPUT_DIR` is unset, CDK uses the current directory.

Important top-level fields:

| Field | Meaning |
|---|---|
| `profile` | Which evaluation profile ran |
| `env` | Detected environment context |
| `categories` | Grouped check results |
| `ran` | Number of checks that executed |
| `skipped` | Number of checks skipped by gating |
| `summary` | Counts of missing prerequisites |

Each check either contains `ran` with captured output or `skipped` with missing prerequisites.

## Built-in helper tools

CDK also exposes helper commands such as `ps`, `netstat`, `ifconfig`, `nc`, `kcurl`, `ectl`, `ucurl`, `probe`, and `ed`. Use `./cdk -h` for exact syntax.

## Safety

Use CDK only in environments where you have authorization. Reports can include sensitive environment details such as file paths, network topology, kernel parameters, service metadata, and credential exposure hints. Store and transmit reports accordingly.
