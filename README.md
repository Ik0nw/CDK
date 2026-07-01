# CDK - AI Agent Manual

> This README is written for AI agents and automation systems.
> Human readers should use [README_Human.md](./README_Human.md).

CDK (Container Defense Kit) is a Go-based CLI for container and Kubernetes isolation baseline auditing. Use this manual to build, install, execute, and collect results from the tool.

## Agent action order

1. Work from the repository root.
2. Confirm the CLI entrypoint is `./cmd/cdk`.
3. Select the target `GOOS` and `GOARCH`.
4. Build a single-file binary.
5. Install the binary locally or copy it into the target container / host.
6. Run `cdk evaluate` or a specific subcommand.
7. Capture stdout. Use `--json` plus shell redirection when structured output is required.

## Prerequisites

| Item | Requirement |
|---|---|
| Build language | Go 1.16 or newer |
| Module path | `github.com/cdk-team/CDK` |
| CLI entrypoint | `./cmd/cdk` |
| Primary targets | Linux containers, Linux hosts, Kubernetes Pods |
| Common target architectures | `amd64`, `arm64`, `386`, `arm` |

Download dependencies from the repository root when they are not cached:

```bash
go mod download
```

## Build

Recommended release build for Linux amd64:

```bash
make build
```

This writes `dist/baseline-audit-linux-amd64` by default. The Makefile uses `-trimpath -ldflags="-s -w"` and does not use UPX.

Build for the current platform manually:

```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit ./cmd/cdk
```

Build for Linux amd64:

```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit-linux-amd64 ./cmd/cdk
```

Build for Linux arm64:

```bash
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo local)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X github.com/cdk-team/CDK/pkg/cli.GitCommit=${GIT_COMMIT}" -o ./dist/baseline-audit-linux-arm64 ./cmd/cdk
```

Build for other Linux architectures by changing `GOARCH`:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -trimpath -ldflags="-s -w" -o ./dist/baseline-audit-linux-386 ./cmd/cdk
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -trimpath -ldflags="-s -w" -o ./dist/baseline-audit-linux-arm ./cmd/cdk
```

## Install

Install on the current machine:

```bash
install -m 0755 ./dist/baseline-audit-linux-amd64 /usr/local/bin/cdk
```

If `/usr/local/bin` is not writable, run the binary from its current path:

```bash
chmod +x ./dist/baseline-audit-linux-amd64
./dist/baseline-audit-linux-amd64 -h
```

Copy to a remote Linux host:

```bash
scp ./dist/baseline-audit-linux-amd64 <user>@<host>:/tmp/cdk
ssh <user>@<host> 'chmod +x /tmp/cdk'
```

Copy to a Kubernetes Pod:

```bash
kubectl cp ./dist/baseline-audit-linux-amd64 <namespace>/<pod>:/tmp/cdk
kubectl exec -n <namespace> <pod> -- chmod +x /tmp/cdk
```

## Execute

Run the default isolation baseline evaluation:

```bash
export CDK_AUDIT_OUTPUT_DIR="${CDK_AUDIT_OUTPUT_DIR:-.}"
./cdk evaluate
```

Use the alias:

```bash
./cdk eva
```

Emit structured JSON:

```bash
./cdk evaluate --json > cdk-report.json
```

Enable extended information gathering and emit JSON:

```bash
./cdk evaluate --full --json > cdk-report-full.json
```

Disable preflight prerequisite gating and attempt all evaluation checks:

```bash
./cdk evaluate --no-gating --json > cdk-report-no-gating.json
```

Use `--no-gating` only when a complete attempted coverage pass is required. It makes checks run even when the detected environment would normally skip them.

## Single audit checks

List available audit checks:

```bash
./cdk run --list
```

Run one audit check:

```bash
./cdk run <check> [<args>...]
```

`<check>` must come from `./cdk run --list`.

## Built-in tools

CDK includes helper tools. Agents should prefer `evaluate` by default and use these tools only when the task explicitly needs them.

| Command | Purpose |
|---|---|
| `./cdk ps` | Show process information |
| `./cdk netstat` | Show network connection information |
| `./cdk ifconfig` | Show network interface information |
| `./cdk nc [options]` | TCP connection tool |
| `./cdk kcurl <path> (get\|post) <uri> [<data>]` | Request the Kubernetes API Server |
| `./cdk ectl <endpoint> get <key>` | Read an etcd key |
| `./cdk ucurl (get\|post) <socket> <uri> <data>` | Request the Docker Unix socket |
| `./cdk probe <ip> <port> <parallel> <timeout-ms>` | TCP port probing |
| `./cdk ed <file>` | Edit a file inside the container |

Show full CLI help:

```bash
./cdk -h
```

## JSON output

`--json` writes one JSON object to stdout. Save it with shell redirection.
Runtime logs are also written to `CDK_AUDIT_OUTPUT_DIR/cdk-audit-<timestamp>.log`; if `CDK_AUDIT_OUTPUT_DIR` is unset, the current directory is used.

Top-level fields:

| Field | Meaning |
|---|---|
| `version` | JSON schema version |
| `tool` | Tool name, fixed as `cdk` |
| `timestamp` | Run start time |
| `profile` | Executed profile information |
| `env` | Preflight environment detection result |
| `categories` | Categorized check results |
| `ran` | Number of checks that executed |
| `skipped` | Number of checks skipped by preflight gating |
| `summary` | Skip reason counts |

Each `categories[].checks[]` item has one state:

| State field | Meaning |
|---|---|
| `ran.output` | Captured stdout / stderr from the check |
| `ran.error` | Error returned by the check |
| `skipped.missing_prereqs` | Missing preflight prerequisites |

## Command selection

| Goal | Command |
|---|---|
| Get a human-readable result quickly | `./cdk evaluate` |
| Get machine-readable output | `./cdk evaluate --json > cdk-report.json` |
| Gather extended information | `./cdk evaluate --full --json > cdk-report-full.json` |
| List single audit checks | `./cdk run --list` |
| Run a specific audit check | `./cdk run <check> [<args>...]` |
| Show help | `./cdk -h` |

## Operating boundary

Run CDK only in authorized containers, hosts, or Kubernetes environments. Output can contain environment summaries, file paths, network structure, kernel parameters, and service information. Treat saved reports as sensitive data.
