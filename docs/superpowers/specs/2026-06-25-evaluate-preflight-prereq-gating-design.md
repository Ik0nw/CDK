---
name: evaluate-preflight-prereq-gating
description: Design spec for adding preflight environment detection and hard prereq gating to the CDK evaluate (recon) path, so that noisy checks (cloud metadata HTTP, K8s API anonymous login, DNS SRV, cgroup probes) are skipped unless preconditions are met via local-only detection.
metadata:
  type: spec
  created: 2026-06-25
  author: Chen xing
  scope: pkg/evaluate, pkg/cli, ~12 check registration call sites
---

# Design: Preflight Detection & Prereq Gating for CDK Evaluate

## 1. Problem & motivation

The current `cdk evaluate` / `cdk eva` command runs every check in its profile **unconditionally** via
`pkg/evaluate/engine.go:56-64` (`Category.run`).  There are zero preconditions.  This means on a bare-metal
or non-container host, or inside a container that lacks Docker/K8s plumbing, CDK will still emit:

- HTTP GETs to **every** cloud metadata endpoint (169.254.169.254, etc.) via `cloud.metadata_api`
- Anonymous `/` and `/api/v1/namespaces` requests to the K8s API server default URL via `k8s.anonymous_login`
- SRV DNS queries for `*.svc.cluster.local.` via `dns.service_discovery`
- Process enumeration, sensitive-file scanning, kernel exploit-suggester bash-spawning outside a container context
- `/proc/1/cgroup` reads + cgroup filesystem touches on non-container hosts

All of these are "loud" and flag-prone in front of HIDS / EDR / honeypots / audit watches.

The user's goal is: **only probe a surface when local, cheap evidence already shows that surface exists**.
Do NOT probe Docker/cgroup/K8s/cloud blindly.

## 2. Non-goals / scope

- Exploit-path (`cdk run <exploit>`) gating is **out of scope** for this spec.  Only the evaluate/recon path
  (`cdk eva`, `cdk eva --full`, `cdk evaluate --profile=*`) is hardened.
- The deprecated `auto-escape` task is **not modified**.
- No build-tag or binary-size changes.
- No network calls of any kind are added by preflight detection — preflight must be 100% local.
- "Stealth" as a concept is not implemented beyond prereq gating; no path obfuscators, no filename
  randomization, no timing jitter.  (Those are separate future pieces.)

## 3. Decisions / trade-offs

| # | Decision | Rationale / trade-off |
|---|---|---|
| 1 | **Hard gating, not soft** — prereq not met ⇒ check skipped completely, no partial execution, no shortened timeouts. | User chose option A.  Avoids any side-effect at the cost of potential under-reporting when preflight mis-detects.  Mitigated by `--no-gating` escape hatch (see §6.4). |
| 2 | **Centralised preflight + Context caching** — detect once at `Evaluator.RunProfile` entry, store in `Context.Env`. | Zero redundant `os.Stat()`s; naturally fits the existing `Context` pattern.  Detection code lives in exactly one place, easy to audit. |
| 3 | **Prereqs declared per-check** via a new `Check.Prereqs []string` field, evaluated uniformly in `Category.run()`. | Incremental: existing checks that don't declare prereqs keep running.  Authors of new checks only need to list flag names, not re-implement detection. |
| 4 | `InCloud` is **conservative and vendor-explicit**: only set `true` when at least one specific cloud vendor is positively identified via DMI/cloud-init heuristics. | User explicitly asked not to blind-fire metadata HTTP.  False-negatives (undetected private cloud) are acceptable; user falls back to `--no-gating` or runs `cdk run <exploit>` manually. |
| 5 | Volcengine / BytePlus vendor heuristics are included in `InCloud`. | User requirement. |
| 6 | CLI `--no-gating` flag disables gating for a single run (forensic / debug mode). | Default is **safe**; opt-in loudness. |

## 4. Architecture

### 4.1. Layering

```
CLI (pkg/cli/parse.go)
  │
  │ profile=basic/extended/additional, noGating=bool
  ▼
Evaluator.RunProfile(id, ctx)        pkg/evaluate/engine.go
  │
  ├─ 1. ctx.Env := DetectEnv()        ─── pkg/evaluate/env.go (NEW)
  │      (local-only; 9 flags + CloudVendor; all failures ⇒ false)
  │
  ├─ 2. for category in profile:
  │      category.run(ctx)
  │        for check in category:
  │          ├─ if ctx.Env missing check.Prereqs: SKIP (log + record)
  │          └─ else: check.execute(ctx)   (unchanged behaviour)
  │
  └─ 3. printSkipSummary()             ─── new in engine.go
```

### 4.2. Data flow

1. `cli.ParseCDKMain` resolves `--profile`, `--full`, `--no-gating`.
2. `Evaluator.RunProfile` is called with a fresh `Context`; if `ctx == nil` it is built via `NewContext()`.
3. `DetectEnv()` runs once; result is cached in `ctx.Env`.  `ctx.NoGating` is set from CLI.
4. Each `Check` carries its `Prereqs []string` (e.g. `{"InContainer", "HasCgroupV1"}`).
5. In `Category.run`, `missing := MissingPrereqs(ctx.Env, check.Prereqs)` consults a name→field map
   once per check; non-empty missing ⇒ `ctx.Skipped = append(...)` and the check is not invoked.
6. After profile execution, a single summary line is emitted to stdout:
   `[✓] N checks ran, [⏭] M skipped (missing: InContainer×a, InCloud×b)`.
   With `--verbose` (future, or debug build) the full per-check skip reason is logged to stderr.

## 5. Preflight flag definitions (pkg/evaluate/env.go)

All detection is **local file read or syscall only**. No network. Any file-read error silently yields `false`.

| Flag | Detection (short-circuit, order matters) |
|---|---|
| `InContainer` | ① `/.dockerenv` exists.  ② `/run/.containerenv` exists.  ③ `/proc/1/cgroup` matches `docker\|containerd\|kubepods\|lxc\|systemd/docker\|cri-containerd\|podman`.  ④ `/proc/1/sched` first-line PID ≠ `1`.  ⇒ Any ⇒ true. |
| `HasDockerSock` | `os.Stat("/var/run/docker.sock")` succeeds AND mode is socket, OR `DOCKER_HOST` env begins with `unix://` and the parsed path exists as socket. |
| `HasContainerdSock` | Read `/proc/net/unix`, regex `@/containerd-shim/.*/.*/shim\.sock` (abstract socket) OR `/run/containerd/containerd.sock` stat succeeds as socket. |
| `HasK8sSA` | `os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")` succeeds AND file size > 0. |
| `InClusterDNS` | Parse `/etc/resolv.conf`.  Match `search` domain contains `svc.cluster.local` —OR— a `nameserver` falls in `10.96.0.0/12`. |
| `InCloud` | See §5.1 for vendor list.  ⇒ At least one vendor positively identified ⇒ true.  Never fires on cloud-init alone. |
| `HasCgroupV1` | `!FileExists("/sys/fs/cgroup/cgroup.controllers")` AND `/proc/self/cgroup` contains v1 hierarchies (lines with `devices:/`, `memory:/`, `cpu:/`). |
| `HasCgroupV2` | `FileExists("/sys/fs/cgroup/cgroup.controllers")`. |
| `Privileged` | Parse `/proc/self/status` `CapEff` line; equals `000003ffffffffff` (all 40 caps) ⇒ true.  Fallback: `Seccomp: 0`. |

Additional informational field `CloudVendor string` (one of: `aws`, `gcp`, `azure`, `aliyun`, `tencent`, `huawei`, `volcengine/byteplus`, `""`).

### 5.1. Cloud vendor heuristics (for `InCloud` + `CloudVendor`)

All fields read from `/sys/class/dmi/id/{product_name,sys_vendor,product_uuid,product_version,chassis_asset_tag,board_vendor}`, `/var/lib/cloud/data/instance-id`, `/var/lib/cloud/instance/datasource`, `/etc/cloud/cloud.cfg`, hostname.

| Vendor | Positive-match rules (any ⇒ vendor detected) |
|---|---|
| **volcengine / byteplus** | `sys_vendor` contains `Volcengine` OR `ByteDance`.  `product_name` contains `BytePlus` (case-insensitive) OR matches `ECS` AND hostname starts with `iv-` or `v-`.  `cloud-init datasource` contains substring `volc` or `byteplus`. |
| aliyun | `sys_vendor` contains `Alibaba Cloud` / `Aliyun`.  `chassis_asset_tag` starts with `alibaba-` / `aliyun-`. |
| aws | `product_uuid` lower-case starts with `ec2`.  `bios_vendor` == `Amazon EC2`.  cloud-init datasource == `DataSourceEc2`. |
| gcp | `product_name` == `Google Compute Engine`.  `bios_vendor` == `Google`. |
| azure | `chassis_asset_tag` == `7783-7084-3265-9085-8269-3286-77`.  `sys_vendor` == `Microsoft Corporation` AND `product_name` == `Virtual Machine`. |
| tencent | `sys_vendor` contains `Tencent`. |
| huawei | `sys_vendor` contains `Huawei`. |

Rules are combined: at least one vendor rule fires ⇒ `InCloud = true` and `CloudVendor = "<vendor>"`.
If two vendors match, first in table wins.  (Volcengine is checked before generic ECS aliases to avoid
false mapping to aliyun.)

### 5.2. Exported helpers

```go
type Env struct {
    InContainer, HasDockerSock, HasContainerdSock bool
    HasK8sSA, InClusterDNS, InCloud               bool
    HasCgroupV1, HasCgroupV2, Privileged          bool
    CloudVendor  string
    DetectedVia  map[string]string  // flag → human-readable detection note (for debug summary)
}

func DetectEnv() *Env
func MissingPrereqs(env *Env, prereqs []string) []string   // returns missing flag names
```

`MissingPrereqs` looks up prereq strings via a `var flagByName = map[string]func(*Env) bool{...}`
table defined in `env.go`.  Unknown prereq name ⇒ treated as "missing" (fail-closed: we never run
a check whose prereq we don't understand, to avoid silent gating failures).

## 6. Engine + registry changes (engine.go, registry.go)

### 6.1. Struct updates

```go
// engine.go — extended types
type Context struct {
    Logger   *log.Logger
    Env      *Env
    NoGating bool          // from CLI --no-gating; when true, MissingPrereqs is short-circuited
    Skipped  []SkipReason  // append-only; final summary reads this
}

type SkipReason struct {
    CheckID string
    Missing []string
}

type Check struct {
    ID          string
    Title       string
    Description string
    Run         CheckFunc
    Prereqs     []string   // NEW
}
```

### 6.2. Gating inside `Category.run`

```go
func (c Category) run(ctx *Context) {
    util.PrintH2(c.Title)
    logger := loggerFromContext(ctx)
    for _, check := range c.Checks {
        if !ctx.NoGating {
            missing := MissingPrereqs(ctx.Env, check.Prereqs)   // nil-env safe; missing = []
            if len(missing) > 0 {
                ctx.Skipped = append(ctx.Skipped, SkipReason{check.ID, missing})
                logger.Printf("skip %s: prereqs not met: %v", readableCheckLabel(check), missing)
                continue
            }
        }
        if err := check.execute(ctx); err != nil {
            logger.Printf("check %s failed: %v", readableCheckLabel(check), err)
        }
    }
}
```

`Evaluator.RunProfile`: before `profile.run(ctx)`, do `ctx.Env = DetectEnv()` (idempotent if already set
for tests).  After, call `printSkipSummary(ctx)` which writes a one-line stdout summary aggregating
`ctx.Skipped`.

### 6.3. New registration helpers (registry.go)

Backwards compatible: existing `RegisterSimpleCheck` and `RegisterContextCheck` calls keep working
(they produce `Check{Prereqs: nil}` which means "no gating, always run").

Two new helpers avoid touching every call site:

```go
func RegisterSimplePrereqCheck(category CategorySpec, id, title string, prereqs []string,
    fn func(), profiles ...string)
func RegisterContextPrereqCheck(category CategorySpec, id, title string, prereqs []string,
    fn CheckFunc, profiles ...string)
```

### 6.4. CLI flag `--no-gating`

`pkg/cli/banner.go` banner string is extended to add the option in the Options block:
```
  --no-gating   Disable preflight prereq gating (runs ALL checks, loud).
```

`pkg/cli/parse.go` reads `--no-gating` from docopt and, on the evaluate path, passes it through to the
`Context` (a new parameter on `NewContext`, or set directly after construction).  Behaviour: if
`--no-gating` is passed, `ctx.NoGating = true` and the prereq loop is skipped; every check in the
profile runs exactly as before the change.

## 7. Prereq assignments per check

Checks **not** listed here keep `Prereqs: nil` (no change, run unconditionally).

| Category file | Check ID | Prereqs |
|---|---|---|
| check_mount_escape.go | `mounts.escape` | `InContainer` |
| network_namespace.go | `network.namespace` | `InContainer` |
| sensitive_service.go | `services.sensitive_service` | `InContainer` |
| available_linux_commands.go | `commands.available` | `InContainer` |
| available_linux_capabilities.go | `commands.capabilities` | `InContainer` |
| service_discovery_dns.go.go | `dns.service_discovery` | `InContainer, InClusterDNS` |
| k8s_anonymous_login.go | `k8s.anonymous_login` | `InContainer, HasK8sSA` |
| k8s_service_account*.go | `discovery.k8s_sa:*` | `HasK8sSA` |
| cloud_metadata_api.go | `cloud.metadata_api` | `InCloud` |
| kernel.go | `kernel.exploits` | `InContainer` |
| (sensitive-files check) | `filesystem.sensitive` | `InContainer` |
| cgroups.go | `cgroups.dump` | `InContainer` |
| seccomp check ×2, namespace isolation, selinux, apparmor | security.* (5 checks) | `InContainer` |

Total of **~15 check registration sites** changed; ~10 local / non-loud checks left untouched.

## 8. Error handling & failure modes

| Condition | Behaviour |
|---|---|
| `DetectEnv()` file reads fail | Flag yields `false`.  Never panics.  Failure details logged to `DetectedVia` for debug output. |
| Unknown prereq name in `Prereqs` | `MissingPrereqs` returns it in the missing list ⇒ check is skipped, logger emits a `WARNING: unknown prereq "X"` line.  Fail-closed: never "guess" that an unknown prereq is satisfied. |
| CLI passes unknown profile | `RunProfile` returns the existing `fmt.Errorf("unknown profile %q")` — no change. |
| `Evaluator.RunProfile(ctx == nil)` | Existing `ctx = NewContext(nil)` branch; `ctx.Env` populated afterwards. |
| `--no-gating` with `--full` | Both flags compose: full profile + every check runs, same as pre-change behaviour. |
| Volcengine host with DMI vendor strings that we don't yet match | `InCloud = false`, metadata check skipped; user can `--no-gating`.  We add new rules incrementally per §9.3. |

## 9. Testing & rollout plan

### 9.1. Unit tests (new file `pkg/evaluate/env_test.go`)

Table-driven tests for `DetectEnv` using a helper that mocks filesystem reads (or, simpler, use a
`testdata/` directory with fake `procfs` / `sysfs` stubs, and override `env.go`'s file-reading helpers
via an unexported `fsOverrides` hook).  Cases:

1. Bare-metal: all markers absent ⇒ every flag `false`.
2. Docker Desktop Linux container: `InContainer=true, HasDockerSock=true, HasCgroupV2=true,
   Privileged=false`.
3. K8s pod with SA mounted: `InContainer=true, HasK8sSA=true, InClusterDNS=true`.
4. Volcengine ECS VM: `InCloud=true, CloudVendor="volcengine/byteplus"`.
5. AWS EC2: `InCloud=true, CloudVendor="aws"`.
6. cgroup v1 host: `HasCgroupV1=true, HasCgroupV2=false`.
7. Privileged container: `CapEff=000003ffffffffff` ⇒ `Privileged=true`.
8. K8s pod *without* SA token (automountServiceAccountToken=false): `HasK8sSA=false` ⇒
   `k8s.anonymous_login` should be skipped.

Unit test for `MissingPrereqs`: unknown prereq returns it missing; empty prereqs return empty; correct
flag lookups.

### 9.2. Integration / manual verification

Run against three known environments and confirm skip-summary output counts match expectation:

- (a) Bare Mac dev host (`go test` or cross-compiled linux binary via docker): ~14 checks ran (basic
  info), ~15 skipped.  **Zero** network requests to metadata / K8s / DNS SRV.
- (b) `docker run --rm -v $PWD:/cdk golang:1.22 bash -c 'cd /cdk && go run ./cmd/cdk eva'`:
  `InContainer=true`, `HasDockerSock=false` (socket not mounted), security + mount + kernel checks run,
  K8s/Cloud/DNS checks skipped.
- (c) (Optional) kind/minikube pod with the CDK binary: `InContainer, HasK8sSA, InClusterDNS` all
  true ⇒ DNS and K8s checks run; `InCloud` typically false ⇒ metadata skipped.

Network-level sanity check in env (a) and (b): wrap CDK in a netns/iptables that DROP any egress to
169.254.169.0/24 + K8s service subnet + log dropped packets.  Assert zero drops after `eva`.

### 9.3. Follow-up / future work (explicitly out of scope for v1)

- Tune Volcengine DMI rules against real hosts once we have a live `dmi/id` dump.
- Add timing jitter + random request ordering for the checks that *do* run (independent anti-recon piece).
- Port gating to the exploit plugin path (user opted out for v1).
- Add `--verbose-skip` to print per-check skip reasons (currently one-line summary only).

## 10. Files changed (§7.1's diff surface, repeated here for implementation-plan handoff)

| Operation | Path |
|---|---|
| CREATE | `pkg/evaluate/env.go` (~250 lines: types, DetectEnv, MissingPrereqs, DMI/cloud-init parsers, vendor rule table, flagByName lookup) |
| CREATE | `pkg/evaluate/env_test.go` (~300 lines: table-driven unit tests) |
| EDIT | `pkg/evaluate/engine.go` — Context/Check struct extensions, SkipReason, gating loop, skip summary |
| EDIT | `pkg/evaluate/registry.go` — two Register*Prereq* helpers |
| EDIT | `pkg/cli/banner.go` — `--no-gating` help line |
| EDIT | `pkg/cli/parse.go` — read docopt flag, thread `NoGating` into Context |
| EDIT × ~15 check files | swap `RegisterSimpleCheck` → `RegisterSimplePrereqCheck` with prereq list (see §7 table) |
