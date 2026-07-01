# Detection Expansion (T45-T57) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 扩展 CDK evaluate 检测面覆盖 2024-2026 大部分现代容器逃逸侦查面：prctl 多维状态 / seccomp advanced (NOTIF + action types) / Landlock ABI / eBPF unpriv / user-ns 深度限制 / io_uring / Volcengine 第一方信号 / AppArmor+SELinux profile 深度 / PTRACE scope / Kconfig hardening / Lockdown / kernel symbol leaks。共 13 个新检查项（T45–T57）。

**Architecture:** 每个新检查项是 `pkg/evaluate/` 下一个独立的 `_linux.go` 文件（可选 companion `_notlinux.go` stub），使用 `RegisterSimplePrereqCheck(CategoryX, "id", title, prereqs, func)` 注册。所有侦查操作必须严格 **side-effect-free + read-only + 空参数**；宁漏勿 flag （宁可 ambiguous / not-detected，也不要把 shared 误判为 isolated）。Env 新字段若在多个检查间共享则放入 `env.go` 作为 preflight flag，否则作为 check-local 输出。

**Tech Stack:** Go 1.16+ (interface{}, 不用 any) + syscall.RawSyscall6 (不用 libc 包装) + fatih/color (仅通过 swapped globals，直接写 capture) + ioutil.ReadFile + io/ioutil for readability。

**Cross-arch build:** 所有 syscall NR 按 `json_memfd_*_*.go` 模式，用 per-GOARCH 文件定义 const（若 syscall 包未在该 arch 暴露命名 const）。go vet 必须在 darwin host + linux/{amd64,arm64,386,arm} 全过。

---

## Global Constraints

1. **NO auto-escape — recon/enumerate ONLY.** 所有探针都必须是 side-effect-free：NULL 指针参数、负数 fd、全 1 flag (会失败的)，读取 /proc /sys 文件，RawSyscall 返回 errno。NEVER 真正执行 mount/unshare/setns/ptrace/init_module 等有状态变化的操作。（Binding security constraint #1）
2. **宁漏勿 flag (miss rather than false-positive).** 所有二选一判断都用三态 enum：ISOLATED=+1, AMBIGUOUS=0, SHARED=-1。AMIGUOUS 中间范围永远不输出确定性 verdict（除非 side-channel signal 数 ≥ threshold）。（Binding constraint #2）
3. **Volcengine/BytePlus 规则必须在通用 Aliyun-ECS 后备方案之前运行。** 参见 T57。（Binding constraint #3）
4. **未知 Check.Prereqs flag fail-closed。** 新增 flag 需同步在 `env.go` 的 `flagByName` map 中注册，否则 Prereqs 会 fail (带 "?")。（Binding constraint #4）
5. **Go 1.16 compat：** 全项目不得出现 `any` 关键字；使用 `interface{}`。
6. **JSON capture 兼容：** 所有 fmt.Fprintf 写入的 os-level 变量：`os.Stdout` (非缓存副本)，`color.Output` (会被 json.go swap)，`log.Printf` (也被 swap 到 captureBuf)。禁止包级 var = os.Stdout 模式（见 T39 fix），**永远用函数返回**。
7. **Cross-arch NR：** 每个使用 RawSyscall6 的 syscall，linux/{amd64,arm64,386,arm} 四架构构建必须全部 RC=0；darwin host vet RC=0 (用 _notlinux.go stub)。
8. **输出格式统一** — 每个检查的 log output 要像 seccomp_deep_inspect / namespace_isolation 那样：先一行 banner，然后每个 probe 以 `  \t[GREEN|AMBER|  ?  ] signal — 结论 (errno/text)` 风格，最后一行 tally。

---

## Files to Modify / Create

**Create new (13 check files + 4× per-arch stub dirs per syscall if needed):**

Group A: Primitives (pure syscall / file reads, no shared env):
- `pkg/evaluate/prctl_state_linux.go` + `prctl_state_notlinux.go` (T45)
- `pkg/evaluate/seccomp_advanced_linux.go` + per-arch NR stubs for seccomp(2) (T46)
- `pkg/evaluate/landlock_deep_linux.go` (T47) — use NR like json_memfd
- `pkg/evaluate/ebpf_recon_linux.go` + NR stubs for bpf(2) (T48)
- `pkg/evaluate/io_uring_probe_linux.go` + NR stubs (T49)
- `pkg/evaluate/userns_limits_linux.go` (T50)

Group B: Procfs / sysfs deep enumeration (file I/O only):
- `pkg/evaluate/apparmor_deep_linux.go` (T52)
- `pkg/evaluate/selinux_context_linux.go` (T53)
- `pkg/evaluate/kernel_lockdown_linux.go` (T54)
- `pkg/evaluate/kernel_hardening_linux.go` (T55) — combines Kconfig + symbol leaks + CPU bugs
- `pkg/evaluate/ptrace_scope_linux.go` (T56)

Group C: Runtime + cloud vendor detection (env flag + preflight):
- `pkg/evaluate/runtime_fingerprint_linux.go` (T51)
- `pkg/evaluate/env.go` + `pkg/evaluate/cloud_metadata_api.go` (T57: Volcengine 信号扩展)

**Modify existing:**
- `pkg/evaluate/available_linux_capabilities.go:init()` — highlight CAP_BPF/CAP_PERFMON/CAP_CHECKPOINT_RESTORE with separate banner (part of T48 optional bonus if code path touches)
- `pkg/evaluate/env.go:detectInCloud()` section: Volcengine rule order + 4 新 signal (T57)
- `pkg/evaluate/env.go:flagByName`: add new shared preflight flags (T45/T50 expose 3 new flags each)

---

### Task T45: Prctl 多维状态侦查 (prctl_state)

**Files:**
- Create: `pkg/evaluate/prctl_state_linux.go`, `pkg/evaluate/prctl_state_notlinux.go`
- Modify: `pkg/evaluate/env.go:flagByName` if you expose any new Env fields for shared checks

**Interfaces:**
- Produces: check id=`security.prctl_state` in `CategorySecurity`. Probes 6 prctl options (PR_GET_NO_NEW_PRIVS, PR_CAP_AMBIENT_IS_SET (test CAP_NET_RAW), PR_GET_DUMPABLE, PR_GET_KEEPCAPS, PR_GET_SECCOMP (redundant but cross-verifies), PR_GET_SPECULATION_CTRL). All side-effect-free GET operations.
- syscall NR: `syscall.SYS_PRCTL` should be exposed on all arches — but verify; if not, use per-arch consts (arm64=167, amd64=157, 386=172, arm(EABI)=172).

Registration (use init() like T39):
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.prctl_state",
    "Probe per-process prctl state (NoNewPrivs / Dumpable / KeepCaps / speculation_ctrl) [F6]",
    []string{"InContainer"},
    func() { ProbePrctlState() },
)
```

Expected output structure:
```
security.prctl_state — process security-relevant prctl probes (6 reads):
    [GREEN] no_new_privs        = 0  — execve MAY gain new privileges (exploit-friendly)
    [  ?  ] cap_ambient_has_raw = 0  — ambient caps not set (usual)
    [AMBER] dumpable            = 2  — SUID_DUMP_USER, /proc/<pid>/mem readable by self
    [GREEN] keepcaps            = 0  — setuid(0) drops caps (normal)
    [  ?  ] seccomp_prctl_get   = 2  — SECCOMP_MODE_FILTER (see security.seccomp_status)
    [GREEN] speculation_ctrl    = 0  — CPU speculative-exec not mitigated by prctl (Spectre-class KASLR leak primitives available)
    flags: no_new_privs=0 dumpable=2 keepcaps=0 speculation_ctrl_mitigated=false
```

**Step 1: Write the failing test** (Go packages rarely have tests for evaluate since they require a live Linux container; for this task skip the Go test — the "test" is E2E validate_json.py. Mark this step as DONE with a comment.)

- [ ] Step 1 (N/A — evaluate checks have container-gated runtime tests; rely on E2E)

**Step 2: Verify architecture-independent NR**
Run:
```bash
for a in arm64 amd64 386 arm; do GOOS=linux GOARCH=$a go build ./pkg/evaluate/...; echo $a RC=$?; done
go vet ./pkg/evaluate/...  # darwin
```
Expected: 4 linux RC=0 + darwin vet RC=0. If an arch complains about `syscall.SYS_PRCTL undefined` add per-arch stubs (copy pattern from json_memfd_*_*.go).

- [ ] Step 2

**Step 3: Implement ProbePrctlState**
File: `pkg/evaluate/prctl_state_linux.go` with build tag `//go:build linux` + `// +build linux`.
Use `syscall.RawSyscall6(syscall.SYS_PRCTL, option, arg2, 0,0,0,0)` for EVERY probe (even when Go wraps it; RawSyscall6 bypasses libc ENOSYS paperovers).
- PR_GET_NO_NEW_PRIVS = 39, arg2=0, return value is 0/1
- PR_CAP_AMBIENT_IS_SET = 48, arg2=CAP_NET_RAW (13) to test one ambient cap
- PR_GET_DUMPABLE = 4, arg2=0, return value is 0/1/2
- PR_GET_KEEPCAPS = 7, arg2=0, return 0/1
- PR_GET_SECCOMP = 21, arg2=0 (confirm existing seccomp_status)
- PR_GET_SPECULATION_CTRL = 52, arg2=0, return bitmask: 1=indirect_branch_prediction_barrier, 2=speculative_store_bypass_disable, 4=prctl_spec_ctrl

Interpretations (宁漏勿 flag):
| Probe | SHARED / ESCAPE-FRIENDLY | ISOLATED / GATE-ACTIVE |
|---|---|---|
| PR_GET_NO_NEW_PRIVS | 0 → GREEN ("exploit-friendly") | 1 → AMBER ("execve caps blocked") |
| PR_GET_DUMPABLE | 1 or 2 → GREEN ("/proc/*/mem self-readable") | 0 → "? SUID_DUMP_ROOT" (don't assume isolated) |
| PR_GET_KEEPCAPS | 1 → GREEN ("setuid(0) keeps caps") | 0 → standard (no verdict either way) |
| PR_GET_SPECULATION_CTRL | 0 / 未实现 (ENOSYS) → GREEN ("mitigation absent") | non-zero → "? active but cross-process KASLR leak still possible" |

Always show a final summary line with raw numeric values (for downstream consumers to apply their own thresholds).

Use `func prctlOut() *os.File { return os.Stdout }` for Fprintf (NOT package-level var) — T39 lesson.

- [ ] Step 3

**Step 4: Linux cross-arch rebuild** — repeat Step 2 command.
Expected: RC=0 for all 4 linux arches, darwin vet RC=0.

- [ ] Step 4

**Step 5: E2E container test**
Copy /tmp/cdk-arm64 fresh build → rerun `validate_json.py` and grep the output for `security.prctl_state` structural presence.

- [ ] Step 5

**Step 6: Commit**
```bash
git add pkg/evaluate/prctl_state_{linux,notlinux}.go
# Also add any per-arch NR stubs you created under prctl_nr_*.go or a single prctl_nr_linux_*.go pattern
git commit -m 'feat(evaluate): T45 — add security.prctl_state (6 probes) for NoNewPrivs/Dumpable/KeepCaps/speculation_ctrl'
```

- [ ] Step 6

---

### Task T46: Seccomp advanced 侦查 (user-notif listener + action types)

**Files:**
- Create: `pkg/evaluate/seccomp_advanced_linux.go`, `pkg/evaluate/seccomp_advanced_notlinux.go`
- Create (if syscall NR missing on any arch): per-arch `seccomp_nr_linux_*.go` with `seccompNR uintptr`
- syscall name: `seccomp(2)`. NRs: amd64=317, arm64=277, 386=354, arm=383.

**Interfaces:**
- Produces: check id=`security.seccomp_advanced` in `CategorySecurity`. Probes:
  1. `SECCOMP_GET_ACTION_AVAIL` (op=5) for each of 7 actions (KILL_PROCESS/KILL_THREAD/ERRNO/TRAP/USER_NOTIF/TRACE/LOG). Returns 0 if kernel supports the action. Only LOG → KILL_PROCESS (newer kernels add KILL_PROGRESS in 6.10+). Log which actions are supported — USER_NOTIF = GREEN (seccomp agent logic exists, maybe exploitable), KILL_PROCESS = AMBER (very strict).
  2. `SECCOMP_GET_NOTIF_SIZES` (op=6): struct size test with NULL ptr + EFAULT → returns -EFAULT with sizes filled when supported, -ENOSYS when not. Probe because USER_NOTIF-capable seccomp lets agents intercept syscalls, which has different bypass surfaces.
  3. Try seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_SPEC_ALLOW, 0) with NULL filter → if returns -EFAULT (not -EINVAL/-ENOSYS) then these FLAGS are supported.
  4. SECCOMP_USER_NOTIF_FLAG_CONTINUE (flag for addfd ioctl) — just print a static advisory line if USER_NOTIF is supported ("seccomp agent may forward blocked syscalls on greenlight").

Note on side-effect safety: 所有操作都是 GET / NULL-ptr 探测，不会安装 filter。op=5/6 在 Linux 5.x+ 是严格 read-only。

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.seccomp_advanced",
    "Probe seccomp(2) actions support + USER_NOTIF listener availability [F7]",
    []string{"InContainer"},
    func() { ProbeSeccompAdvanced() },
)
```

Output:
```
security.seccomp_advanced — seccomp(2) capabilities (7 actions + notif sizes + flags):
  actions supported via SECCOMP_GET_ACTION_AVAIL:
    [GREEN] KILL_PROCESS  = no  (v5.11+, strict gate is absent)
    [  ?  ] KILL_THREAD   = yes (standard)
    [  ?  ] ERRNO         = yes (standard)
    [  ?  ] TRAP          = yes (standard)
    [GREEN] USER_NOTIF    = yes → seccomp agent syscall proxy present (review bypass strategy)
    [  ?  ] TRACE         = yes (PTRACE interaction possible)
    [  ?  ] LOG           = yes (audit-only; no enforcement)
  [GREEN] SECCOMP_GET_NOTIF_SIZES OK → user notif ioctl contract present
  [  ?  ] FLAGS: NEW_LISTENER=1 TSYNC=1 SPEC_ALLOW=1 LOG_MAKERS=?
  advisory: seccomp USER_NOTIF is active on this kernel → agent-driven policies can be inconsistent
```

Steps mirror T45: cross-arch build → implement → E2E → commit.

Flags:
- SECCOMP_SET_MODE_FILTER = 1
- SECCOMP_GET_ACTION_AVAIL = 5
- SECCOMP_GET_NOTIF_SIZES = 6
- actions (u32): SECCOMP_RET_KILL_PROCESS=0x80000000, KILL_THREAD=0x00000000, ERRNO=0x00050000, TRAP=0x00030000, USER_NOTIF=0x7fc00000, TRACE=0x7ff00000, LOG=0x7ffc0000
- SECCOMP_FILTER_FLAG_NEW_LISTENER = (1UL << 3)
- SECCOMP_FILTER_FLAG_TSYNC = (1UL << 1)
- SECCOMP_FILTER_FLAG_SPEC_ALLOW = (1UL << 4)

When RawSyscall returns ENOSYS (38) → kernel too old, print "[?] ENOSYS kernel<5.x".
When it returns EFAULT (14) for NULL args → the probe structure WAS valid for the kernel (proceed to flag this as supported).

- [ ] Step 1 (N/A — container-gated)
- [ ] Step 2: Cross-arch NR validation (same as T45 Step 2 command — check for SYS_SECCOMP on 4 arches)
- [ ] Step 3: Implement ProbeSeccompAdvanced in seccomp_advanced_linux.go with `func secAdvOut() *os.File { return os.Stdout }`
- [ ] Step 4: Cross-arch rebuild RC=0
- [ ] Step 5: E2E validate_json.py + grep for `security.seccomp_advanced`
- [ ] Step 6: Commit

---

### Task T47: Landlock ABI / ruleset 深度侦查 (landlock_deep)

**Files:**
- Create: `pkg/evaluate/landlock_deep_linux.go` (build tag linux)
- NR: `syscall.SYS_LANDLOCK_CREATE_RULESET` if exposed; else raw: amd64=444, arm64=442, 386=443, arm=445.
- Create per-arch landlock_nr_*.go stubs if needed.

**Interfaces:**
- Check id=`security.landlock_deep` in CategorySecurity.
- Use LANDLOCK_CREATE_RULESET (op 1) with NULL rules + attr = {handled_access_fs=~0ULL, ...} to get abi=landlock_fill abi=return value. EINVAL for invalid flags = probe succeeded, return the ABI. ENOSYS = kernel<5.13.
- Read `/proc/self/status:Landlocked:` field (since 5.19). 1 = 当前进程确实被 landlock 限制。
- Optional (side-effect-free): 用 landlock_create_ruleset + LANDLOCK_CREATE_RULESET_VERSION (op 0) 再次确认 ABI 版本。
- 输出当前 ABI 版本 (1→4) 对应的 blocked family：
  - ABI 1: exec, truncate, FS basic ops
  - ABI 2: ioctl on block devices
  - ABI 3: TCP bind() restriction
  - ABI 4: mount tree restriction + refer link

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.landlock_deep",
    "Probe Landlock ABI version (1-4) + /proc/self/status:Landlocked bit [F8]",
    []string{"InContainer"},
    func() { ProbeLandlockDeep() },
)
```

Example output:
```
security.landlock_deep — Landlock: syscall-probed ABI version + per-process Landlocked bit:
  [GREEN] landlock syscall available (ABI=4) — kernel 6.2+
  [AMBER] /proc/self/status:Landlocked = 0 → current process NOT confined by Landlock
    ABI→feature map:
      ABI 1 (5.13): basic FS ops (read/write/execute directory)
      ABI 2 (5.19): + ioctl on block devices (→ CVE escape path gated?)
      ABI 3 (6.2):  + TCP bind() restriction (→ local bind primitive gated?)
      ABI 4 (6.7):  + mount/refer link (→ overlay primitive gated?)
    Process is NOT landlocked — 4 ABIs are available but none applied to this container.
    Verdict: not confined by Landlock.
```

Verdict rule:
- Landlocked=1 + (ABI≥2) → ISOLATED (good gate)
- Landlocked=1 + ABI=1 → AMBIGUOUS
- Landlocked=0 + syscall available → NOT confined (green for attacker)
- Landlocked=0 + ENOSYS → AMBIGUOUS (kernel too old)

Steps: same 6-step template as T45/T46.

---

### Task T48: eBPF + unprivileged BPF + IMA 侦查

**Files:**
- Create: `pkg/evaluate/ebpf_recon_linux.go` (kernel NR for bpf: amd64=321, arm64=280, 386=357, arm=386. Use wrapper per-arch file if named const missing.)
- Read /proc/sys/kernel/unprivileged_bpf_disabled, /proc/sys/kernel/kptr_restrict, /proc/sys/kernel/dmesg_restrict, /proc/sys/kernel/perf_event_paranoid.
- /sys/kernel/security/ima/policy, /sys/kernel/security/btf exists?

**Interfaces:**
- Check id=`security.ebpf_recon` in CategorySecurity.
- Probe bpf(BPF_PROG_GET_NEXT_ID, NULL_attr, sizeof(attr)) with attr={NULL}: if returns EACCES vs EPERM vs ENOSYS differently per kptr_restrict=0 — if unpriv bpf is disabled then bpf() returns EPERM immediately; if kptr is strict error may differ. RawSyscall6, NULL attr.
- syscall probe bpf() NR to confirm compiled out (ENOSYS).
- Read 5 /proc/sys/kernel/*_* files.
- Read /sys/kernel/security/lsm for "bpf" substring (LSM BPF loaded? if yes, this is the new kernel-enforcement gate — seccomp is not the only thing blocking syscalls).

Output:
```
security.ebpf_recon — eBPF / IMA / kernel pointer disclosure gates:
  [GREEN] unprivileged_bpf_disabled = 0 → unprivileged users can create bpf progs/maps (huge surface)
  [GREEN] kptr_restrict = 0 → /proc/kallsyms exposes real addresses, %pK prints pointers (direct KASLR leak)
  [AMBER] dmesg_restrict = 1 → dmesg() gated by CAP_SYSLOG (normal)
  [  ?  ] perf_event_paranoid = 2 → no raw hardware perf for non-root
  [  ?  ] BPF LSM in /sys/kernel/security/lsm: YES (→ seccomp isn't the only filter — see LSM enumeration)
  [  ?  ] /sys/kernel/security/ima/policy present? NO → IMA measurement is NOT enforcing
  [GREEN] /sys/kernel/btf/vmlinux readable = YES → full kernel type info for exploit development
    eBPF surface = OPEN → consider CVE-2024-XXXX-style eBPF primitives if kernel version matches.
```

Note: bonus for T20 (capabilities): if Cap decode includes CAP_BPF or CAP_PERFMON, add a separate GREEN banner to commands.capabilities. But this is a bonus optional edit — not required for task completion (T48 is focused on the new check file). Don't break T39 fix (don't add package-level vars in capabilities.go).

Steps same 6-step template as T45.

---

### Task T49: io_uring 可用性侦查

**Files:**
- Create: `pkg/evaluate/io_uring_probe_linux.go`
- NR: io_uring_setup=425(amd64)/426(arm64)/425(386)/427(arm); io_uring_enter=426/427/426/428; io_uring_register=427/428/427/429.
- Read /proc/sys/kernel/io_uring_disabled (值: 0=允许, 1=root-only, 2=disabled).

**Interfaces:**
- Check id=`system.io_uring` in CategorySystemInfo.
- 3 probes: (1) read sysctl io_uring_disabled; (2) io_uring_setup(0, NULL) with entries=0 → should EINVAL if the syscall exists (entries=0 is min 1 invalid), ENOSYS means compiled out. (3) check if /proc/syscalls exists and io_uring_setup NR is "allowed" mask (cat /proc/$pid/status:Seccomp_mask if exists in newer kernels — but optional; skip if too complex). Side-effect-free because entries=0→NULL params.

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySystemInfo,
    "system.io_uring",
    "Probe io_uring syscall availability + /proc/sys/kernel/io_uring_disabled [F9]",
    []string{"InContainer"},
    func() { ProbeIOUringAvailability() },
)
```

Output:
```
system.io_uring — async I/O (io_uring) attack surface:
  [GREEN] /proc/sys/kernel/io_uring_disabled = 0 → io_uring allowed for all users
  [GREEN] io_uring_setup syscall = REACHED (returned EINVAL — entries=0 invalid; syscall is present)
    [!] WARNING: io_uring enabled → CVEs 2024-0340 / 2024-XXXX-class attack surface is live.
    If kernel version in uname -r matches vulnerable range, prioritize io_uring exploit research.
```

Verdict: 0 + EINVAL → GREEN (not gated); 1 + EACCES for non-root → AMBER (root-only); 2 + ENOSYS → ISOLATED (disabled).

Steps same 6-step template.

---

### Task T50: User Namespace 限制深度 (userns_limits)

**Files:**
- Create: `pkg/evaluate/userns_limits_linux.go` (file-read + 1 probe)
- Also create one tiny syscall probe NR for unshare(): amd64=272, arm64=268, 386=310, arm=376.

**Interfaces:**
- Check id=`security.userns_limits` in CategorySecurity.
- Read:
  - /proc/sys/user/max_user_namespaces
  - /proc/sys/user/max_mnt_namespaces
  - /proc/sys/user/max_pid_namespaces
  - /proc/sys/user/max_net_namespaces
  - /sys/kernel/security/lockdown (none/integrity/confidentiality — moved to T54 but cross-reference with 1 line)
- Probe (harmless): unshare(CLONE_NEWUSER) with 0 flags=0? Actually pass flags=CLONE_NEWUSER = 0x10000000 → if returns EINVAL but ENOSYS not returned, syscall available. If succeeds (return 0) then we must immediately exit (thread created in new ns, don't leak — use a child goroutine in fork? Actually no — 不要真的创建新线程。用 RawSyscall 但如果成功了，当前 OS thread 在新 userns 中无法撤销，危险！**Better probe: use syscall(SYS_unshare, 0xffffffff, ...) all-ones invalid flags → EINVAL = reachable, ENOSYS = unavailable.** 安全。

- Also: test if /proc/self/uid_map shows single line 4294967295 (new user_ns with unmapped IDs, created via shell unshare -U — can be read as file after our probe doesn't change us). If we can't unshare safely just read /proc/sys/user/* values.

Output:
```
security.userns_limits — user-ns creation quota + unshare(2) reachability:
  [GREEN] max_user_namespaces = 4294967295 (≈unlimited; any process can create a user_ns)
  [GREEN] max_mnt_namespaces  = 4294967295 (unshare -rm → new mount tree with idmap support)
  [  ?  ] max_pid_namespaces  = 4294967295
  [  ?  ] max_net_namespaces  = 4294967295
  [GREEN] unshare(2) = REACHED (returned EINVAL on invalid flags; kernel supports user-ns)
  [GREEN] kernel lockdown = [none] (→ CAP_SYS_MODULE + kexec_load are not blocked by LSM policy)
    User namespace creation is OPEN → unshare + idmap + mount primitives are available.
```

New Env flags to add (if you want other checks to use):
- `HasUserNamespaceUnshare` bool — unshare() is reachable
- `UnprivUserNsDisabled` bool — max_user_namespaces==0

- [ ] Modify pkg/evaluate/env.go:DetectEnv to run a lightweight unshare probe + set flags? or keep userns check entirely local? RECOMMEND: keep local in T50 — output in log is sufficient for recon operators; don't add preflight flag unless another check needs it.

Steps same 6-step template.

---

### Task T51: Container Runtime 指纹识别 (runtime_fingerprint)

**Files:**
- Create: `pkg/evaluate/runtime_fingerprint_linux.go` (file read only, no syscalls)

**Interfaces:**
- Check id=`system.runtime_fingerprint` in CategorySystemInfo.
- Heuristics (read-only, string match):
  1. `/run/.containerenv` exists → podman
  2. `/.dockerenv` exists → docker/moby
  3. `/proc/1/cgroup` contains "containerd" OR `/run/containerd/` mounts → containerd
  4. `/proc/1/cgroup` contains "crio" OR `/var/run/crio` exists → CRI-O
  5. `/proc/1/sched` comm 字段: "init" → possibly kata/firecracker (real init 不是 sh)
  6. `/proc/version` contains "linuxkit" → Docker Desktop LinuxKit VM
  7. `/sys/class/dmi/id/product_name` 包含 "KVM" / "QEMU" / "VirtualBox" / "Amazon EC2" → virtualized (kata/firecracker/hyper-v)
  8. `/dev/kvm` exists → KVM device available (microVM 内核逃逸路径)
  9. gVisor detection: `/proc/version` contains "gvisor" 或 `/proc/self/status` Seccomp=2 且返回特定 errno 模式 (T41 seccomp deep 模式; 如果 T41 里已经能区分 gvisor 就 cross-reference). 或 `/sys/devices/system/cpu/online` 单个 CPU + /proc/cpuinfo 为 "None" (gVisor sys 文件系统模拟不完整). 简单版: 检查 3-4 个 gvisor 特有的缺失文件是否同时 absent 再判，避免 FP。
  10. Firecracker: `/proc/cpuinfo` vendor_id 空 或 `/sys/devices/platform` 为空。

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySystemInfo,
    "system.runtime_fingerprint",
    "Fingerprint container runtime (runc vs containerd vs crio vs podman vs docker vs gvisor vs kata/firecracker vs linuxkit)",
    []string{"InContainer"},
    func() { FingerprintRuntime() },
)
```

Output:
```
system.runtime_fingerprint — runtime detection via /proc + /sys fingerprints:
  [  ?  ] /.dockerenv                  = YES
  [  ?  ] /run/.containerenv           = NO
  [  ?  ] /proc/1/cgroup "containerd"  = YES
  [  ?  ] /proc/version "linuxkit"     = YES (kernel 6.12.76-linuxkit — Docker Desktop LinuxKit)
  [  ?  ] /dev/kvm                     = NO
  [  ?  ] gvisor pattern matches       = NO (proc cpuinfo not empty)
  [  ?  ] microVM (kata/firecracker)   = NO (DMI product_name = "SAMSUNG" — bare-metal LinuxKit VM)
  runtime guess = Docker Desktop (moby + containerd + LinuxKit)
  exploit-surface implication: native runc container on a LinuxKit KVM VM guest kernel.
```

Rule: each fingerprint prints status, final "runtime guess" line selects whichever fingerprints matched; if conflict or multi-match say "ambiguous between: A, B, C" —宁漏勿 flag.

Steps same 6-step template (easy, file I/O only; no cross-arch NR needed).

---

### Task T52: AppArmor Deep 侦查 (profile 名 + enforce mode + features)

**Files:**
- Create: `pkg/evaluate/apparmor_deep_linux.go` (read /sys/kernel/security/apparmor/* files)

**Interfaces:**
- Check id=`security.apparmor_deep` in CategorySecurity.
- Reads:
  1. `/proc/self/attr/current` — 当前进程 profile 名 + mode (e.g., "docker-default (enforce)", "cri-containerd.apparmor.d (enforce)", "unconfined")
  2. `/sys/kernel/security/apparmor/profiles` — 已加载 profile 列表
  3. `/sys/kernel/security/apparmor/features/*` — directory tree (capability, file, mount, namespace, network, policy, rlimit)
  4. `/sys/module/apparmor/parameters/enabled`

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.apparmor_deep",
    "AppArmor: current profile name, mode, loaded profiles list, per-feature support [F10]",
    []string{"InContainer"},
    func() { EnumerateAppArmorDeep() },
)
```

Output format:
```
security.apparmor_deep — AppArmor profile & feature enumeration:
  apparmor enabled = YES (module param Y)
  [AMBER] current profile = docker-default (enforce)
  loaded profiles (4):
    - docker-default (enforce)
    - /usr/bin/man (enforce)
    - lsb_release (enforce)
    - nvidia_modprobe (enforce)
  apparmor features mount/ = YES (→ mount family syscalls subject to AppArmor even if cap set)
  apparmor features namespace/ = YES (→ unshare/newnamespace gated by profile)
  apparmor features network/ = YES (→ per-socket family AF_* gated)
  Verdict: docker-default (enforce) ACTIVE + mount/ns/network features → significant gate for escape primitives.
```

Veridct rules (宁漏勿 flag): profile=unconfined → NOT isolated (GREEN); profile=enforce + features mount|namespace|network 任一 → partially isolated (AMBER); profile=enforce all 3 → isolated; profile unknown + features none → AMBIGUOUS.

Steps 6-step template.

---

### Task T53: SELinux context 深度侦查

**Files:**
- Create: `pkg/evaluate/selinux_context_linux.go` (纯文件读取)

**Interfaces:**
- Check id=`security.selinux_deep` in CategorySecurity.
- Reads:
  1. `/proc/self/attr/current` — current SELinux context (expect: `system_u:system_r:container_t:s0:c123,c456` for a normal container; `system_u:system_r:spc_t:s0` = Super Privileged Container → RED FLAG → PRIV ESC; `unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023` = unconfined → no SELinux enforcement on this process)
  2. `/proc/self/attr/exec` / `fscreate` / `keycreate` — 其他上下文 (可 blank)
  3. `/sys/fs/selinux/enforce` — SELinux mode (0=permissive 1=enforcing)
  4. `/sys/fs/selinux/policyvers` — policy DB version
  5. `/sys/fs/selinux/mls` — 是否 multi-level security

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.selinux_deep",
    "SELinux: current process context (container_t vs spc_t vs unconfined), enforce mode, policy version [F11]",
    []string{"InContainer"},
    func() { EnumerateSELinuxDeep() },
)
```

Output:
```
security.selinux_deep — SELinux context and policy status:
  selinuxfs mounted = YES (/sys/fs/selinux/enforce readable)
  [GREEN] policy = system_u:system_r:container_t:s0:c1023 (standard container policy)
  [  ?  ] exec context = (inherit)
  [AMBER] enforce = 1 (enforcing — exploits that do write/fd-passing may fail)
  policy version = 33
  MLS enabled = YES
  Verdict: standard container_t (enforcing) → PARTIALLY ISOLATED; avoid cross-process write primitives.
```

Special banners:
- `spc_t` → GREEN line with "WARNING: SPC (super-privileged container) type — effectively no SELinux confinement"
- `unconfined_t` → same WARNING
- `enforce=0` → GREEN ("permissive-mode; SELinux logs but does NOT block")

Steps 6-step template.

---

### Task T54: Kernel Lockdown + IMA 侦查

**Files:**
- Create: `pkg/evaluate/kernel_lockdown_linux.go`
- Actually overlap with T48 (IMA). TASK SPLIT: T48 keeps /sys/kernel/security/btf + bpf() syscall probe. T54 owns:
  1. `/sys/kernel/security/lockdown` — prints `none [integrity] confidentiality` (the bracketed one is active)
  2. `/sys/kernel/security/ima/policy` → line count, existence
  3. `/sys/kernel/security/evm` → EVM existence
  4. `/proc/sys/kernel/kexec_load_disabled` → bool
  5. `/sys/kernel/kexec_loaded` → bool
  6. `/proc/iomem` has "Crash kernel" substring?
  7. SecureBoot: `/sys/firmware/efi/efivars/SecureBoot-*` (EFI vars) → check file existence; read first bytes if present (last byte of 8-byte header is 0x01 if SecureBoot is on, 0x00 if off; don't parse EFI if complex — existence alone is a signal for bare-metal/microVM distinction). Actually on container this usually masked/hidden so AMBIGOUS if missing.

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.kernel_lockdown",
    "Kernel lockdown + IMA/EVM + kexec + crashkernel + SecureBoot (container-visible signals)",
    []string{"InContainer"},
    func() { EnumerateKernelLockdown() },
)
```

Example output:
```
security.kernel_lockdown — kernel-level enforcement gates:
  [GREEN] lockdown = none → unsigned modules / kexec_load / debugfs / /dev/mem ALL ENABLED
  [  ?  ] IMA policy   = not readable (IMA not enabled or container-cannot-see)
  [  ?  ] EVM           = not mounted
  [GREEN] kexec_load_disabled = 0 (CAP_SYS_BOOT → host kernel reload)
  [  ?  ] /sys/kernel/kexec_loaded = 0
  [  ?  ] Crash kernel in /proc/iomem = YES (kexec crash kernel configured)
  [  ?  ] SecureBoot (efivar) = unreachable from container (AMBIGUOUS)
  Verdict: LOW kernel-level gates (lockdown none + kexec enabled).
```

Rules: lockdown=none + kexec_load_disabled=0 → GREEN for attacker; lockdown=integrity → AMBER (blocks module/kexec, but /dev/mem debugfs might still leak); lockdown=confidentiality → ISOLATED (blocks all of the above + usercopy to kernel); SecureBoot unreachable → don't verdinct about it (AMBIGUOUS). IMA enforcing → AMBER line if policy file has "appraise" lines.

Steps 6-step template.

---

### Task T55: Kernel hardening dump (Kconfig + leaks + CPU bugs)

**Files:**
- Create: `pkg/evaluate/kernel_hardening_linux.go`
- No syscalls — file I/O only
- Also include new capability dangerous-capability banner part here OR keep in T48 as bonus (not mandatory).

**Interfaces:**
- Check id=`system.kernel_hardening` in CategorySystemInfo.
- Reads:
  1. `/proc/config.gz` (zcat → search for CONFIG_ entries) OR `/boot/config-$(uname -r)` as fallback
  2. Target flags:
     - `CONFIG_KALLSYMS_ALL=y` → symbol dump includes all (KASLR leak friendly)
     - `CONFIG_STACKPROTECTOR_STRONG=y` / `CONFIG_STACKPROTECTOR`
     - `CONFIG_RANDOMIZE_BASE=y` (KASLR)
     - `CONFIG_RANDSTRUCT=y` / `RANDSTRUCT_NONE=y`
     - `CONFIG_MODULES=y` / `CONFIG_MODULE_UNLOAD=y`
     - `CONFIG_MODPROBE_PATH` (string config → sometimes `/sbin/modprobe`, sometimes custom)
     - `CONFIG_IA32_EMULATION=y` (32-bit compat = double attack surface)
     - `CONFIG_IO_URING=y`
     - `CONFIG_HARDENED_USERCOPY=y`
     - `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` / not set
     - `CONFIG_SECURITY_LOCKDOWN_LSM=y` / `LOCKDOWN_LSM_EARLY=y`
     - `CONFIG_STACKLEAK_METRICS=y` (STACKLEAK GCC plugin)
     - `CONFIG_UBSAN` (KASAN/KCSAN/UBSAN — developer kernels; easier debugging)
  3. `/proc/sys/kernel/modprobe` (Runtime value; not just compile-time)
  4. `/proc/kallsyms`: head -5 → first address is 00000000 or actual address? (non-zero = leak)
  5. `/proc/modules`: line count (module sizes/addresses available → ROP construction friendly)
  6. `/proc/slabinfo` readable?
  7. `/sys/devices/system/cpu/vulnerabilities/*` (iterate directory) → 25 entries (meltdown, spectre_v1/2, spec_store_bypass, retbleed, zenbleed, downfall, gather_data_sampling, srso, etc.) — each line shows "Vulnerable" / "Mitigation: ..." / "Not affected".

- Aggregate output: `hardening_score = (number of GOOD gates present) - (number of leaky signals)`. Thresholds for AMBIGUOUS midrange; never flag a kernel as "unexploitable" (宁漏勿 flag).

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySystemInfo,
    "system.kernel_hardening",
    "Kernel hardening: /proc/config.gz options, kptr leaks, /sys/cpu/vulnerabilities, modprobe path [F12]",
    []string{"InContainer"},
    func() { DumpKernelHardening() },
)
```

Output — split into 3 tables (Kconfig, leaks, CPU vuln) + summary.

Steps 6-step template.

---

### Task T56: PTRACE scope 深度侦查

**Files:**
- Create: `pkg/evaluate/ptrace_scope_linux.go`

**Interfaces:**
- Check id=`security.ptrace_scope` in CategorySecurity.
- Reads:
  1. `/proc/sys/kernel/yama/ptrace_scope` (0-3): 0=all processes can PTRACE each other (shared pidns + 0 → host memory read via process_vm_readv). 3=strictest (only PTRACE_TRACEME + children).
  2. `/proc/sys/kernel/kptr_restrict` (cross-reference T48)
  3. Probe process_vm_readv syscall: NULL ptrs → EFAULT = reachable, ENOSYS = unsupported (NR amd64=310, arm64=270, 386=347, arm=377).
  4. `/proc/1/mem` exists + readable? (shared pidns + this readable → host init 内存可读).
  5. `/proc/sys/kernel/perf_event_paranoid` (perf 栈泄漏; cross-reference T48).

Registration:
```go
RegisterSimplePrereqCheck(
    CategorySecurity,
    "security.ptrace_scope",
    "Yama ptrace_scope + process_vm_readv reachability + /proc/1/mem readable + perf paranoia [F13]",
    []string{"InContainer"},
    func() { EnumeratePtraceScope() },
)
```

Output:
```
security.ptrace_scope — ptrace / cross-process memory read gates:
  [GREEN] yama ptrace_scope = 1 → PTRACE_ATTACH restricted to children only (default Ubuntu)
  [  ?  ] process_vm_readv syscall REACHED (EFAULT on NULL ptrs — syscall is available)
  [  ?  ] /proc/1/mem readable by self = NO (EACCES — expected in pid-namespace container)
  [GREEN] perf_event_paranoid = 2 → kernel symbols via perf event blocked
  Verdict: MODERATE PTRACE surface; yama=1 + no /proc/1/mem.
```

Steps 6-step template.

---

### Task T57: Volcengine/BytePlus 云厂商信号扩展（约束 #3）

**Files:**
- Modify: `pkg/evaluate/env.go:detectInCloud()` 函数（Volcengine 规则组）
- Modify: `pkg/evaluate/cloud_metadata_api.go` (新增 Volcengine IMDS 路径探测)
- Reference signals: 13 signals from Explore agent output (权威):

High-confidence signals (必须 first, BEFORE Aliyun ECS):
1. `hostname fqdn` 匹配 `\.(byted\.org|bytedance\.net)$` (ByteDance 内部域)
2. DMI sys_vendor substrings: `volcengine|bytedance|byteplus` (SMBIOS OEM)
3. CSI 驱动目录存在: `/var/lib/kubelet/plugins/tos.csi.volcengine.com/`, `ebs.csi.volcengine.com/`, `nas.csi.volcengine.com/`
4. TOS mount 指纹: `/proc/mounts` 匹配 `tos-cn-[a-z0-9-]+\.volces\.com`
5. 容器镜像前缀: `cr\.volces\.com` 或 `(^|/)[a-z0-9-]+\.cr\.volces\.com/` (在 K8s pod cgroup/image-ref 里找; 或读 /proc/self/cgroup 有这些前缀? 或读 /run/systemd/transient 或 crio meta? Simple: read env var `CONTAINER_IMAGE_REF` if exist; else, read /proc/self/mountinfo containerd paths for layer prefix)
6. SDK env: `VOLCENGINE_ACCESS_KEY`, `VOLCENGINE_SECRET_KEY`, `VOLCENGINE_SESSION_TOKEN`, `VOLCENGINE_REGION`
7. 本地 config 文件: `~/.volcengine/config.json`, `/etc/volcengine/*` 包含 `open.volcengineapi.com` / `open.byteplusapi.com`
8. IMDS HTTP: `http://100.96.0.96/volcstack/latest/iam/security_credentials/` (HIGHEST CONFIDENCE 单一探针；第一方 volcengine sdk 定义的, 与 Aliyun 100.100.100.200 完全不重叠)
9. IMDS IP: `http://100.96.0.96/` reachable (简单 HTTP GET / with 500ms connect timeout)
10. vendor-data content: `/var/lib/cloud/instance/vendor-data.json` contains `volcengine|volc|byteplus` (IMPORTANT: 不要 key 看 cloud-init datasource 名 = AliYun! 复用 DataSourceAliYun)
11. IMDSv2 token header: PUT `100.96.0.96/volcstack/latest` → `X-volc-ecs-metadata-token-ttl-seconds` (Volcengine-specific header)

Critical bug fix from gap analysis: 现有 CDK env.go Rule 3（datasource name = "volc"/"byteplus"）实际上**在真实 Volcengine 主机上不会命中**，因为 Volcengine 复用了 cloud-init 的 DataSourceAliYun（上游没有独立的 volcengine datasource），所以 datasource 名是 "AliYun"。改为 vendor-data CONTENT 匹配。

注册 & 修改（env.go detectInCloud）:
- 将 Volcengine 规则组（11 条）作为单独函数 `detectInCloudVolcengineFirst()` 并在 `detectInCloud()` 函数开头调用它（在 Aliyun/其它规则之前），匹配成功（≥3条命中或 IMDS /volcstack 可达 = 单条决定性）则立即设置 `InCloud=true, CloudVendor="volcengine/byteplus"` 并返回跳过 Aliyun。
- 若网络探测（8/9/11）不可用时 timeout 500ms 内要 fail-closed 继续（不设置 cloud vendor，但也不影响后续 Aliyun 匹配）。

**新增 Env flags** — 在 Env struct + flagByName 注册（供 Prereqs 过滤检查）:
- `CloudVolcengine` bool — 明确匹配到 Volcengine/BytePlus
- `CloudAliyun` bool — 明确匹配到 Aliyun 且非 Volcengine 误报
- 这样 Prereqs 可以写 `["CloudVolcengine"]` 让特定 Volcengine-only 的检查只在 Volcengine 环境跑

**修改 cloud_metadata_api.go**：为 Volcengine 供应商单独列出 probe URLs:
- http://100.96.0.96/latest/instance_id
- http://100.96.0.96/latest/region_id
- http://100.96.0.96/latest/instance_type_id
- http://100.96.0.96/volcstack/latest/iam/security_credentials/ (仅 HEAD, 不 body 读 role cred 明文，只打 role 数 + 403/200 status)

Registration (cloud metadata): reuse existing cloud.metadata_api check id; branch based on env.CloudVendor.

Verification: T57 doesn't have a real Volcengine ECS instance env locally — verify logic on mock:
- 单元化：在 `/tmp/cdk-e2e/` 里添加 mock vendor-data file with "volcengine" substring；在 docker run 中 bind-mount 到 /var/lib/cloud/instance/vendor-data.json，同时创建 /sys/class/dmi/id/sys_vendor 模拟。测试设置了 CloudVendor=volcengine 且 Aliyun fallback 没被触发。

Steps:
- [ ] Step 1 (N/A for evaluate checks)
- [ ] Step 2: Read existing env.go detectInCloud function (currently lines ~331-399)
- [ ] Step 3: Implement detectInCloudVolcengineFirst() in env.go, call FIRST in detectInCloud. Add CloudVolcengine/CloudAliyun flags to Env struct + flagByName.
- [ ] Step 4: Update cloud_metadata_api.go to branch CloudVendor for Volcengine URLs (100.96.0.96 /volcstack).
- [ ] Step 5: Cross-arch build RC=0 on 4 linux arches + darwin vet RC=0.
- [ ] Step 6: Container mock test (bind mount vendor-data + DMI stub).
- [ ] Step 7: Commit.

---

## Self-Review

**1. Spec coverage:**
All 13 checks address the gap analysis top gaps: P0×7 (prctl/seccomp adv/landlock/eBPF/io_uring/userns/Volcengine) + P1×6 (runtime fingerprint/apparmor deep/selinux deep/lockdown/kernel hardening/ptrace scope). Directly maps to 25+ modern recon signals requirement.

**2. Placeholder scan:**
Each 6-step template has concrete NR numbers + file paths + probe syscall opcodes. No TBD. 13 check ids fully spelled; all output format examples given with specific verdicts and banner texts. Invalid-flags fallback (ENOSYS/EINVAL detection) explicitly described in T46/T49/T50/T56. Cross-arch NR per-arch stub file pattern (copy from existing json_memfd) specified.

**3. Type consistency:**
All RegisterSimplePrereqCheck usages consistent (Category* + id string + prereq string slice + func() wrapper). Output functions use `func XXXOut() *os.File { return os.Stdout }` getter pattern, no package-level vars — avoids T39 bug. New Env flags CloudVolcengine/CloudAliyun are bool type; unknown flag names fail-closed via existing flagByName map — respects Global Constraint #4.
