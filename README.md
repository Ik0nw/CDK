# CDK - Container Defense Kit

> 容器隔离基线审计工具 | 内部合规自测 · 技术架构 / 二次开发 / 代码审查参考文档

---

> 面向所有开发者的架构与实现说明文档。
> 想要编译、运行、解读报告（快速上手）请看面向最终用户的说明：
>
> 👉 **[HUMAN_README.md](./HUMAN_README.md) — 用户使用 / 目录速览 / 合规**

---

## 0. 身份与约束（先读本节）

- 本仓库 = **CDK（Container Defense Kit）**，Go 项目，模块根 `github.com/cdk-team/CDK`（或私有 fork）。
- 仓库目的：在容器 / K8s / Linux 宿主机环境进行 **只读的** 隔离基线审计与安全评估。
- **禁止**为它添加任何会**变更**目标环境状态的行为（写文件、开 socket 对外、修改 sysctl、修改 cgroup、加载内核模块等），除非显式地被“主动探测（active probe）”框架封装并默认关闭。
- **禁止**引入会对外发起非元数据协议流量的网络行为（非 169.254.169.254 / kube-api 既定端点的流量一律视为违规）。
- 任何新的“主动”行为必须进入 `Prereqs` 门控（见下文 §3）并默认在 `NoGating=false` 下保持 **SKIP**，直到用户显式启用。

---

## 1. 目录结构（开发速查）

```
CDK/
├── cmd/cdk/                       # CLI 入口；新增子命令改这里
├── pkg/evaluate/                  # ⚠️ 核心：所有评估检查项
│   ├── env.go                     # Env 结构 + Prereq 定义 + Check 接口
│   ├── json.go                    # 报告序列化（含 memfd 特殊路径）
│   ├── json_memfd_linux_*.go      # 按 GOARCH 分离的 memfd syscall 号
│   ├── json_memfd_notlinux.go     # 非 linux 的桩
│   ├── available_linux_capabilities.go  # capabilities 位图解析
│   ├── seccomp_deep_inspect.go    # seccomp BPF 反编译 / 策略解析
│   ├── k8s_service_account.go     # SA token 与挂载探测
│   ├── security_info.go           # 安全上下文统一读取
│   ├── kernel_hardening_linux.go  # T*  内核硬ening 评估
│   ├── kernel_lockdown_linux.go   # T*  lockdown 评估
│   ├── apparmor_deep_linux.go     # T45 AppArmor profile 深度检查
│   ├── landlock_deep_linux.go     # T* Landlock
│   ├── selinux_context_linux.go   # T* SELinux
│   ├── seccomp_advanced_linux.go  # T* seccomp 进阶
│   ├── userns_limits_linux.go     # T* user-ns 限制
│   ├── cloud_vendor_expand_linux.go # T* 云厂商元数据扩展
│   ├── ebpf_recon_linux.go        # T* eBPF 暴露面
│   ├── io_uring_check.go          # T* io_uring 可用性
│   ├── prctl_state.go             # T* prctl 选项
│   ├── ptrace_scope_linux.go      # T* ptrace YAMA
│   ├── runtime_fingerprint.go     # T* 运行时指纹（docker/containerd/cri-o/pouch）
│   ├── sysnr_linux_*.go           # 每架构 syscall 号常量表
│   └── sysnr_notlinux.go          # 非 linux 桩
├── pkg/audit/credential_access/   # 凭据访问类审计
├── pkg/cli/                       # 参数解析
├── pkg/plugin/                    # 插件接口（interface.go 含 gating 集成）
├── pkg/tool/probe/net.go          # 网络/元数据探测
├── pkg/util/file_io.go            # 文件 IO 封装
├── docs/superpowers/plans/        # 历史变更的设计记录
├── README.md                      # ⬅ 你正在看的这份（架构 / 开发规范）
├── HUMAN_README.md                # 👉 人类最终用户使用说明
└── README-AUDIT-COUNTERS.md       # T001–T057 检查项全量清单
```

---

## 2. 新增评估项（Check）的强制模板

当你要新增一个 `T0xx` 检查项时，**必须按下列模板执行**，否则视为不合规：

```go
// 1. 在 pkg/evaluate/ 下新增 T<NNN>_<name>_linux.go（跨平台文件用 build tag）
//
// 2. 定义注册函数，调用 RegisterCheck（已在 env.go / check_registry.go）
func init() {
    RegisterCheck(Check{
        ID:          "T099",
        Prereqs:     PrLinux | PrContainer, // 只在 Linux 容器内运行
        Info: Info{
            Name:        "example_check",
            Description: "一句话说明这项检查什么、为什么重要",
            Severity:    "medium", // info | low | medium | high | critical
            Category:    "isolation", // isolation | credential | hardening | fingerprint | metadata | capability
        },
        Run: func(e Env) Result {
            // 3. 只读取；不得修改。失败时返回 SKIP 并说明原因，不要 panic。
            // 4. 依赖内核版本/能力/某文件存在时，先判断 e 字段再读。
            return Result{Level: LevelWarn, Detail: ..., Reason: "..."}
        },
    })
}
```

**关键字段约定：**

| 字段 | 合法值 |
|---|---|
| `Prereqs` | `PrNone`（任意环境）或多个 `PrXxx` 的按位或。所有标志见 `pkg/evaluate/env.go`。 |
| `Result.Level` | `LevelPass`, `LevelInfo`, `LevelWarn`, `LevelFail`, `LevelSkip`。|
| `Result.Detail` | 保持 JSON 可序列化的 struct；不要塞二进制。|
| `Result.Reason` | `LevelSkip` 时必填，说明 **为什么**被跳过。 |

**修改代码时的 L0 检查清单（代码提交前必过自查项）：**

1. 🔒 有没有对目标环境产生副作用？（`O_WRONLY`、`os.Create`、`os.Remove`、`exec.Command`、`Listen/Dial` 到非元数据 IP、`prctl(SET_*)` 等一律需解释）
2. 🚪 有没有接入 `Prereqs`？如果会读 `/proc/kcore`、`sysfs` 敏感路径、会尝试 setns / ptrace / bpf 调用，必须加 `PrXxx` 并默认 gated。
3. 🧱 错误路径是否返回 `LevelSkip` + 合理的 `Reason`？
4. 🧱 跨平台代码是否加了 build tag？非 Linux 的“桩文件”放在 `<name>_notlinux.go` 或带 `//go:build !linux`。
5. 🧠 新增的检查项编号 `T<NNN>` **必须**在 `README-AUDIT-COUNTERS.md` 末尾追加一行。
6. 📝 **不要提交 `_test.go`** 到 MR（该仓库要求人工 review 单测后单独合入）。

---

## 3. 前置门控系统（Preflight Gating）

### 3.1 入口

`pkg/evaluate/env.go` 中的 `Env` 结构：

```go
type Env struct {
    OS            string  // GOOS
    Arch          string  // GOARCH
    KernelVersion string  // uname -r
    InContainer   bool    // 是否在容器内
    InitPID       bool    // PID == 1
    Systemd       bool    // systemd 为 init
    IsK8s         bool    // 有 KUBERNETES_SERVICE_HOST 或 /var/run/secrets/kubernetes.io
    CgroupV2      bool    // cgroup v2
    DinD          bool    // Docker-in-Docker（嵌套容器）
    Caps          uint64  // 可用 capabilities 位图
    NoGating      bool    // 命令行 --no-gating
}
```

### 3.2 Prereq 位

```go
const (
    PrNone      Prereq = 0
    PrLinux     Prereq = 1 << iota
    PrHost                              // 在宿主机（非容器）
    PrContainer                         // 在容器内
    PrK8s                               // 处于 K8s Pod
    PrInitPID                           // PID=1
    PrSystemd                           // systemd 为 init
    PrCgroupV2                          // cgroup v2
    PrDinD                              // Docker-in-Docker
    PrCapSysAdmin                       // 持有 CAP_SYS_ADMIN
    // ...
)
```

### 3.3 工作流程

```
RunAllChecks()
  └─ detectEnv()                 // 只执行一次，填充 Env（含 9 项探测）
       └─ for _, check := range registry:
              if !check.Prereqs.satisfied(env) → SKIP with Reason
              else → check.Run(env)
```

**当你新增 `Env` 字段时：**
- 必须配套一个 `PrXxx` 位
- 必须在 `detectEnv()` 中设置默认值（不要让布尔型零值意外“通过”门控）
- 必须在 CLI 的 `--no-gating` 下全部视为 true（已由 `Prereqs.satisfied` 统一处理，不要手动覆盖）

---

## 4. 编译 / 交叉编译约束（修改构建相关必须遵守）

- 入口：`./cmd/cdk`。
- Go 版本下限：**Go 1.16**。避免使用 1.18+ generics / 1.21+ slices 包等若不确定是否允许，请查 `go.mod`。
- memfd 相关代码按架构拆分文件：`json_memfd_linux_{386,amd64,arm,arm64}.go`，每文件内只定义 `sysMemfdCreate` 常量。
- syscall 号按架构拆分：`sysnr_linux_{386,amd64,arm,arm64}.go` + `sysnr_notlinux.go` 桩。
- **若修改会导致 `go vet ./...` 或 `GOARCH=arm64 go build ./...` 失败，不得合入。**

---

## 5. 关于测试文件

- **MR 中不要包含任何 `_test.go` 文件或 `test/` 目录内容。** 该仓库要求单测单独提交流程与人工复核。
- 本地开发仍建议编写测试，但提交 MR 前请执行：
  ```bash
  git status --short | awk '$1 ~ /A/ && $2 ~ /_test\.go|^test\// {print $2}' | xargs git rm --cached
  ```

---

## 6. 常见改动错误（提交前必查）

| 错误模式 | 后果 | 正确做法 |
|---|---|---|
| 在 `Run(env)` 里写 `/tmp/cdk-scan-*` 临时文件 | 违反只读原则 | 用 `bytes.Buffer`；必须落盘时显式用 `PrTempWritable` Prereq + 默认 gated |
| `switch runtime.GOOS { case "linux": ... default: panic(...) }` | 非 Linux 构建时 CI 炸 | 用 build tag；非 Linux 写 `//go:build !linux` 的空返回桩 |
| 新增 `Txxx` 未更新 `README-AUDIT-COUNTERS.md` | 报告/审计缺失映射 | 同步追加，包含 T ID、Name、Category、默认 Severity |
| 在 `detectEnv()` 里执行有副作用的探测 | 污染前置状态 | 所有探测只读；任何需要主动调用的请放到独立 `Run` Check + PrActive |
| 把 JSON 序列化错误当 `panic` | 线上报告丢失 | `LevelInfo + Detail: "<encode err: xxx>"` |
| 修改报告 schema 但不改 `HUMAN_README.md` 对应说明 | 人类用户误解 | §4 的表格必须同步；`README-AUDIT-COUNTERS.md` 必须同步 |

---

## 7. 面向人类的文档（引用链接）

修改了行为、接口、检查项编号或报告 schema 后，**必须同步更新面向人类的文档**：

- 👉 **[HUMAN_README.md](./HUMAN_README.md)** — 用户使用说明、目录速览、门控机制介绍、MR 说明
- 👉 **[README-AUDIT-COUNTERS.md](./README-AUDIT-COUNTERS.md)** — T001–T057 检查项总表（新增/重编号时必改）

---

*当审查 / 重构过程中出现本文件与 `HUMAN_README.md` 描述不一致的地方，以 `HUMAN_README.md` + 代码本身的事实为准，并请及时修正本文件。*
