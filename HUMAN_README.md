# HUMAN_README — Container Defense Kit (CDK)

> 面向人类的说明文档。如果你是 AI / LLM / Agent，请看 [`AI_README.md`](./AI_README.md)。

---

## 这是什么

**CDK（Container Defense Kit）** 是一个面向**容器与 Kubernetes 环境**的隔离基线审计工具。它在容器内部或宿主机上以只读方式执行一系列检查项，输出隔离能力、安全基线和可被利用面的评估报告。

- 合规基线审计（capabilities / LSM / seccomp / user-ns 等）
- 运行时指纹与内核加固状态评估
- 凭据暴露面扫描（环境变量、挂载卷、元数据服务侧通道）
- K8s 组件可见性与 RBAC / ServiceAccount 暴露面审核

---

## 快速开始

### 1. 编译

需要 Go 1.16+。推荐交叉编译为目标 Linux 平台：

```bash
# linux/amd64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk

# linux/arm64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o cdk-arm64 ./cmd/cdk
```

### 2. 运行

```bash
# 在目标容器内执行全量评估，输出 JSON 报告
./cdk evaluate --json --report report.json

# 只看高风险项
./cdk evaluate --format summary
```

### 3. 解释结果

检查项编号形如 `T001`–`T057`，在报告 JSON 中每一项包含：

| 字段 | 含义 |
|---|---|
| `id` | 检查项编号（T001 起） |
| `info.name` | 检查项名称 |
| `result.level` | `PASS` / `INFO` / `WARN` / `FAIL` / `SKIP` |
| `result.detail` | 结构化发现 |
| `result.reason` | SKIP 时说明原因（通常由前置门控触发） |

新增的 T45–T57 检测项在 [`README-AUDIT-COUNTERS.md`](./README-AUDIT-COUNTERS.md) 有完整列表与释义。

---

## 目录速览

```
CDK/
├── cmd/cdk/                       # CLI 入口
├── pkg/
│   ├── evaluate/                  # 检查项实现（T001–T057）
│   │   ├── env.go / Env 结构      # 前置门控：9 项环境探测
│   │   ├── available*.go          # capabilities、syscall 基线
│   │   ├── apparmor_deep_linux.go # T45 类 LSM 深度检查
│   │   ├── seccomp_*.go           # seccomp / syscall 过滤分析
│   │   ├── kernel_*.go            # 内核硬ening / lockdown
│   │   ├── ebpf_recon_linux.go    # eBPF 暴露面
│   │   └── ...
│   ├── audit/                     # 凭据/文件扫描
│   ├── cli/                       # 参数解析
│   ├── plugin/                    # 插件接口
│   ├── tool/                      # 内部工具（探测、网络等）
│   └── util/
├── docs/superpowers/plans/        # 设计与变更记录
├── AI_README.md                   # 给 AI / Agent 的规范说明
├── HUMAN_README.md                # ⬅ 你现在在这里
├── README.md                      # 原版简短 README
└── README-AUDIT-COUNTERS.md       # T001–T057 清单与等级映射
```

---

## 前置门控（Preflight Gating）

本分支引入了环境前置门控机制：**会在评估前一次性探测 9 项环境信号**（内核版本、是否容器、是否 init PID、是否 systemd、是否 K8s、CPU 架构、cgroup 版本、是否 Docker-in-Docker、可用 capabilities）。每个 `Check` 通过 `Prereqs` 字段声明依赖，不满足时直接 `SKIP` 并给出原因，减少误报和无效探测。

相关文件：

- `pkg/evaluate/env.go` — `Env` 结构、`Prereq` 常量、`Check.Prereqs`
- `pkg/evaluate/env_test.go` — 门控单测（此 MR 未包含，见本地仓库）
- CLI：`--no-gating` 关闭所有门控（调试用）

---

## 关于这份 MR 的改动

| Commit | 主题 |
|---|---|
| `f2b3a7f` | fix(evaluate): 6 bug fixes from T39-T43 + memfd + cross-build |
| `0fd62fc` | feat(evaluate): 新增 13 个检测项（T45–T57） |
| `b59bc1e` | Gate active security probes by environment（按环境门控） |
| `a2a5bd2` | Add Docker matrix for scan gating（扫描门控矩阵配套的 `.gitignore` 项） |

---

## 合规提示

CDK 只允许在**已书面授权**的环境使用。生成的报告可能包含凭据摘要、网络结构、内核参数等敏感信息，请按企业数据分级策略保管和销毁。
