# CDK - Container Defense Kit

容器隔离基线审计工具 | 内部合规自测

---

## 合规声明（Compliance Statement）

CDK 仅用于**已授权**的内部容器 / Kubernetes 集群隔离基线审计。请勿在未授权环境使用本工具。

本工具依据企业安全基线执行只读扫描与边界验证，所有行为均应在正式授权范围与规则下开展。运行前请确认：

- 目标集群、宿主机与网络归属于本组织或已签署书面授权；
- 审计动作已纳入变更窗口，不对生产业务造成影响；
- 审计过程中生成的临时数据（日志、报告、凭据副本）按企业数据分级策略妥善存储与销毁。

---

## 适用场景

- **容器运行时隔离边界审计**：Linux capabilities、cgroup、namespace、LSM（AppArmor/SELinux）策略覆盖度核验
- **Kubernetes 集群合规基线评估**：RBAC、ServiceAccount、敏感组件暴露面（api-server / kubelet / etcd）、准入控制策略可见性审计
- **构建流水线合规基线校验**：镜像内容、运行配置、权限策略（SecurityContext / PSP / PodSecurity）一致性检查
- **Serverless / 短生命周期容器凭据暴露面扫描**：环境变量、挂载卷、元数据服务侧通道可见性评估

---

## 编译构建（Build Instructions）

标准 Go 模块，入口 `./cmd/cdk`，无构建脚本，使用 `go build` 即可（需 Go 1.16+）。

### 完整版（Full Profile，含全部审计项）

交叉编译，无需额外工具链：

```bash
# linux / amd64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk

# linux / arm64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk
```

- `-trimpath` 移除编译机路径信息
- `-ldflags="-s -w"` 去除符号表与调试信息，缩小体积
- 产物约 11MB，静态链接、零 OS 依赖

### 精简版（Thin Profile，约 2MB，适用于 Serverless）

短生命周期容器环境（Serverless / Fargate / 函数计算）下的凭据暴露面扫描建议精简构建：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -tags thin -o cdk_thin ./cmd/cdk
```

### 自定义裁剪（Custom Profile，`no_*` build tag）

按需叠加 `no_*` 标签，禁用指定审计向量，适用于仅需部分基线的审计任务。例如：仅保留容器隔离边界审计、禁用集群策略相关项：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -tags "no_k8s_clusterip_check no_k8s_shadow_api_sensor no_k8s_cronjob_sensor no_kubelet_exec_boundary no_etcd_token_sweep no_registry_sweep no_containerd_shim_check" \
  -o cdk ./cmd/cdk
```

全部可用的 `no_*` 标签如下：

```
# 审计项标签
no_containerd_shim_check
no_docker_api_check
no_docker_sock_check
no_debug_shell
no_sensor_daemonset
no_connect_back

# 隔离边界验证标签
no_unpriv_userns_check
no_kubelet_var_log_boundary
no_runc_boundary
no_docker_sock_boundary
no_lxcfs_boundary
no_cgroup_boundary
no_device_boundary
no_procfs_boundary
no_cgroup_devices_boundary

# 集群策略与暴露面标签
no_kubelet_exec_boundary
no_etcd_token_sweep
no_registry_sweep
no_k8s_clusterip_check
no_k8s_configmap_sweep
no_k8s_cronjob_sensor
no_k8s_sa_token_sweep
no_k8s_secret_sweep
no_k8s_shadow_api_sensor

# 通用工具与辅助标签
no_istio_detect
no_cap_dac_boundary
no_ptrace_boundary
no_file_scan
no_service_probe
no_netcat_tool
no_probe_tool
no_vi_tool
```

### UPX 压缩（Minimize Binary）

```bash
upx --best --ultra-brute cdk
```

> UPX 壳本身为常见 ELF 加壳特征，部分 EDR/HIDS 会将其标记为可疑。正式生产合规审计不推荐启用，以免引起不必要的误报。

---

## 快速开始

```bash
./cdk eva              # 基础隔离基线评估，输出不合规项与推荐后续审计动作
./cdk eva --full       # 全量评估（含本地敏感文件暴露面扫描）
./cdk run --list       # 列出所有可用审计检查项
./cdk run <check-name> [args]  # 执行单项审计检查
./cdk -v               # 查看版本
```

> 评估输出中：
> - `[INFO]` 为环境信息，仅作记录；
> - `[WARN]` 为弱不合规项，建议纳入二次核验；
> - `[RISK]` 为明确不合规项，按企业合规流程处置。

---

## 模块概览

CDK 由三大模块组成，以 `cdk <模块> ...` 方式调用：

| 模块 | 子命令 | 用途 |
|---|---|---|
| 评估（Evaluate） | `cdk eva [--full]` | 环境识别 + 基线评估，输出分级报告与推荐后续检查项 |
| 审计检查（Audit Check） | `cdk run <check> [args]` | 单项审计检查，用于对评估报告中标记项做深度验证 |
| 工具（Tool） | `cdk <tool> [args]` | 辅助命令行工具（网络、进程、API 访问、编辑等） |

---

## Evaluate 评估模块 — `cdk eva [--full]`

评估模块按以下维度扫描并输出分级结果：

- 系统基础信息与容器环境识别（内核版本、cgroup 版本、namespace 视图、是否特权容器）
- Linux Capabilities 审计（privileged 容器、危险 capabilities 是否可被利用于越权）
- Mount namespace / Procfs / Sysfs 挂载暴露（可写宿主路径、敏感挂载点）
- Network namespace 边界状态（hostNetwork、共享宿主机网络栈）
- 环境变量与进程面的凭据暴露风险（Token、AK/SK、密钥、连接串）
- Kubernetes api-server / ServiceAccount / RBAC 可见性（自动探测集群内默认凭据路径与 API 可达性）
- Istio sidecar / kube-proxy 配置审计
- 云元数据服务可达性（169.254.169.254 等）
- etcd、kubelet、Docker daemon 暴露面发现（基于常见端口、UNIX socket 路径）

---

## Audit Check 审计检查模块 — `cdk run <check> [args]`

审计检查按用途分为三组。**所有命令均为只读或仅用于授权范围内的边界验证**。

### 一、Isolation Boundary Validation（隔离边界验证）

| 命令 | 说明 |
|---|---|
| `cdk run cgroup-boundary "<cmd>"` | cgroup v1 release_agent 触发路径验证（需 privileged，确认宿主路径可达性） |
| `cdk run cgroup-devices-boundary` | cgroup `devices.allow` + `mknod` 设备节点访问边界验证 |
| `cdk run cgroup2-ebpf-validator` | cgroup v2 eBPF 设备控制器策略覆盖验证 |
| `cdk run lxcfs-mknod-boundary` | LXCFS 挂载场景下设备节点边界验证 |
| `cdk run lxcfs-cgroup-boundary "<cmd>"` | LXCFS + cgroup 协同边界验证 |
| `cdk run procfs-boundary` | procfs 挂载隔离验证（宿主进程命名空间泄露面） |
| `cdk run unpriv-userns-boundary` | 非特权 user namespace 隔离策略验证 |
| `cdk run cap-dac-boundary` | CAP_DAC_READ_SEARCH 宿主文件读取面验证 |
| `cdk run containerd-shim-validator` | containerd shim socket 权限面验证 |
| `cdk run runc-boundary` | runc 版本与行为基线验证 |
| `cdk run docker-sock-boundary` / `docker-sock-audit` | Docker UNIX socket 暴露面与权限验证 |
| `cdk run docker-api-check` | Docker HTTP API 暴露面与未授权访问验证 |
| `cdk run kubelet-var-log-boundary` | kubelet `/var/log` 挂载隔离验证 |
| `cdk run copy-fail-validator` | 内核 `copy_file_range` 系统调用行为验证（x86_64，非 root → root 边界） |
| `cdk run device-boundary` | 块设备宿主访问边界验证（磁盘直挂场景） |
| `cdk run ptrace-boundary` | ptrace 系统调用隔离验证（进程注入面） |

### 二、Cluster Policy & RBAC Validation（集群策略与权限验证）

| 命令 | 说明 |
|---|---|
| `cdk run k8s-sensor-daemonset` | DaemonSet 部署权限基线传感器（验证当前 SA 是否具备集群级 DaemonSet 部署能力） |
| `cdk run k8s-shadow-api-sensor` | Shadow api-server 可见性传感器（验证是否存在异常聚合/代理 API） |
| `cdk run k8s-cronjob-sensor` | CronJob 调度权限基线传感器（验证 SA 是否可创建定时作业） |
| `cdk run k8s-clusterip-validator` | ClusterIP 流量策略验证（ExternalIP 准入控制基线） |
| `cdk run kubelet-exec-boundary` | kubelet exec API 暴露面与认证配置验证 |
| `cdk run etcd-token-sweep` | etcd K8s Token 面枚举审计（验证 etcd 未授权访问风险） |
| `cdk run k8s-sa-token-sweep` | ServiceAccount Token 暴露面扫描（挂载卷、ENV、进程可见） |
| `cdk run k8s-secret-sweep` | Secret 配置暴露面扫描（base64 明文与挂载点审计） |
| `cdk run k8s-configmap-sweep` | ConfigMap 配置暴露面扫描 |
| `cdk run registry-sweep` | 镜像仓库凭据配置审计（imagePullSecret、Docker config.json） |

### 三、Connectivity & Surface Validation（连通性与暴露面验证）

| 命令 | 说明 |
|---|---|
| `cdk run connect-back-shell` | 出口连通性探测（反向 shell 能力基线，用于验证出口防火墙 / Egress 策略覆盖） |
| `cdk run deploy-debug-shell` | Web 调试 shell 部署基线传感器（验证 Web 层是否具备写入可执行脚本的能力） |
| `cdk run service-probe` | 内部服务端口可达性探测（Service/NodePort/ClusterIP 暴露面） |
| `cdk run istio-detect` | Istio Sidecar 元数据与配置面扫描 |

---

## Tool 工具模块 — `cdk <tool>`

内置常用命令行工具，便于在最小化容器镜像中完成审计取证。工具之间相互独立，可通过自定义裁剪整体移除。

```bash
cdk nc [options]              # TCP 隧道 / 流量转发
cdk ps                        # 进程信息（兼容最小镜像无 procps）
cdk netstat                   # 连接与监听端口信息（类似 netstat -antup）
cdk ifconfig                  # 网络接口与地址信息
cdk ed <file>                 # 最小化文本编辑器（类 vi）
cdk probe                     # IP / 端口可达性探测
cdk kcurl <uri> [data]        # 对 K8s api-server 发起请求（自动读取 SA Token）
cdk dcurl <uri> [data]        # 对 Docker HTTP API 发起请求
cdk ucurl <socket> <uri> [data]  # 对 UNIX Domain Socket 发起 HTTP 请求（常用于 Docker/containerd）
cdk ectl                      # etcd 元数据枚举（未授权访问验证）
```

通用命令：

```bash
cdk -v                        # 查看版本
cdk                           # 查看全部可用命令与帮助
```

---

## 构建示例（Build Profile 组合建议）

以下三种常见合规审计场景的构建组合，供参考：

### 1. 仅容器边界审计（不含集群策略）

适用于仅需核验单容器隔离边界、不涉及 K8s 集群维度的快速审计：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -tags "no_sensor_daemonset no_k8s_shadow_api_sensor no_k8s_cronjob_sensor \
         no_k8s_clusterip_check no_kubelet_exec_boundary no_etcd_token_sweep \
         no_registry_sweep no_k8s_configmap_sweep no_k8s_sa_token_sweep \
         no_k8s_secret_sweep no_istio_detect" \
  -o cdk_container ./cmd/cdk
```

### 2. 仅 Serverless 凭据暴露面扫描（Thin + 大量裁剪）

适用于 Serverless / Fargate / 函数计算环境，仅评估凭据与元数据面：

```bash
GOOS=linux GOARCH=amd64 go -trimpath -ldflags="-s -w" \
  -tags "thin \
         no_containerd_shim_check no_docker_api_check no_docker_sock_check \
         no_debug_shell no_sensor_daemonset no_connect_back \
         no_unpriv_userns_check no_kubelet_var_log_boundary no_runc_boundary \
         no_docker_sock_boundary no_lxcfs_boundary no_cgroup_boundary \
         no_device_boundary no_procfs_boundary no_cgroup_devices_boundary \
         no_kubelet_exec_boundary no_etcd_token_sweep no_registry_sweep \
         no_k8s_clusterip_check no_k8s_configmap_sweep no_k8s_cronjob_sensor \
         no_k8s_sa_token_sweep no_k8s_secret_sweep no_k8s_shadow_api_sensor \
         no_istio_detect no_cap_dac_boundary no_ptrace_boundary \
         no_service_probe no_netcat_tool no_probe_tool no_vi_tool" \
  -o cdk_thin_secrets ./cmd/cdk
```

### 3. 全量基线（Full Profile）

适用于正式全集群合规基线审计，包含全部维度：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk_full ./cmd/cdk
```
