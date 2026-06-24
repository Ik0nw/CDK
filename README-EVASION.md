# CDK 编译与功能

## 编译

标准 Go 模块，入口 `./cmd/cdk`，无构建脚本，用 `go build` 即可（需 Go 1.16+）。

### 完整版（最常用）

交叉编译，无需额外工具链：

```bash
# linux / amd64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk

# linux / arm64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o cdk ./cmd/cdk
```

- `-trimpath` 去掉编译机路径
- `-ldflags="-s -w"` 去符号表与调试信息，缩小体积
- `-o cdk` 输出文件名（可改成无特征名，如 `-o udevd`）

产物约 11MB，静态链接、零 OS 依赖。

### Thin 版（更小，约 2MB）

短生命周期容器（serverless）用：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -tags thin -o cdk_thin ./cmd/cdk
```

### 自定义裁剪

按需叠加 `no_*` tag 去掉指定 exploit，例如只留 cgroup 逃逸、去掉 k8s 类：

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -tags "no_k no_etcd_get_k no_kubelet_exec no_docker_sock_pwn no_containerd_shim_pwn" \
  -o cdk ./cmd/cdk
```

可用的 `no_*` tag：

```
no_abuse_unpriv_userns   no_cap_dac_read_search   no_check_ptrace
no_containerd_shim_pwn   no_deploy_webshell       no_docker_api_pwn
no_docker_runc           no_docker_sock_check     no_docker_sock_pwn
no_etcd_get_k            no_file_scan             no_image_registry_brute
no_istio_check           no_k                     no_kubelet_exec
no_kubelet_var_log_escape  no_lxcfs_rw            no_mount_cgroup
no_mount_device          no_mount_procfs          no_rewrite_cgroup_devices
no_reverse_shell         no_service_probe
```

### UPX 压缩（最小）

```bash
upx --best --ultra-brute cdk
```

> UPX 壳本身是独立检测特征，很多 EDR 会标记加壳 ELF，追求不被检测时不建议用。

---

## 功能

三大模块，命令 `cdk <模块> ...`。

### Evaluate 评估 — `cdk eva`

扫描当前容器 / K8s 环境，给出可利用面和推荐 exploit。

```bash
cdk eva           # 基础
cdk eva --full    # 全量
```

### Exploit 利用 — `cdk run <name> [args]`

容器逃逸：

| 命令 | 说明 |
|---|---|
| `cdk run mount-cgroup "<cmd>"` | cgroup v1 release_agent 逃逸（privileged 容器） |
| `cdk run rewrite-cgroup-devices` | 重写 cgroup devices.allow + mknod 逃逸 |
| `cdk run cgroup2-ebpf-bypass` | cgroup v2 eBPF 设备控制器绕过 |
| `cdk run lxcfs-rw` | lxcfs rw 下 mknod 逃逸 |
| `cdk run lxcfs-rw-cgroup "<cmd>"` | lxcfs rw 下 cgroup release_agent 逃逸 |
| `cdk run mount-procfs` | procfs 逃逸 |
| `cdk run abuse-unpriv-userns` | 滥用非特权 user namespace |
| `cdk run cap-dac-read-search` | CAP_DAC_READ_SEARCH 读宿主文件 |
| `cdk run containerd-shim-pwn` | containerd shim 利用 |
| `cdk run docker-runc-check` / `docker-runc-pwn` | docker/runc 检查与利用 |
| `cdk run docker-sock-check` / `docker-sock-pwn` | docker.sock 检查与利用 |
| `cdk run docker-api-pwn` | docker HTTP API 利用 |
| `cdk run kubelet-var-log-escape` | kubelet var/log 逃逸 |

K8s 利用：

| 命令 | 说明 |
|---|---|
| `cdk run k8s-backdoor-daemonset` | 部署后门 DaemonSet |
| `cdk run k8s-shadow-apiserver` | 部署影子 apiserver |
| `cdk run k8s-cronjob` | 部署 CronJob |
| `cdk run k8s-mitm-clusterip` | K8s MITM（CVE-2020-8554） |
| `cdk run kubelet-exec` | kubelet exec 利用 |
| `cdk run etcd-get-k` | 枚举 etcd keys |

其他：

| 命令 | 说明 |
|---|---|
| `cdk run reverse-shell` | 反弹 shell |
| `cdk run deploy-webshell` | 部署 webshell |
| `cdk run check-ptrace` | ptrace 检查 |
| `cdk run service-probe` | 服务探测 |

### Tool 工具 — `cdk <tool>`

```bash
cdk nc [options]       # TCP 隧道
cdk ps                 # 进程信息
cdk netstat            # 类似 netstat -antup
cdk ifconfig           # 网络信息
cdk ed <file>          # 编辑文件
cdk probe              # IP/端口扫描
cdk kcurl <uri> [data] # 请求 K8s api-server
cdk dcurl <uri> [data] # 请求 Docker HTTP API
cdk ucurl <socket> <uri> [data]  # 请求 Docker Unix Socket
cdk ectl               # 未授权枚举 etcd keys
```

### 通用

```bash
cdk -v                 # 版本
cdk                    # 查看全部命令
```
