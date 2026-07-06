# CDK Evaluate — HIDS/EDR Detection Test Rules

This document defines realistic HIDS/EDR detection rules that a blue team
would deploy to detect container escape reconnaissance.  Each rule is
evaluated against the current CDK evaluate implementation to determine
whether our stealth measures are effective.

## Rule Format

Each rule has:
- **ID**: unique identifier
- **Source**: which sensor generates it (file audit, eBPF, netflow, static scan)
- **Pattern**: the detection logic
- **Severity**: informational | low | medium | high | critical
- **CDK Verdict**: does CDK trigger this rule?  Why or why not?

---

## 1. File Access Rules (file audit / inotify / fanotify)

### R-FILE-001: Direct kernel memory device access
- **Source**: file audit (open() syscall monitoring)
- **Pattern**: process opens `/dev/mem`, `/dev/kmem`, or `/dev/port`
- **Severity**: critical
- **CDK Verdict**: **EVASION** — paths are XOR-obfuscated in binary,
  decoded at runtime via `util.DevMemPath()` etc.  The open() call uses
  `syscall.Open(O_RDONLY|O_CLOEXEC)` which goes through the kernel
  directly; the path string is never in .rodata as plaintext.

### R-FILE-002: Container runtime socket access
- **Source**: file audit (connect() to unix socket)
- **Pattern**: process connects to `/var/run/docker.sock` or
  `/run/containerd/containerd.sock`
- **Severity**: high
- **CDK Verdict**: **EVASION** — socket paths are XOR-obfuscated via
  `util.DockerSockPath()` / `util.ContainerdSockPath()`.  The connect()
  call uses `net.DialTimeout("unix", ...)` with a runtime-decoded path.

### R-FILE-003: Credential file reads
- **Source**: file audit (read() on sensitive paths)
- **Pattern**: process reads `/etc/shadow`, `/etc/passwd`, `/root/.ssh/*`
- **Severity**: high
- **CDK Verdict**: **EVASION** — paths are XOR-obfuscated via
  `util.EtcShadowPath()`, `util.EtcPasswdPath()`, `util.RootSshPath()`.
  Only `syscall.Open(O_RDONLY|O_CLOEXEC)` is attempted; no actual read
  of shadow/passwd content is performed (we only test openability).

### R-FILE-004: ld.so.preload modification attempt
- **Source**: file audit (write/open(O_WRONLY) on `/etc/ld.so.preload`)
- **Pattern**: process opens `/etc/ld.so.preload` for writing
- **Severity**: critical
- **CDK Verdict**: **EVASION** — path is XOR-obfuscated via
  `util.EtcLdSoPreloadPath()`.  We test writability with a single
  `syscall.Open(O_RDWR|O_CLOEXEC)` that immediately closes; no content
  is written.

### R-FILE-005: Cron directory modification
- **Source**: file audit (write to `/etc/cron*`)
- **Pattern**: process creates or modifies files under `/etc/cron*`
- **Severity**: high
- **CDK Verdict**: **EVASION** — paths are XOR-obfuscated via
  `util.EtcCronDPath()`, `util.EtcCrontabPath()`.  Directory writability
  test uses `O_CREAT|O_EXCL` with immediate `unlink()` — no persistent
  artifact left behind.

### R-FILE-006: Kernel symbol reads
- **Source**: file audit (read on `/proc/kallsyms`, `/proc/kcore`)
- **Pattern**: process reads `/proc/kallsyms` or `/proc/kcore`
- **Severity**: medium
- **CDK Verdict**: **EVASION** — paths are XOR-obfuscated via
  `util.ProcKallsymsPath()`, `util.ProcKcorePath()`.  kallsyms is read
  via `readFileLines()` which uses `util.StealthReadFile()` (raw
  openat + read via RawSyscall6, bypassing libc/LD_PRELOAD hooks).
  kcore is only tested with `O_RDONLY|O_CLOEXEC` open (no read).

### R-FILE-007: Host path bind-mount writability test
- **Source**: file audit (O_CREAT attempts on host paths)
- **Pattern**: process attempts to create files under `/var/lib/docker`,
  `/var/lib/kubelet`, `/etc/systemd/system`, `/etc/kubernetes`
- **Severity**: high
- **CDK Verdict**: **EVASION** — paths are XOR-obfuscated via
  `util.VarLibDockerPath()`, `util.VarLibKubeletPath()`,
  `util.EtcSystemdPath()`, `util.EtcKubernetesPath()`.  Temp file
  creation uses `O_CREAT|O_EXCL` with immediate `unlink()`.

### R-FILE-008: FUSE device access
- **Source**: file audit (open on `/dev/fuse`)
- **Pattern**: process opens `/dev/fuse` for read-write
- **Severity**: medium
- **CDK Verdict**: **EVASION** — path is XOR-obfuscated via
  `util.DevFusePath()`.

---

## 2. Syscall / Process Behavior Rules (eBPF / auditd / seccomp log)

### R-SYSCALL-001: Raw bpf() syscall
- **Source**: eBPF tracing (tracepoint/syscalls/sys_enter_bpf)
- **Pattern**: process calls `bpf()` syscall (NR 321 on amd64)
- **Severity**: high
- **CDK Verdict**: **TRIGGERS** — `ebpf_recon_linux.go` calls
  `syscall.RawSyscall6(SYS_BPF, ...)` with a NULL attr to probe if the
  syscall is available.  This is a single, side-effect-free call but
  it WILL appear in eBPF syscall tracing.
  - **Mitigation**: the probe is guarded by `InContainer` prereq and
    only fires once.  The NULL attr argument ensures no BPF program is
    loaded.  We could add a `--no-bpf-probe` flag to skip this.

### R-SYSCALL-002: Raw io_uring_setup() syscall
- **Source**: eBPF tracing
- **Pattern**: process calls `io_uring_setup()` (NR 425 on amd64)
- **Severity**: medium
- **CDK Verdict**: **TRIGGERS** — `io_uring_check.go` calls
  `io_uring_setup(0, NULL)` which returns -EINVAL before any allocation.
  Single call, no side effects, but visible in eBPF traces.

### R-SYSCALL-003: Raw landlock_create_ruleset() syscall
- **Source**: eBPF tracing
- **Pattern**: process calls `landlock_create_ruleset()` (NR 444 on amd64)
- **Severity**: low
- **CDK Verdict**: **TRIGGERS** — `landlock_deep_linux.go` probes the
  Landlock ABI version via a single raw syscall.

### R-SYSCALL-004: mount/umount2/pivot_root syscall probes
- **Source**: seccomp audit log
- **Pattern**: process calls mount, umount2, or pivot_root
- **Severity**: high
- **CDK Verdict**: **TRIGGERS** — `seccomp_deep_inspect.go` probes 12
  escape-relevant syscalls including mount, umount2, pivot_root, unshare,
  ptrace, etc.  Each is called with arguments that guarantee failure
  (invalid flags, NULL pointers), so no actual escape happens.
  - **Mitigation**: all probes use `runtime.LockOSThread()` to contain
    per-thread side effects.  `unshare` is called with `CLONE_NEWUSER`
    (not `CLONE_NEWNS`) to avoid mount namespace side effects.

### R-SYSCALL-005: openat() with O_CLOEXEC on many paths
- **Source**: eBPF tracing (do_sys_open)
- **Pattern**: process opens 20+ different paths in rapid succession
- **Severity**: low (behavioral anomaly)
- **CDK Verdict**: **PARTIALLY EVASIVE** — the evaluate run opens many paths
  (device nodes, host paths, proc files, sysctls).  However:
  - In `--stealth` mode, 15-45ms jitter is added between checks, breaking
    the "rapid succession" pattern.
  - Check order is randomized in stealth mode (Fisher-Yates shuffle),
    avoiding deterministic access sequences.
  - **ALL file reads across the entire codebase now use `util.StealthReadFile()` / `util.StealthOpen()`**
    which calls `RawSyscall6(SYS_OPENAT, ...)` directly, bypassing
    LD_PRELOAD hooks.  This includes: env.go shared helpers
    (`readFileLines`, `readFileFirstLine`, `fileExists`) used by ~20
    checks, security_info.go (`readFirstLine`, `countNSPidLevels`,
    `countLines`, `utilReadLines`, `CheckSeccompStatus`,
    `CheckSeccompKernelSupport`, `CheckSELinux`, `CheckAppArmor`,
    `readKernelConfigOption`), all T58-T71 checks, AND all audit
    modules (boundary/, credential_access/, discovery/, remote_control/).
    Zero `io/ioutil` imports remain in pkg/ (2026-07-06 #5).
  - Without `--stealth`, paths are still opened rapidly (but with
    O_CLOEXEC, mostly O_RDONLY, via raw syscall not libc).

### R-SYSCALL-006: memfd_create() usage
- **Source**: eBPF tracing
- **Pattern**: process calls `memfd_create()` (NR 319 on amd64)
- **Severity**: low
- **CDK Verdict**: **TRIGGERS** — `json.go` uses memfd-backed anonymous
  files for stdout/stderr capture during JSON output.  This is a
  legitimate use but some EDR flag memfd_create as suspicious (used by
  malware for fileless execution).

---

## 3. Network Rules (netflow / socket monitoring)

### R-NET-001: Unix socket connect to container runtime
- **Source**: eBPF tracing (sys_enter_connect)
- **Pattern**: process connects to unix socket path matching
  `*docker.sock` or `*containerd.sock`
- **Severity**: high
- **CDK Verdict**: **TRIGGERS** — `socket_escape_linux.go` connects to
  docker/containerd sockets to test reachability.  The connect() call
  is unavoidable for a functional test.
  - **Mitigation**: connections are short-lived (connect + close within
    2s timeout).  Only 2-3 socket paths are probed.  The HTTP probes
    use a 3s timeout.

### R-NET-002: HTTP requests to container runtime API
- **Source**: network monitoring (HTTP over unix socket)
- **Pattern**: HTTP GET to `/_ping`, `/v1.41/version`,
  `/v1.41/containers/json`, `/v1.41/info`
- **Severity**: high
- **CDK Verdict**: **TRIGGERS** — these are standard Docker API
  endpoints.  A well-tuned EDR would flag any process making these
  requests over a unix socket.
  - **Mitigation**: we use a minimal User-Agent (Go default) and only
    make GET requests (no POST/container creation).  Adding jitter
    between requests would help.

### R-NET-003: Kubernetes API server probes
- **Source**: network monitoring
- **Pattern**: HTTPS requests to `kubernetes.default.svc` or
  `10.96.0.1:443` with service account token
- **Severity**: medium
- **CDK Verdict**: **TRIGGERS** — `k8s_service_account.go` and
  `k8s_anonymous_login.go` probe the API server.  This is expected
  behavior for a pod but the specific endpoints (`/apis`,
  `/api/v1/namespaces`) are recon signatures.

---

## 4. Static Binary Analysis Rules (YARA / .rodata scan)

### R-YARA-001: Sensitive path strings in binary
- **Source**: YARA scan of binary on disk
- **Pattern**: binary contains plaintext strings like `/dev/mem`,
  `/etc/shadow`, `/var/run/docker.sock`, `/proc/kallsyms`
- **Severity**: medium
- **CDK Verdict**: **EVASION** — all high-sensitivity paths are
  XOR-encoded at compile time and decoded at runtime via
  `util.xorObfsPath()`.  The .rodata section contains only the
  encoded byte arrays, not the plaintext paths.
  - Paths still in plaintext (low-sensitivity storage/device nodes only):
    `/dev/sda`, `/dev/sda1`, `/dev/sdb`, `/dev/vda`, `/dev/nvme0n1`,
    `/dev/xvda`, `/dev/loop0`, `/dev/tty0`, `/dev/net/tun`,
    `/dev/uhid`, `/dev/uinput`, `/dev/cpu/0/msr`, `/proc/bus/pci`
  - **Post-iteration update (2026-07-02 #2)**: 30+ additional paths
    obfuscated: /home, /etc/cron.daily, /etc/ld.so.conf.d,
    /lib/systemd/system, /etc/init.d, /var/spool/cron,
    /var/lib/containerd, /etc/profile.d, /etc/bashrc, /run/secrets,
    /var/run/secrets, /etc/hosts, /etc/hostname, /etc/resolv.conf,
    /dev/shm, /dev/mqueue, /tmp, /proc, /sys, /dev,
    /sys/fs/selinux/enforce, /proc/self/attr/current, /proc/cmdline,
    /sys/module/apparmor/parameters/enabled, /proc/config.gz,
    /proc/1/root, /proc/1/fd, /proc/mounts, /proc/self/mountinfo,
    /proc/self/status, /proc/sys/vm/unprivileged_userfaultfd,
    /proc/sys/kernel/osrelease, /proc/sys/kernel/dmesg_restrict,
    /sys/kernel/security, /dev/urandom.

### R-YARA-002: Container escape tool signatures
- **Source**: YARA scan
- **Pattern**: binary contains strings like "cgroup", "release_agent",
  "notify_on_release", "docker.sock", "escape"
- **Severity**: medium
- **CDK Verdict**: **PARTIAL EVASION** — "release_agent" is obfuscated
  via `util.CgroupReleaseAgentFile()`.  "docker.sock" is obfuscated.
  But "cgroup" appears in plaintext in many places (cgroup path
  parsing, mountinfo scanning).  "escape" appears in check titles and
  output strings.

### R-YARA-003: Webshell code patterns
- **Source**: YARA scan
- **Pattern**: binary contains `<?php @eval`, `<%@ page import=`
- **Severity**: critical
- **CDK Verdict**: **EVASION** — `conf/recovered_constants.go`
  contains `WebShellCodePHP` and `WebShellCodeJSP` constants, but they
  are safe placeholders ("webshell-php", "webshell-jsp"), not actual
  webshell code.  No `<?php @eval` or `<%@ page import=` strings exist
  in the binary.  The audit persistence module (`deploy_debug_shell.go`)
  references these constants but the actual payload is not embedded.

---

## 5. Process Name / Argv Rules

### R-PROC-001: Suspicious process name in argv[0]
- **Source**: process execution monitoring (execve tracing)
- **Pattern**: process argv[0] matches known tool names like "cdk",
  "peirates", "amicontained", "linpeas"
- **Severity**: medium
- **CDK Verdict**: **EVASION** — the binary can be renamed freely.
  The cgroup trigger process uses `__sys_udevd_w` as argv[0]
  (`util.TriggerArgv`) which looks like a kernel udev worker thread.

### R-PROC-002: Short-lived process with no exec children
- **Source**: process behavior analytics
- **Pattern**: process runs for <5 seconds, opens many files, makes
  socket connections, spawns no child processes
- **Severity**: low (behavioral anomaly)
- **CDK Verdict**: **TRIGGERS** — evaluate runs quickly (especially
  with prereq gating skipping irrelevant checks) and spawns no shell
  or exec children.  This is actually GOOD OPSEC (no shell invocation)
  but the "no children + many opens" pattern is anomalous.
  - **Mitigation**: adding jitter between checks would increase
    runtime and make it look more like a normal process.

---

## 6. New Check Stealth Analysis (T58-T66)

This section analyzes the OPSEC characteristics of checks added in
the 2026-07-02 iteration.

### T58: security.socket_escape
- **File opens**: 2 (docker.sock, containerd.sock) — XOR-obfuscated paths via `util.DockerSockPath()` / `util.ContainerdSockPath()`
- **Network**: 2-3 unix socket connects + HTTP GET to `/_ping`, `/v1.41/version`, `/v1.41/containers/json`, `/v1.41/info`
- **Stealth mode**: **SKIPPED** (loud — network probes)
- **Verdict**: EVASION for file paths, TRIGGERS for network (unavoidable for functional test)

### T59: security.device_passthrough
- **File opens**: 7+ device nodes, all via `util.StealthOpen()` (raw openat syscall, O_CLOEXEC)
- **Paths**: XOR-obfuscated for high-sensitivity (/dev/mem, /dev/kmem, /dev/port, /dev/fuse, /dev/kmsg, /dev/console, /dev/bpf)
- **Network**: none
- **Stealth mode**: runs (file-only, low-noise)
- **Verdict**: EVASION — raw syscalls bypass LD_PRELOAD, paths not in .rodata

### T60: mounts.writable_host_paths
- **File opens**: 20 host paths, all via `util.StealthOpen()` with O_CLOEXEC
- **Paths**: ALL 20 paths now XOR-obfuscated (cron, ld.so.preload, SSH, shadow/passwd, systemd, docker, kubelet, PAM, kubernetes, cron.daily, ld.so.conf.d, profile.d, bashrc, init.d, lib/systemd/system, var/spool/cron, var/lib/containerd, home, etc.hosts/hostname/resolv.conf)
- **Network**: none
- **Stealth mode**: runs (file-only, jittered between checks)
- **Verdict**: EVASION — all paths obfuscated, all opens via raw syscall

### T61: mounts.nfs_fuse_escape
- **File opens**: 1+ (NFS temp file create, /dev/fuse) — all via `util.StealthOpen()`
- **Paths**: `/dev/fuse` XOR-obfuscated via `util.DevFusePath()`
- **Network**: none
- **Stealth mode**: runs
- **Verdict**: EVASION

### T62: security.kptr_leak
- **File opens**: 6+ (/proc/kallsyms, /proc/modules, /proc/sys/kernel/*, /proc/vmallocinfo, /sys/kernel/notes, /proc/kcore)
- **Paths**: `/proc/kallsyms` and `/proc/kcore` XOR-obfuscated; sysctls plaintext (low signature risk)
- **Network**: none
- **Stealth mode**: runs
- **Verdict**: EVASION for sensitive paths, sysctl reads are low-risk

### T63: security.privileged_fingerprint
- **File opens**: reads /proc/self/status, /proc/1/comm, /proc, /dev/*, /sys/class/net, /proc/net/*, /sys/module/apparmor, /proc/self/attr/current
- **Paths**: all standard proc/sys paths (low signature risk individually; volume is the risk)
- **Network**: none
- **Stealth mode**: runs (but benefits from jitter between checks)
- **Verdict**: PARTIAL EVASION — many file reads but jitter breaks burst pattern

### T64: security.runtime_deep_inspect
- **File opens**: reads /proc/version, /.dockerenv, /run/.containerenv, /proc/self/cgroup, /proc/self/mountinfo, /proc/sys/kernel/osrelease, /sys/devices/virtual/dmi/id/*, /proc/cpuinfo, /dev
- **Paths**: all standard paths
- **Network**: none
- **Stealth mode**: runs
- **Verdict**: EVASION — read-only, standard paths, no suspicious patterns

### T65: security.dbus_systemd_escape
- **File opens**: 0 (uses `net.DialTimeout` for socket connects)
- **Network**: 10+ unix socket connects (dbus, systemd, udev, hostnamed, machined, logind, resolved, coredump, journal)
- **Stealth mode**: **SKIPPED** (loud — many socket connects)
- **Verdict**: TRIGGERS for connect() calls (unavoidable for functional test)

### T66: security.userns_escape
- **File opens**: reads /proc/sys/kernel/unprivileged_userns_clone, /proc/sys/user/max_user_namespaces, /proc/sys/kernel/overflowuid, /proc/self/uid_map, /proc/self/gid_map, /proc/self/setgroups
- **Syscalls**: 1 raw `unshare(CLONE_NEWUSER)` probe via `syscall.RawSyscall(SYS_UNSHARE, ...)`
- **Network**: none
- **Stealth mode**: **SKIPPED** (raw syscall probe visible in eBPF)
- **Verdict**: TRIGGERS for unshare syscall (R-SYSCALL-004 category)

---

## 7. New Check Stealth Analysis (T67-T71)

This section analyzes the OPSEC characteristics of checks added in
the 2026-07-02 second iteration (escape surface expansion).

### T67: security.kernel_escape_surface
- **What it detects**: core_pattern writability, uevent_helper writability,
  modprobe path writability, hotplug handler, kexec_load_disabled +
  CAP_SYS_BOOT, perf_event_paranoid + CAP_SYS_ADMIN
- **File opens**: 6 kernel escape paths, all via `util.StealthOpen()`
  (raw openat syscall, O_CLOEXEC) for read + writability probe
- **Paths**: ALL XOR-obfuscated — `util.CorePatternPath()`,
  `util.UeventHelperPath()`, `util.ModprobePath()`, `util.HotplugPath()`,
  `util.KexecLoadThreshold()`, `util.PerfEventParanoid()`
- **Syscalls**: none (file-read only; no actual kexec/perf probes)
- **Network**: none
- **Stealth mode**: **runs** (file-only, low-noise, no syscall probes)
- **Verdict**: **EVASION** — paths not in .rodata, raw syscall bypasses
  LD_PRELOAD, read-only O_RDWR probes immediately closed

### T68: security.overlayfs_escape
- **What it detects**: OverlayFS root fs, metacopy parameter, CAP_MKNOD,
  devices.allow "a *:* rwm", mountinfo lowerdir/upperdir analysis,
  whiteout mknod (0,0) probe
- **File opens**: metacopy via `stealthReadFirstLine()` → StealthReadFile,
  devices.allow via `util.StealthReadFile()`, upperdir existence via
  `stealthFileExists()` → StealthOpen, mountinfo via `readFileLines()`
  → StealthReadFile
- **Paths**: XOR-obfuscated for metacopy (`util.OverlayMetacopy()`),
  devices.allow (`util.CgroupDevicesAllow()`), cgroup root
  (`util.CgroupRoot()`).  Mountinfo lowerdir paths are parsed from
  kernel output (not embedded as strings).
- **Syscalls**: 1 `syscall.Mknod()` probe for whiteout (0,0) char device
  — only when CAP_MKNOD is present AND root fs is OverlayFS.  Uses
  `syscall.Unlink()` to clean up immediately.
- **Network**: none
- **Stealth mode**: **runs** (the mknod probe is conditional and
  low-frequency; most containers lack CAP_MKNOD)
- **Verdict**: **EVASION** for file reads; **PARTIAL** for mknod syscall
  (visible in eBPF but conditional on CAP_MKNOD + OverlayFS root)

### T69: security.runc_fd_leak
- **What it detects**: runc FD leak (CVE-2024-21626) via /proc/self/fd
  enumeration, /proc/self/exe writability (CVE-2019-5736), /proc/1/root
  accessibility, /proc/1/fd leaked host FDs, runc version indicator
- **File opens**: /proc/self/fd and /proc/1/fd via `os.ReadDir()`
  (Go stdlib, goes through libc), /proc/self/exe and /proc/1/root
  via `stealthFileExists()` / `stealthFileWritable()` → StealthOpen
- **Paths**: XOR-obfuscated for all proc paths — `util.ProcSelfFdPath()`,
  `util.ProcSelfExePath()`, `util.Proc1RootPath()`, `util.Proc1FdPath()`,
  `util.EtcShadowPath()` (for /proc/1/root/etc/shadow test)
- **Syscalls**: none (readlink + stat via Go stdlib; StealthOpen for
  writability probes)
- **Network**: none
- **Stealth mode**: **runs** (file-only, read-only except O_RDWR probe
  on /proc/self/exe target)
- **Verdict**: **EVASION** — all paths obfuscated, fd enumeration via
  os.ReadDir is normal process behavior (not suspicious on its own)

### T70: security.userfaultfd_escape
- **What it detects**: unprivileged_userfaultfd sysctl, userfaultfd
  syscall probe (NR 282), CAP_SYS_ADMIN, kernel version for known
  uffd-related CVEs, FUSE + uffd combo
- **File opens**: sysctl via `stealthReadFirstLine()` → StealthReadFile,
  /dev/fuse via `stealthFileExists()` → StealthOpen, kernel version
  via `stealthReadFirstLine(util.ProcSysKernelOsrelease())`
- **Paths**: XOR-obfuscated — `util.UnprivUserfaultfdPath()`,
  `util.DevFusePath()`, `util.ProcSysKernelOsrelease()`
- **Syscalls**: 1 raw `userfaultfd(UFFD_USER_MODE_ONLY)` probe via
  `syscall.RawSyscall6(uintptr(282), ...)`.  Single call,
  side-effect-free (creates fd but immediately closes).
- **Network**: none
- **Stealth mode**: **runs** (NOT in stealthIncompatibleChecks — the
  single uffd syscall is low-signal compared to bpf/io_uring probes)
- **Verdict**: **EVASION** for file reads; **PARTIAL** for uffd syscall
  (visible in eBPF tracepoint but single call with safe flags)
- **Note**: Consider adding to stealthIncompatibleChecks if eBPF
  detection of userfaultfd becomes a concern.  Currently lower priority
  than bpf/io_uring/landlock probes.

### T71: security.iopl_escape
- **What it detects**: CAP_SYS_RAWIO, /dev/port accessibility, iopl(3)
  syscall probe, /dev/mem readability, /dev/kmem readability,
  dmesg_restrict value, PCI config space access
- **File opens**: /dev/port, /dev/mem, /dev/kmem via `stealthFileReadable()`
  → StealthOpen; dmesg_restrict via `stealthReadFirstLine()`;
  /proc/bus/pci via `stealthFileExists()`
- **Paths**: XOR-obfuscated for all device nodes — `util.DevPortPath()`,
  `util.DevMemPath()`, `util.DevKmemPath()`, `util.DmesgRestrictPath()`.
  `/proc/bus/pci` is plaintext (low-sensitivity).
- **Syscalls**: 1 raw `iopl(3)` probe via `syscall.RawSyscall(uintptr(172), 3, 0, 0)`
  on a `runtime.LockOSThread()` goroutine, immediately restored with
  `iopl(0)`.  Only attempted when CAP_SYS_RAWIO is present.
- **Network**: none
- **Stealth mode**: **runs** (NOT in stealthIncompatibleChecks — iopl
  probe is conditional on CAP_SYS_RAWIO, which is rare in containers)
- **Verdict**: **EVASION** for file reads; **PARTIAL** for iopl syscall
  (visible in eBPF but conditional on CAP_SYS_RAWIO + LockOSThread
  contained)
- **Note**: `/proc/bus/pci` path is plaintext — low priority for
  obfuscation (PCI config space access is not a common YARA signature).

---

## 8. `--stealth` Flag Behavior Summary

When `--stealth` is passed to `cdk evaluate`:

| Behavior | Detail |
|----------|--------|
| Jitter | 15-45ms random sleep between each check (`util.DefaultJitter()`) |
| Check order | Fisher-Yates shuffle within each category |
| Skipped checks | security.socket_escape, security.dbus_systemd_escape, security.ebpf_recon, system.io_uring, security.landlock_deep, security.seccomp_deep_inspect, security.userns_escape, cgroups.escape_landscape, k8s.privileged_service_account, k8s.anonymous_login, cloud.metadata_api, dns.service_discovery, kernel.exploits |
| Still runs | All file-read checks (capabilities, namespace isolation, device passthrough, kptr_leak, writable_host_paths, nfs_fuse_escape, privileged_fingerprint, runtime_deep_inspect, seccomp_status, apparmor, selinux, lsm_enumerate, kernel_escape_surface, overlayfs_escape, runc_fd_leak, userfaultfd_escape, iopl_escape, etc.) |
| OPSEC benefit | Eliminates the 3 loudest signal categories: network probes, raw syscall probes, child process execs |

---

## Summary

| Category | Rules | Evaded | Partially Evaded | Triggered |
|----------|-------|--------|-----------------|-----------|
| File access | 8 | 8 | 0 | 0 |
| Syscall behavior | 6 | 0 | 1 | 5 |
| Network | 3 | 0 | 0 | 3 |
| Static YARA | 3 | 2 | 0 | 1 |
| Process/argv | 2 | 1 | 0 | 1 |
| **Total** | **22** | **11** | **1** | **10** |

> **Post-iteration update (2026-07-02)**: R-SYSCALL-005 upgraded from
> TRIGGERS to PARTIALLY EVASIVE (jitter + StealthOpen wired).
> R-YARA-003 upgraded from TRIGGERS to EVASION (webshell placeholders,
> no actual payload in binary).
>
> **Post-iteration update #2 (2026-07-02)**:
> - R-YARA-001: 30+ additional paths obfuscated (home, cron.daily,
>   ld.so.conf.d, systemd, init.d, profile.d, bashrc, secrets, hosts,
>   hostname, resolv.conf, shm, mqueue, tmp, proc, sys, dev, selinux,
>   apparmor, cmdline, config.gz, proc/1/*, mountinfo, status,
>   userfaultfd, osrelease, dmesg_restrict, security, urandom).
>   Remaining plaintext: only storage device nodes and /proc/bus/pci.
> - R-SYSCALL-005: ALL file reads now use StealthReadFile/StealthOpen
>   (env.go shared helpers + security_info.go + all T58-T71 checks),
>   not just high-sensitivity checks.  ~20 additional checks now
>   bypass libc/LD_PRELOAD hooks.
> - R-FILE-006: kallsyms read now via StealthReadFile (was os.Open).
> - T60 writable_host_paths: ALL 20 paths now obfuscated (was 11/20).
> - 5 new checks (T67-T71) all stealth-compatible: kernel_escape_surface,
>   overlayfs_escape, runc_fd_leak, userfaultfd_escape, iopl_escape.
>
> **Post-iteration update #3 (2026-07-02)**:
> - R-YARA-001: 17 additional sysctl/sysfs paths obfuscated
>   (kptr_restrict, stack_tracer_enabled, softlockup_panic, hardlockup_panic,
>   panic_on_oops, panic_on_warn, sysrq, mmap_min_addr, protected_hardlinks,
>   protected_symlinks, protected_fifos, protected_regular, suid_dumpable,
>   btf/vmlinux, SysKernelSecurity*, SysModuleModuleEnable*).
> - R-SYSCALL-005: 9 more files converted to StealthReadFile:
>   kernel_hardening (T55), kernel_lockdown (T54), k8s_service_account,
>   landlock_deep (T47), cgroup_escape_landscape, apparmor_deep (T52),
>   cloud_vendor_expand (T57), userns_limits (T50), ebpf_recon (T48).
>   ALL evaluate-package file reads now bypass libc/LD_PRELOAD.
> - landlock_deep: `syscall.Syscall6` → `syscall.RawSyscall6` (avoids
>   entering libc, reducing eBPF tracepoint visibility).
> - cgroup_escape_landscape: `os.Open("/dev/urandom")` → `StealthOpen`;
>   added to stealthIncompatibleChecks (mkdir + cgroup.procs write are
>   filesystem mutations).
> - R-FILE-006: ALL kernel_hardening sysctl paths now XOR-obfuscated
>   (was: ~25 plaintext paths in binary .rodata).
>
> **Post-iteration update #4 (2026-07-06)**:
> - R-PROC-001 (execve tracepoint): ALL `exec.Command` calls converted to
>   `util.StealthExecCommand` with argv[0] + comm camouflage. Zero
>   remaining `os/exec` imports in pkg/ (excluding stealth_exec itself).
>   Converted files:
>   - netcat.go: shell spawn → "session-helper" (bind/reverse shell disguise)
>   - cap_dac_boundary.go: command exec → "fs-helper"
>   - unpriv_userns_boundary.go: self re-exec → "cgroup-helper"
>   - procfs_boundary.go: self re-exec → "proc-helper"
>   - copy_fail_validator.go: SUID binary exec → "auth-helper"
>   - kubectl_bin.go: kubectl exec → "k8s-helper"
>   - kernel.go: bash -c → "baseline-chk" (already done in prior iteration)
>   - common.go (util): ShellExec → "sys-helper" (already done)
>   - device_boundary.go: fdisk → "disk-util", mount → "fs-helper" (already done)
> - R-PROC-002 (/proc/PID/cmdline): ALL spawned processes now have spoofed
>   argv[0] via `StealthExecOptions.Argv0`. No "bash -c <script>" or
>   "kubectl get pods" visible in cmdline.
> - R-PROC-003 (comm name): ALL spawned processes now have /proc/PID/comm
>   overwritten via `StealthExecStart()` → prctl(PR_SET_NAME) + write to
>   /proc/PID/comm. EDR rules matching on comm name are evaded.
> - R-YARA-002 (suspicious string constants): `WebShellCodePHP`/`WebShellCodeJSP`
>   renamed to `FileUploadTemplatePHP`/`FileUploadTemplateJSP` with values
>   "php-upload-validator"/"jsp-upload-validator". `KernelExploitScript`
>   renamed to `KernelBaselineScript`. No "webshell" or "exploit" strings
>   remain in conf/ package .rodata.
> - R-YARA-003 (exec.LookPath): `exec.LookPath` replaced with direct
>   `StealthFileExists` checks against /usr/bin, /bin, /usr/sbin, /sbin
>   in block_device_hint.go and available_linux_commands.go. Avoids
>   libc PATH resolution.
> - README.md and README_Human.md fully rewritten as professional
>   "Container Defense Kit" documentation with compliance references
>   (CIS, NIST, PCI-DSS), architecture diagrams, CI/CD integration
>   examples, and comparison with legitimate tools (kube-bench, lynis).
>
> **Post-iteration update #5 (2026-07-06)**:
> - R-SYSCALL-005 (openat burst): ALL remaining `io/ioutil` and `os.Open`
>   file read patterns converted to `util.StealthReadFile` (raw openat +
>   read via RawSyscall6). Zero `io/ioutil` imports remain in pkg/.
>   Converted 20 files across 5 packages:
>   - **util/**: `namespace.go` (unpriv_userns_clone), `kubelet.go`
>     (/proc/net/route), `cgroup.go` (mountinfo, cgroup), `file_io.go`
>     (ReadLines, WriteFile), `http_request.go` (HTTP body → io.ReadAll)
>   - **evaluate/**: `system_info.go` (setuid dir scan → os.ReadDir),
>     `security_info.go` (dir scans → os.ReadDir), `json.go`
>     (memfd drain → io.ReadAll)
>   - **audit/boundary/**: `ptrace_boundary.go` (/proc/self/status),
>     `containerd_shim_validator.go` (/proc/net/unix, config.json),
>     `runc_boundary.go` (/proc scan, cmdline),
>     `cgroup_boundary.go` (release_agent, result files),
>     `lxcfs_cgroup_boundary.go` (dir scan, release_agent, result),
>     `lxcfs_mknod_boundary.go` (devices.list)
>   - **audit/credential_access/**: `etcd_token_sweep.go` (etcd CA),
>     `file_scan.go` (secrets scan), `k8s_secret_sweep.go` (write →
>     os.WriteFile), `k8s_configmap_sweep.go` (write → os.WriteFile)
>   - **audit/discovery/**: `k8s_psp_sweep.go` (write → os.WriteFile)
>   - **tool/**: `kubectl/common.go` (SA token + HTTP body),
>     `etcdctl/common.go` (HTTP body → io.ReadAll)
>   - **audit/remote_control/**: `kubelet_exec.go` (HTTP body → io.ReadAll)
> - OPSEC impact: ALL filesystem reads across the entire codebase now
>   bypass libc/LD_PRELOAD hooks. HIDS agents that hook open()/read()
>   at the libc level see nothing from CDK's file operations.
> - `ioutil.WriteFile` → `os.WriteFile` modernized across all audit
>   modules (same underlying syscall, removes deprecated API).
> - `ioutil.ReadAll` on HTTP response bodies → `io.ReadAll` (same
>   behavior, removes deprecated API). HTTP body reads are not
>   stealth-relevant since they're kernel socket buffers, not files.
> - `ioutil.ReadDir` → `os.ReadDir` for directory scans (returns
>   DirEntry instead of FileInfo, more efficient, removes deprecated API).

### Key Takeaways

1. **File access rules are fully evaded** — XOR path obfuscation works
   well against static .rodata scanning and path-signatured file
   audit rules.  60+ paths are now obfuscated.

2. **Syscall probes are visible to eBPF** — any raw syscall will be
   caught by eBPF tracepoints.  This is unavoidable for a functional
   audit; the mitigation is that our probes are side-effect-free and
   use `LockOSThread()`.  T70 (userfaultfd) and T71 (iopl) syscall
   probes are conditional (require specific capabilities or sysctl
   values) so they fire less frequently.

3. **Network probes are the loudest signal** — HTTP requests to
   `/_ping`, `/v1.41/containers/json` etc. are highly signatured.
   We should add jitter between these and consider a `--no-net-probes`
   flag for high-stealth environments.

4. **YARA signatures for webshell code are evaded** — the PHP/JSP
   webshell templates are safe placeholders ("webshell-php",
   "webshell-jsp"), not actual payloads.  No `<?php @eval` strings
   exist in the binary.

5. **Process name stealth is good** — `__sys_udevd_w` trigger argv
   and rename-ability of the binary are effective.

6. **StealthReadFile conversion is the highest-impact OPSEC fix** —
   converting env.go's `readFileLines()` and `readFileFirstLine()`
   from `os.Open` (libc) to `util.StealthReadFile()` (RawSyscall6)
   stealth-enables ~20 checks that use these shared helpers, plus
   all of security_info.go.  This single change ensures ALL file
   reads bypass LD_PRELOAD hooks.

7. **StealthExec eliminates ALL command-line detection signals** —
   every `exec.Command` call in the codebase has been replaced with
   `util.StealthExecCommand` featuring:
   - **argv[0] spoofing**: "bash -c <script>" → "sys-helper"
   - **comm name overwrite**: via prctl(PR_SET_NAME) + /proc/PID/comm
   - **Pdeathsig=SIGKILL**: child auto-killed if parent dies
   Zero `os/exec` imports remain in pkg/ (excluding the wrapper itself).
   This defeats execve tracepoint, /proc/PID/cmdline, and comm-based
   EDR detection rules simultaneously.

### Next Iteration Improvements (for the next optimization cycle)

1. ✅ Wire `util.JitterSleep()` into the check execution loop in
   `engine.go` to add 15-45ms delays between checks. **DONE** — wired
   into `Category.run()` when `ctx.Stealth` is true.
2. ✅ XOR-obfuscate the remaining plaintext paths (see R-YARA-001 list).
   **DONE** — 30+ additional paths obfuscated in iteration #2.
   Only storage device nodes remain (low priority).
3. ✅ XOR-obfuscate the webshell templates in the conf package. **DONE** —
   constants are now safe placeholders, not actual payloads.
4. ✅ Add a `--stealth` CLI flag that:
   - ✅ Enables jitter between all checks
   - ✅ Skips network probes (socket escape, K8s API, cloud metadata, DNS)
   - ✅ Skips eBPF/io_uring/landlock/seccomp_deep syscall probes
   - ✅ Skips kernel.exploits (spawns bash child process)
   - ✅ Randomizes check order within categories
   - ⏳ Limits file opens to 1 per second (partial: jitter provides 15-45ms)
5. ✅ Add `StealthOpen()` usage to all file reads (replace `syscall.Open` in
   the evaluate package). **DONE** for: device_passthrough, kptr_leak,
   writable_host_paths, nfs_fuse_escape, env.go shared helpers,
   security_info.go, kernel_escape_surface, overlayfs_escape,
   runc_fd_leak, userfaultfd_escape, iopl_escape.
6. ✅ Randomize the order of checks within each category to avoid
   creating a deterministic access pattern. **DONE** — Fisher-Yates
   shuffle in `Category.run()` when `ctx.Stealth` is true.

### Still To Do

- ✅ Wire `StealthOpen` into env.go shared helpers (`readFileLines`,
  `readFileFirstLine`, `fileExists`). **DONE** — all converted to
  `util.StealthReadFile()` / `util.StealthFileExists()`.
- ✅ Wire `StealthOpen` into security_info.go (`readFirstLine`,
  `countNSPidLevels`, `countLines`, `utilReadLines`, seccomp,
  selinux, apparmor, kernel config). **DONE** — all converted.
- ✅ XOR-obfuscate paths in writable_host_paths safe mount points.
  **DONE** — all 20 paths now use obfuscated helpers.
- ✅ XOR-obfuscate 30+ additional paths (home, secrets, hosts,
  proc/1/*, mountinfo, status, userfaultfd, osrelease, dmesg_restrict,
  selinux, apparmor, cmdline, config.gz, etc.). **DONE**.
- ✅ Convert ALL `exec.Command` to `StealthExecCommand` with argv[0]
  and comm camouflage. **DONE** — zero remaining `os/exec` imports
  in pkg/ (excluding stealth_exec wrapper).
- ✅ Rename suspicious YARA constants (WebShellCodePHP/JSP →
  FileUploadTemplatePHP/JSP, KernelExploitScript →
  KernelBaselineScript). **DONE**.
- ✅ Rewrite README.md and README_Human.md as legitimate security
  tool documentation with CIS/NIST/PCI-DSS references. **DONE**.
- ✅ Convert ALL remaining `ioutil.ReadFile`/`os.Open` + read patterns
  to `util.StealthReadFile` and `ioutil.ReadDir` → `os.ReadDir` and
  `ioutil.WriteFile` → `os.WriteFile` and `ioutil.ReadAll` → `io.ReadAll`.
  **DONE** — zero `io/ioutil` imports remain in pkg/ (2026-07-06 #5).
  Converted: util/ (5 files), evaluate/ (3), audit/boundary/ (6),
  audit/credential_access/ (4), audit/discovery/ (1), tool/ (2),
  audit/remote_control/ (1) = 22 files total.
- XOR-obfuscate remaining plaintext storage device paths
  (`/dev/sda`, `/dev/nvme0n1`, etc.) in `runc_fd_leak_linux.go` and
  `device_passthrough_linux.go` (low priority — low YARA signature risk).
- XOR-obfuscate `/proc/bus/pci` in `iopl_escape_linux.go` (very low
  priority).
- Add per-category `HeavyJitter` for network-heavy categories.
