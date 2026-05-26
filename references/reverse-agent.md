# Reverse Agent — 技术速查

> **适用版本**: radare2 5.x+, Ghidra 11.x+, angr 9.x+, Python 3.8+

## Mission
静态与动态逆向：二进制分析、算法恢复、控制流重建、脱壳。

## When Selected
- stripped/部分文档化的二进制
- native library / patched build
- 验证/解密/算法恢复
- loader/packer/异常控制流

---

## First Pass

1. `file binary` — 格式、架构、packing
2. `strings binary | head -50` + `rabin2 -z binary` — 字符串/符号/导入
3. 判断主要 blocker：编码、crypto、验证逻辑、patch diff、loader 行为
4. 缩小到热点函数列表

---

## 核心技术

### 静态分析
```bash
# Radare2
r2 -A binary           # 自动分析
afl                     # 列出函数
pdf @ main              # 反汇编 main
axt @ sym.check_flag    # 交叉引用
izz                     # 所有字符串

# rabin2 (不打开 r2)
rabin2 -I binary        # 基本信息
rabin2 -z binary        # 字符串
rabin2 -i binary        # 导入
rabin2 -E binary        # 导出
rabin2 -S binary        # 段/节

# Rizin (r2 替代，语法兼容)
rizin -A binary
afl; pdf @ main; axt @ sym.check_flag

# objdump
objdump -d binary | grep -A5 'main>'
objdump -t binary | grep flag

# Binwalk
binwalk binary          # 嵌入文件检测
binwalk -e binary       # 自动提取
```

### Ghidra 无头分析
```bash
# Ghidra headless 批量反编译 (~/.local/ghidra/)
analyzeHeadless /tmp/ghidra_project proj_name \
  -import binary \
  -postScript DecompileAllFunctions.java \
  -scriptPath ~/.local/ghidra/Ghidra/Features/Decompiler/ghidra_scripts

# 导出反编译到文件
analyzeHeadless /tmp/ghidra_project proj_name \
  -process binary \
  -postScript ExportDecompiledFunctions.py /tmp/decompiled.c

# 注意: JAVA_HOME 需指向 JDK 21+ (SDKMAN)
```

### angr 符号执行
```python
import angr, claripy

proj = angr.Project('./binary', auto_load_libs=False)

# 方法 1: 找到 success 地址，回避 failure 地址
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401300)

if simgr.found:
    found = simgr.found[0]
    print(found.posix.dumps(0))  # stdin 内容 = flag

# 方法 2: 符号变量约束求解
flag = claripy.BVS('flag', 8 * 32)  # 32 字节符号变量
state = proj.factory.entry_state(stdin=flag)
for i in range(32):
    state.solver.add(flag.get_byte(i) >= 0x20)
    state.solver.add(flag.get_byte(i) <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401300)
if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
```

### angr 高级用法
```python
# Hook 函数（替换复杂/外部函数）
@proj.hook(0x401100, length=5)  # hook 地址, 跳过的字节数
def skip_check(state):
    state.regs.rax = 1  # 强制返回 true

# SimProcedure（替换库函数）
class MyPrintf(angr.SimProcedure):
    def run(self, fmt):
        return 0  # 跳过 printf，避免路径爆炸

proj.hook_symbol('printf', MyPrintf())

# 探索策略 — 避免路径爆炸
simgr = proj.factory.simgr(state)
simgr.use_technique(angr.exploration_techniques.DFS())  # 深度优先
# 或
simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=200))

# Veritesting — 自动合并路径减少爆炸
simgr.use_technique(angr.exploration_techniques.Veritesting())

# 内存中搜索 flag（不需要知道 success 地址）
simgr.explore(find=lambda s: b'flag{' in s.posix.dumps(1))  # stdout 含 flag

# SimProcedure 替换复杂函数
class IgnoreStrcmp(angr.SimProcedure):
    def run(self, a1, a2):
        return claripy.BVV(0, 32)  # 永远返回 "相等"

proj.hook_symbol('strcmp', IgnoreStrcmp())

# 从函数中间开始执行 (跳过反调试/初始化)
state = proj.factory.blank_state(addr=0x401200)  # 跳过 0x401000-0x4011ff
state.regs.rdi = symbolic_input_addr  # 手动设置参数

# 路径修剪 — 避免无用分支
def prune_filter(state):
    return b'bad' not in state.posix.dumps(1)
simgr = proj.factory.simgr(state, save_unconstrained=True)
simgr.step(until=lambda s: s.active and len(s.active) < 100)
```

### Unicorn Engine 模拟执行
```python
from unicorn import *
from unicorn.x86_const import *

# 模拟执行 — 对混淆代码/自解密代码特别有效
mu = Uc(UC_ARCH_X86, UC_MODE_64)

# 映射内存
CODE_ADDR = 0x400000
STACK_ADDR = 0x7fff0000
mu.mem_map(CODE_ADDR, 0x10000)    # 代码段
mu.mem_map(STACK_ADDR, 0x10000)   # 栈

# 写入代码
code = open('shellcode.bin', 'rb').read()
mu.mem_write(CODE_ADDR, code)

# 设置寄存器
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + 0x8000)

# Hook — 追踪执行
def hook_code(uc, address, size, user_data):
    print(f"  0x{address:x}: size={size}")
mu.hook_add(UC_HOOK_CODE, hook_code)

# Hook 内存访问
def hook_mem(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(f"  Write 0x{value:x} to 0x{address:x}")
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem)

# 执行
try:
    mu.emu_start(CODE_ADDR, CODE_ADDR + len(code))
except UcError as e:
    print(f"Emulation stopped: {e}")

# 读取结果
result = mu.mem_read(0x600000, 0x100)  # 读输出区域
```

### 反混淆 (OLLVM / Tigress)

**识别 OLLVM 混淆**：
```bash
# 特征: 控制流平坦化 (CFF) — 巨大的 switch-case/dispatcher
# 在 r2 中:
r2 -A binary
afl  # 函数列表: 极少函数，每个巨大
agf @ main  # 控制流图: 一个大 dispatcher + 多个 case block
# 特征: 大量 cmp + je/jne 跳到同一个 dispatcher
```

| 混淆类型 | 特征 | 对策 |
|---------|------|------|
| CFF (控制流平坦化) | 巨大 switch dispatcher | deflat.py (Binary Ninja/r2 插件) 或 angr symbolic |
| BCF (虚假控制流) | 永远为 true/false 的不透明谓词 | 符号执行自动判断死路径 |
| 字符串加密 | 无可读字符串，运行时解密 | 动态执行/Unicorn 模拟到解密后 dump |
| Instruction Substitution | 等价但复杂的指令替换 | Miasm/Triton 简化 |
| MBA (Mixed Boolean-Arithmetic) | `(x ^ y) + 2*(x & y)` 替代 `x+y` | Z3 等价性验证 + 简化 |

```python
# 用 angr 绕过控制流平坦化
# 思路: 不关心控制流结构，只关心输入→输出关系
# 设置符号输入 → explore → 求解约束
# angr 的符号执行天然不受 CFF 影响（因为它追踪数据流而非控制流）
```

### 自定义虚拟机分析
```bash
# 特征: binary 中包含解释器 + bytecode
# 检测: 巨型 switch (opcode dispatch) + 数据段中有连续的 bytecode blob

# 分析步骤:
# 1. 定位 dispatch 循环 (switch(opcode) + 取指 + 更新 PC)
# 2. 提取 bytecode blob (从 .rodata 或附加段)
# 3. 编写 trace 脚本记录每条指令的操作
# 4. 使用 Unicorn 模拟执行并 dump 中间状态
# 5. 构建 opcode → 操作映射表
```

```python
# Unicorn trace VM 执行
from unicorn import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x100000)  # 代码段 + bytecode 段
code = open('./binary', 'rb').read()
mu.mem_write(0x400000, code)

# trace VM 指令
vm_instrs = []
def hook_code(uc, addr, size, ud):
    if 0x401500 <= addr < 0x401800:  # VM dispatch 范围
        rip_val = uc.reg_read(UC_X86_REG_RIP)
        opcode = uc.mem_read(uc.reg_read(UC_X86_REG_RAX), 1)  # 假设 opcode 在 rax
        vm_instrs.append((addr, opcode.hex(), uc.reg_read(UC_X86_REG_RBX)))

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(0x401000, 0x402000)

# 分析 trace 推断 opcode 语义
for addr, op, rb in vm_instrs[:30]:
    print(f"  0x{addr:x}: op={op} rb=0x{rb:x}")
```

### Frida 用于 Native 二进制 (非 Mobile 场景)
```bash
# Frida 也可以 hook Linux ELF (不只是 Android)
# 安装: pip3 install frida-tools
# 用法: frida -f ./binary -l hook.js

# hook.js 示例 — hook strcmp 截获 flag 比较
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter: function(args) {
        var s1 = args[0].readUtf8String();
        var s2 = args[1].readUtf8String();
        console.log("strcmp: " + s1 + " vs " + s2);
    }
});

# hook 自定义函数 (通过偏移)
var base = Module.findBaseAddress("binary");
Interceptor.attach(base.add(0x1234), {
    onEnter: function(args) {
        console.log("arg0: " + args[0]);
        console.log("buffer: " + hexdump(args[1], {length: 64}));
    },
    onLeave: function(retval) {
        console.log("return: " + retval);
    }
});

### Frida 自动化脚本模板 (Python)
```python
import frida, sys

session = frida.attach("binary")  # or frida.spawn("./binary")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        console.log("called!");
        // args[0], args[1], ...
    },
    onLeave: function(retval) {
        console.log("ret -> " + retval);
    }
});
""")
script.load()
sys.stdin.read()

# 完整 dump 内存 (解决 PyArmor/upx 脱壳)
# frida -p PID -e "var m = Process.enumerateRanges('rwx'); m.forEach(r => { if (r.size < 1024*1024) console.log(r.base + ':' + r.size + ':' + hexdump(Memory.readByteArray(r.base, r.size), {offset:0,length:r.size})); })"
```

### 常见加密算法识别

| 特征常量 | 算法 |
|---------|------|
| `0x67452301, 0xEFCDAB89` | MD5 |
| `0x6a09e667, 0xbb67ae85` | SHA-256 |
| `0x9E3779B9` | TEA/XTEA/Xor |
| `0x61C88647` | TEA (delta 负值) |
| S-box 256 字节 | AES / RC4 |
| `0xC6A4A7935BD1E995` | MurmurHash64A |

### TEA/XTEA 解密模板
```python
import struct
def tea_decrypt(v, key):
    v0, v1 = struct.unpack('=2I', v)
    delta = 0x9E3779B9
    s = (delta * 32) & 0xFFFFFFFF
    k = struct.unpack('=4I', key)
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        s = (s - delta) & 0xFFFFFFFF
    return struct.pack('=2I', v0, v1)
```

### XOR 解密
```python
# 单字节 XOR brute-force
data = open('encrypted', 'rb').read()
for key in range(256):
    dec = bytes(b ^ key for b in data)
    if b'flag' in dec:
        print(f"Key={key}: {dec}")
```

### APK 逆向
```bash
# 解包
apktool d app.apk -o app_unpacked

# JADX 反编译
jadx -d output/ app.apk

# DEX 中搜索
grep -rn "flag\|secret\|key\|password" output/

# so 库分析
file lib/arm64-v8a/libnative.so
r2 -A lib/arm64-v8a/libnative.so
```

### PyInstaller / Python 打包
```bash
# 提取
python3 pyinstxtractor.py packed.exe

# 反编译 pyc
uncompyle6 main.pyc    # Python ≤3.8
pycdc main.pyc          # Python 3.9+ (已安装: ~/.local/bin/pycdc)
# pycdc 失败时用 pcdas 获取字节码:
pcdas main.pyc > disasm.txt

# Marshal 分析
python3 -c "
import marshal, dis
with open('main.pyc', 'rb') as f:
    f.read(16)  # skip header
    code = marshal.load(f)
    dis.dis(code)
"

# PyArmor 脱壳
# 特征: 导入 _pytransform, 运行时解密 bytecode
# 方法 1: Frida 内存 dump
# frida -f packed.exe -l hook.js --no-pause
# Interceptor.attach(Module.findExportByName(None,'PyMarshal_ReadObjectFromString'),{onLeave(retval){console.log(retval);}})

# 方法 2: Audit hook (Python 3.9.7+)
# python3 -c "
# import sys; dumped=[]
# def hook(name,args):
#   if name=='code.__new__': dumped.append(args[0])
# sys.addaudithook(hook); import obfuscated_module
# open('dump.pyc','wb').write(dumped[0])
# "

# 方法 3: pyarmor-unpacker (github DimaReverse/pyarmor-unpacker)
# 解包后 pycdc 反编译

# PyArmor v8+: 全进程内存 dump + strings 搜索
# procdump / frida 抓进程内存 → strings dump.bin | grep -i flag
```
```

### Packed / UPX 脱壳
```bash
# 检测 packing
file binary        # "UPX compressed" / 异常段名
rabin2 -I binary   # 极少导入 + 高熵段
strings binary | grep UPX

# UPX 脱壳
upx -d packed_binary -o unpacked_binary

# 手动脱壳 (非 UPX)
# 1. 找到 OEP (Original Entry Point)
# 2. dump 内存
# 3. 修复 IAT
# gdb: break on entry → run → dump memory
```

### Anti-Debug 检测与绕过
```bash
# 常见反调试手法
# - ptrace(PTRACE_TRACEME) → 返回 -1 表示已被调试
# - /proc/self/status → TracerPid != 0
# - int3 / SIGTRAP handler
# - timing check (rdtsc)

# GDB 绕过
# set follow-fork-mode child
# catch syscall ptrace
# 或直接 patch: 把 ptrace 调用 NOP 掉
```

### Golang 二进制
```bash
# 特征：静态链接、符号多、runtime.main
# 恢复符号
go_parser binary        # 或 GoReSym
# 在 r2 中:
r2 -A go_binary
afl | grep main.        # Go 函数以 main. 开头
```

### Rust 二进制
```bash
# 特征：大量 panic/unwrap 符号、Rust mangling
# 反编译后关注: fn main(), 搜索 "flag" 字符串
# demangle: rustfilt < symbols.txt
```

### .NET / C# 逆向
```bash
# dnSpy (Windows, 交给用户)
# 或 Linux 替代
monodis assembly.exe
ildasm assembly.dll
```

### 固件 / 嵌入式分析
```bash
# 检测固件类型
binwalk firmware.bin          # 检测嵌入的文件系统 / 已知签名
binwalk -E firmware.bin       # 熵分析 (高熵 = 加密/压缩, 低熵 = 明文)
binwalk -e firmware.bin       # 自动提取

# ESP32 固件
# esp32_image_parser:  raw flash → ELF (Ghidra 可分析)
python3 esp32_image_parser.py dump_flash firmware.bin

# 提取 NVS (Non-Volatile Storage) 分区
python3 espressif_nvs_analyzer.py nvs_partition.bin

# QEMU 模拟嵌入式固件
# 1. binwalk 提取文件系统
# 2. 找到启动脚本 (run.sh / bootargs)
# 3. QEMU system-mode 模拟
qemu-system-arm -M virt -kernel vmlinux -drive file=squashfs.img,format=raw -nographic

# 常见嵌入式 CTF 结构:
# - 裸机 ARM/MIPS 固件 → Ghidra (手动指定基址)
# - ESP32 flash dump → esp32_image_parser + Ghidra
# - Linux 嵌入式 (squashfs, initramfs) → binwalk + QEMU
```

### WASM 分析
```bash
wasm2wat main.wasm -o main.wat
# 阅读 WAT，寻找验证/比较逻辑
# 修改后: wat2wasm main.wat -o patched.wasm
```

### 二进制差异对比 (Patch Diff)
```bash
# 场景: 题目提供 patched 版本和原始版本，找差异

# 1. 字节级对比 (radiff2)
radiff2 binary.orig binary.patched   # 输出差异地址和字节

# 2. 反汇编级对比
diff <(objdump -d binary.orig) <(objdump -d binary.patched) | grep -E '^[<>]' | head -30

# 3. Diaphora (免费 bindiff 替代)
# IDA 插件: 函数匹配、伪代码差异、基本块对比
# python3 diaphora.py --ida binary.orig binary.patched

# 4. 手动 patch 提取 (python)
python3 -c "
o = open('binary.orig','rb').read(); p = open('binary.patched','rb').read()
for i in range(min(len(o),len(p))):
    if o[i] != p[i]: print(f'0x{i:x}: {o[i]:02x} → {p[i]:02x}')
"

# 常见 patch 场景: 跳转条件反转 (jnz→jz/jmp), 密钥替换, 函数调用移除
```

---

## Z3 约束求解

```python
from z3 import *

# 逐字符约束
flag = [BitVec(f'f{i}', 8) for i in range(FLAG_LEN)]
s = Solver()

# 添加约束（从逆向得到的检查逻辑）
for i in range(FLAG_LEN):
    s.add(flag[i] >= 0x20, flag[i] <= 0x7e)  # printable

# 示例：flag[0] ^ 0x42 == 0x24
s.add(flag[0] ^ 0x42 == 0x24)

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[f].as_long()) for f in flag)
    print(result)

# BitVec 数组 (用于多轮 XOR/置换)
key = [BitVec(f'k{i}', 8) for i in range(8)]
for i in range(len(cipher)):
    s.add(cipher[i] == plain[i] ^ key[i % 8])

# Extract/Concat (位提取和拼接，用于位旋转)
from z3 import Extract, Concat
x = BitVec('x', 32)
rot_left_14 = Concat(Extract(17, 0, x), Extract(31, 18, x))  # ROL 14

# S-Box 约束 (直接编码置换表)
s_box = [0x63, 0x7c, 0x77, ...]  # AES S-Box
for i in range(256):
    s.add(If(x == i, y == s_box[i], True))  # y = s_box[x]

# 线性方程组 (整数运算，无模数)
x, y, z = Ints('x y z')
s.add(x + y - z == 10, 2*x - y + z == 5, x + 3*y + z == 15)

# UNSAT 调试
if s.check() == unsat:
    print(s.to_smt2())  # 导出 SMT-LIB2 定位冲突约束
    # 分段测试: 每次启用一半约束，二分法定位
    for c in s.assertions():
        t = Solver()
        t.add(c)
        print(f"{c}: {t.check()}")  # 单约束检查
```

### 求解器规范与 WP 记录

## 求解器规范与 WP 记录

### Solver 要求
```python
# 1. python3 solver.py 直接输出 flag，无手动步骤
# 2. 标注关键函数地址、约束来源、patch 点
# 3. 包含完整注释，不依赖逆向者后续操作

def solve():
    # === Key Functions ===
    # check_flag @ 0x401234 (XOR loop + compare)
    #
    # === Constraints (from check_flag) ===
    # - flag length: 32 (cmp eax, 32 @ 0x401220)
    # - xor key: [0x42, 0x13, 0x37] (from 0x401234 loop)
    # - expected: .rodata:0x404000 (32 bytes)
    #
    # === Patches ===
    # - 0x401000: ptrace → NOP (anti-debug bypass)

    from z3 import *
    solver = Solver()
    flag = [BitVec(f'f{i}', 8) for i in range(32)]
    # ... constraints from reversing ...
    assert solver.check() == sat, "unsat — check constraints"
    return bytes([solver.model()[f].as_long() for f in flag])

if __name__ == '__main__':
    print(solve().decode())
```

---

## Escalation

需要 `pwn-agent` 当：
- 恢复的逻辑可用于 exploitation
需要 `mobile-agent` 当：
- 关键行为在 JNI/app 打包层

---

## Windows 工具委托

如需 IDA Pro / x64dbg 分析，提供用户精确指令：
```
请在 Windows 端：
1. IDA Pro 打开 binary，F5 反编译 main 函数
2. 截图反编译结果粘贴回来
```
