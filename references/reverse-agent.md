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

### WASM 分析
```bash
wasm2wat main.wasm -o main.wat
# 阅读 WAT，寻找验证/比较逻辑
# 修改后: wat2wasm main.wat -o patched.wasm
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
