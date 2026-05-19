# Environment Baseline

## 目标环境

- 操作系统：Linux（Kali / Ubuntu / Debian / WSL2）
- Python：系统 Python3 或 `.venv` 虚拟环境
- **纯 Linux 操作**，Windows 命令交给用户执行
- **工具路径索引**：`workspace.json`（查看已注册工具的路径和用法）

---

## Bootstrap 触发条件

**立即 bootstrap**：
- 首次进入新比赛工作区
- 分类关键工具缺失
- 环境问题阻塞分类/复现/验证

**可跳过**：
- 工具已就绪
- 下一步是不依赖特殊工具的简单本地检查

---

## 按类型验证工具

| 类型 | 最低要求 |
|------|---------|
| Pwn | `checksec`, `gdb`/`gdb-multiarch` + pwndbg, `patchelf`, Python `pwntools`, `ROPGadget`, `one_gadget` |
| Web | `curl`, `jq`, `sqlmap`(可选), `ffuf`/`gobuster`(可选) |
| Reverse | `radare2`/`rizin`, `binwalk`, `strings`, `objdump`, `Ghidra headless`, `angr`, `pycdc` |
| Mobile | `apktool`, `jadx`, `adb`, Java runtime |
| Crypto | Python `pycryptodome`, `sympy`, `z3-solver`, `gmpy2`, `sage`(可选) |
| Misc | `ffmpeg`, `exiftool`, `tshark`, `zbar-tools`, `steghide`, `zsteg` |
| Forensics | `volatility3`(可选), `foremost`, `tshark`, `binwalk` |

---

## 快速安装

### Python 包（pip install — 不需要 sudo）
```bash
pip3 install pwntools ROPGadget ropper z3-solver pycryptodome capstone unicorn \
  requests httpx beautifulsoup4 lxml scapy pyshark r2pipe \
  numpy sympy pillow opencv-python python-magic gmpy2 \
  angr pycdc randcrack owiener

# 清华源加速
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple <包名>
```

### 系统工具（apt — 需要 sudo，提示用户执行）
```bash
# 请用户执行：
sudo apt update && sudo apt install -y \
  curl git jq wget unzip file make build-essential \
  gdb gdb-multiarch patchelf binutils strace ltrace socat netcat-openbsd \
  radare2 binwalk ffmpeg pngcheck foremost \
  libimage-exiftool-perl steghide zbar-tools tshark john hashcat \
  sqlmap gobuster ffuf
```

**注意**：apt 包需要 sudo 权限。如无 sudo，改用 pip 安装 Python 版本或从源码编译到 `~/.local/`。

### 用户级安装的工具（已安装在 ~/.local/）
查看 `workspace.json` 中的 `reverse_linux_tools` 和 `R2-Linux` 条目：
- **radare2**: `~/.local/bin/r2` (source build)
- **Ghidra headless**: `~/.local/ghidra/support/analyzeHeadless` (需 JDK 21+)
- **angr**: `pip3 install angr`
- **pwndbg**: `~/.local/pwndbg/` (GDB plugin)
- **rizin**: `~/.local/bin/rizin` (source build)
- **pycdc**: `~/.local/bin/pycdc` (source build)

### 完整 Bootstrap 脚本
```bash
bash .skills/ctf-agents-team/scripts/bootstrap-linux.sh
```

---

## 验证命令

```bash
python3 --version
pip3 --version
gdb --version 2>/dev/null || echo "gdb not found"
r2 -v 2>/dev/null || echo "radare2 not found"
rizin -v 2>/dev/null || echo "rizin not found"
checksec --version 2>/dev/null || echo "checksec not found"
analyzeHeadless 2>/dev/null | head -1 || echo "Ghidra headless not found"
python3 -c "import angr; print('angr', angr.__version__)" 2>/dev/null || echo "angr not found"
pycdc --help 2>/dev/null | head -1 || echo "pycdc not found"
```

---

## 缺包处理原则

- Python 包 → `pip3 install <包名>`，不询问用户
- pip 超时/被墙 → 切换清华源
- apt 包 → **提示用户手动执行** `sudo apt install`
- 源码编译 → 安装到 `~/.local/`，更新 `workspace.json`
- 工具安装失败 → 记录到 wp.process，尝试替代工具

---

## .venv 约定

如果工作区有 `.venv/` 目录，优先使用：
```bash
source .venv/bin/activate  # 或
.venv/bin/python3 script.py
```

如果没有 `.venv/`，使用系统 Python3。

---

## workspace.json 说明

`workspace.json` 是**运行时由用户创建或由工具自动生成的**工具路径注册表，**不在本仓库中**。

**位置**：比赛工作区根目录（与比赛目录同级）

**用途**：记录已安装工具的精确路径和用法，避免重复检测。

**格式示例**：
```json
{
  "tools": {
    "radare2": {"path": "~/.local/bin/r2", "version": "5.9.6"},
    "ghidra": {"path": "~/.local/ghidra/support/analyzeHeadless", "version": "11.2"},
    "pwndbg": {"path": "~/.local/pwndbg/", "status": "installed"},
    "pycdc": {"path": "~/.local/bin/pycdc", "status": "installed"},
    "fenjing": {"path": "~/.local/bin/fenjing", "status": "installed"}
  },
  "python_packages": {
    "pwntools": "4.12.0",
    "angr": "9.2.100",
    "z3-solver": "4.12.1"
  }
}
```

**使用规则**：
- 如果 `workspace.json` 存在，优先使用其中记录的工具路径
- 如果不存在，按正常 `which`/`command -v` 检测
- 安装新工具后可更新 `workspace.json`（但不强制）
