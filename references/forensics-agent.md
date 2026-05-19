# Forensics Agent — 技术速查

## Mission
数字取证：内存分析、磁盘镜像、流量分析、侧信道、文件恢复。

## When Selected
- `.pcap/.pcapng/.evtx/.raw/.dd/.E01`
- memory dump / disk image
- 侧信道/功耗分析
- 文件恢复/元数据取证

---

## First Pass

1. `file *` 识别 artifact 类型
2. 判断主问题：流量分析 / 内存取证 / 磁盘取证 / 侧信道 / stego
3. 提取 metadata 和概览信息
4. 根据 artifact 类型选择工具链

---

## 核心技术

### 流量分析 (PCAP)
```bash
# 概览
tshark -r capture.pcap -z conv,ip
tshark -r capture.pcap -z io,stat,1

# 协议统计
tshark -r capture.pcap -z proto,colinfo,frame.protocols

# HTTP 分析
tshark -r capture.pcap -Y http.request -T fields -e ip.dst -e http.request.method -e http.request.uri
tshark -r capture.pcap --export-objects http,exported/

# DNS
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e dns.a

# 提取文件
foremost -i capture.pcap -o recovered/
binwalk -e capture.pcap

# TCP 流重组
tshark -r capture.pcap -z follow,tcp,ascii,0
```

### 流量隐写

```bash
# TTL 隐写
tshark -r capture.pcap -T fields -e ip.ttl | python3 decode_ttl.py

# 时间间隔编码
tshark -r capture.pcap -T fields -e frame.time_delta
# 间隔差异编码二进制数据

# ICMP 数据
tshark -r capture.pcap -Y icmp -T fields -e data
```

### 内存取证

```bash
# Volatility 3
vol3 -f memory.raw windows.info
vol3 -f memory.raw windows.pslist
vol3 -f memory.raw windows.filescan
vol3 -f memory.raw windows.dumpfiles --pid PID
vol3 -f memory.raw windows.hashdump
vol3 -f memory.raw windows.cmdline
vol3 -f memory.raw windows.netscan

# Volatility 2 (旧版)
volatility -f memory.raw imageinfo
volatility -f memory.raw --profile=Win7SP1x64 pslist
volatility -f memory.raw --profile=Win7SP1x64 filescan | grep flag
volatility -f memory.raw --profile=Win7SP1x64 dumpfiles -Q OFFSET -D output/

# Linux 内存
vol3 -f memory.raw linux.bash
vol3 -f memory.raw linux.pslist
```

### 磁盘取证

```bash
# 镜像信息
mmls disk.dd          # 分区表
fsstat -o OFFSET disk.dd  # 文件系统

# 文件列表
fls -r -o OFFSET disk.dd

# 提取文件
icat -o OFFSET disk.dd INODE > extracted_file

# 已删除文件恢复
foremost -i disk.dd -o recovered/
photorec disk.dd

# 挂载
sudo mount -o loop,ro,offset=$((SECTOR*512)) disk.dd /mnt/evidence
```

### Windows 事件日志

```bash
# .evtx 解析
python3 -c "
import Evtx.Evtx as evtx
with evtx.Evtx('Security.evtx') as log:
    for record in log.records():
        print(record.xml())
" | grep -i flag

# 或使用 evtx_dump
evtx_dump Security.evtx | grep -A5 -B5 'flag'
```

### 侧信道分析

```python
# 功耗/电磁 trace 分析
import numpy as np

traces = np.load('traces.npy')  # shape: (num_traces, num_samples)
plaintexts = np.load('plaintexts.npy')

# CPA (Correlation Power Analysis)
# Sbox 输出的汉明重量作为功耗假设
sbox = [0x63, 0x7c, 0x77, 0x7b, ...]  # AES S-box
for key_guess in range(256):
    # 中间值 = Sbox[plaintext ^ key_guess]
    intermediate = np.array([sbox[p ^ key_guess] for p in plaintexts[:, byte_idx]])
    hw = np.array([bin(v).count('1') for v in intermediate])  # 汉明重量
    # 与每个采样点的相关性
    for t in range(traces.shape[1]):
        corr = np.corrcoef(hw, traces[:, t])[0, 1]
        # 最大相关性 → 正确密钥
```

### USB 键盘/鼠标取证

```bash
# USB HID 键盘流量
tshark -r usb.pcap -T fields -e usb.capdata | grep -v '^$'

# 解码 USB 键盘 (HID Usage Table)
python3 -c "
hid_map = {0x04:'a', 0x05:'b', 0x06:'c', 0x07:'d', 0x08:'e', 0x09:'f',
           0x0a:'g', 0x0b:'h', 0x0c:'i', 0x0d:'j', 0x0e:'k', 0x0f:'l',
           0x10:'m', 0x11:'n', 0x12:'o', 0x13:'p', 0x14:'q', 0x15:'r',
           0x16:'s', 0x17:'t', 0x18:'u', 0x19:'v', 0x1a:'w', 0x1b:'x',
           0x1c:'y', 0x1d:'z', 0x1e:'1', 0x1f:'2', 0x20:'3', 0x21:'4',
           0x22:'5', 0x23:'6', 0x24:'7', 0x25:'8', 0x26:'9', 0x27:'0',
           0x28:'\\n', 0x2c:' ', 0x2d:'-', 0x2e:'=', 0x2f:'[', 0x30:']'}
hid_shift = {0x1e:'!', 0x1f:'@', 0x20:'#', 0x21:'\$', 0x22:'%',
             0x23:'^', 0x24:'&', 0x25:'*', 0x26:'(', 0x27:')',
             0x2f:'{', 0x30:'}', 0x2d:'_', 0x2e:'+'}
import sys
for line in sys.stdin:
    data = bytes.fromhex(line.strip().replace(':',''))
    if len(data) < 3: continue
    modifier, _, keycode = data[0], data[1], data[2]
    if keycode == 0: continue
    shift = modifier & 0x22  # left/right shift
    if shift and keycode in hid_shift:
        print(hid_shift[keycode], end='')
    elif keycode in hid_map:
        c = hid_map[keycode]
        print(c.upper() if shift else c, end='')
"

# USB 鼠标流量 → 画点轨迹
tshark -r usb.pcap -T fields -e usb.capdata | python3 draw_mouse.py
```

### 注册表分析

```bash
# regipy — Python 注册表解析
pip3 install regipy
python3 -c "
from regipy.registry import RegistryHive
reg = RegistryHive('/path/to/NTUSER.DAT')
for entry in reg.recurse_subkeys(reg.root):
    print(entry.path, entry.name)
" | grep -i flag

# 常见取证注册表位置
# NTUSER.DAT — 用户配置、最近文件、Run 键
# SAM — 用户账户和密码哈希
# SYSTEM — 系统配置、服务
# SOFTWARE — 安装的软件、注册信息
```

### Timeline 分析

```bash
# 文件 MAC 时间
find /mnt/evidence -type f -printf '%T@ %p\n' | sort -n | tail -20

# log2timeline / plaso (如已安装)
log2timeline.py timeline.plaso /mnt/evidence
psort.py -o l2tcsv timeline.plaso > timeline.csv

# 手动关联
# 1. 收集所有文件 modify/access/create 时间
# 2. 收集日志时间戳
# 3. 按时间排序，重建事件序列
```

### 浏览器取证

```bash
# Chrome 历史 (SQLite)
sqlite3 "History" "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 20;"

# Firefox 历史
sqlite3 "places.sqlite" "SELECT url, title, datetime(last_visit_date/1000000, 'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;"

# Cookie / 保存的密码
sqlite3 "Cookies" "SELECT host_key, name, value FROM cookies;"
# Chrome 密码需要 DPAPI 解密 (Windows) 或 keyring (Linux)
```

### 文件恢复

```bash
# 按文件签名搜索
foremost -i disk.dd -o output/

# 手动提取 (JPEG)
# JPEG: FFD8 开头, FFD9 结尾
python3 -c "
data = open('disk.dd', 'rb').read()
start = data.find(b'\xff\xd8')
end = data.find(b'\xff\xd9', start) + 2
open('recovered.jpg', 'wb').write(data[start:end])
"

# ZIP 修复
zip -FF broken.zip --out fixed.zip
```

### 元数据取证

```bash
exiftool image.jpg        # EXIF 数据
exiftool -all image.jpg   # 所有元数据
exiftool *.pdf            # PDF 元数据

# GPS 坐标提取
exiftool -GPSLatitude -GPSLongitude image.jpg

# 修改时间
exiftool -CreateDate image.jpg
stat file.txt
```

---

## 常见取证模式

| 模式 | 技术 |
|------|------|
| PCAP 中的文件传输 | `tshark --export-objects` 或 `foremost` |
| USB 键盘记录 | 提取 HID data，映射到按键 |
| DNS 数据外泄 | 子域名中编码数据 |
| 注册表分析 | `regipy` 或 `volatility registry` |
| 浏览器历史 | SQLite 数据库 (Chrome/Firefox) |
| 时间线重建 | 文件 MAC 时间、日志时间戳关联 |

---

## Escalation

需要 `misc-agent` 当：
- 提取的数据需要编码/解码管道
需要 `pwn-agent` 当：
- PCAP 中包含可回放的 exploit
需要 `crypto-agent` 当：
- 恢复的数据被加密
