# Misc Agent — 技术速查

## Mission
混合题型处理：编码/解码、jail 逃逸、stego、Forensics 提取后的二级产物解码、游戏/VM、约束求解、RF/SDR。

## When Selected
- image/audio/video/archive
- 多步解码/文件变换/日志（不含原始 PCAP 分析）
- text/numeric 编码
- jail/sandbox/VM/game
- 多步解码链

---

## First Pass

1. 识别主要 artifact：图像、音频、压缩包、编码文本、混合目录；原始 PCAP/pcapng 先交 Forensics
2. 判断第一个问题：结构、元数据、传输、编码
3. 先提取 metadata，再 brute-force
4. 多步解码链保存中间产物

---

## 核心技术

### 文件识别
```bash
file *
xxd mystery_file | head -5
binwalk mystery_file
exiftool mystery_file
```

### 编码速查

| 编码 | 特征 |
|------|------|
| Base64 | `A-Za-z0-9+/=` |
| Base32 | `A-Z2-7=` 大写 |
| Hex | `0-9a-fA-F` |
| Binary | 纯 `0/1` |
| URL encode | `%xx` |
| Morse | `.` `-` `/` |
| Brainfuck | `+-<>[].,` |

```bash
# Base64
echo "encoded" | base64 -d
# Hex
echo "68656c6c6f" | xxd -r -p
# ROT13
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
```

详见 [knowledge/encodings.md](../knowledge/encodings.md) 和 [knowledge/encodings-advanced.md](../knowledge/encodings-advanced.md)。

### 图像隐写
```bash
# LSB 提取 (正确处理 RGB 通道)
python3 -c "
from PIL import Image
im = Image.open('img.png')
pixels = list(im.getdata())
bits = ''
for px in pixels:
    if isinstance(px, int):  # grayscale
        bits += str(px & 1)
    else:  # RGB/RGBA
        for ch in px[:3]:  # R, G, B
            bits += str(ch & 1)
# 转字节
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
print(flag[:200])
"

# steghide (JPEG only)
steghide extract -sf image.jpg -p ""  # 空密码
steghide extract -sf image.jpg -p "password"

# zsteg (PNG/BMP — 多通道/多bit自动检测)
zsteg image.png
zsteg image.png -a  # 全部通道组合

# 盲水印
python3 bwm.py decode original.png watermarked.png output.png

# 图片宽高修复 (PNG IHDR CRC 爆破)
python3 -c "
import struct, zlib, itertools
data = open('img.png','rb').read()
ihdr = data[12:29]  # IHDR 数据区
for w in range(1, 2000):
    for h in range(1, 2000):
        new_ihdr = struct.pack('>II', w, h) + ihdr[8:]
        if zlib.crc32(b'IHDR' + new_ihdr) & 0xffffffff == struct.unpack('>I', data[29:33])[0]:
            print(f'Width={w}, Height={h}')
            break
"

# EXIF 隐藏数据
exiftool -b -Comment image.jpg
exiftool -b -ThumbnailImage image.jpg > thumb.jpg
```

### 音频隐写
```bash
# 频谱图 (常见隐藏文字/图案)
sox audio.wav -n spectrogram -o spec.png
ffmpeg -i audio.wav -lavfi showspectrumpic=s=1024x512 spec.png

# DTMF 解码
multimon-ng -a DTMF -t wav audio.wav

# 摩斯电码 — 听音频/看波形，手动转录
# SSTV — qsstv 或 RX-SSTV (交给用户运行 GUI)

# Audacity 分析 (交给用户)
# → 查看频谱图/反转/速度调节/LSB 通道分离
```

### PDF 分析
```bash
# 提取嵌入文件
pdfdetach -list document.pdf
pdfdetach -saveall document.pdf

# 提取文本和元数据
pdftotext document.pdf -
exiftool document.pdf
strings document.pdf | grep -iE 'flag|secret|password'

# PDF 流解码 (JS/隐藏层)
python3 -c "
import PyPDF2
reader = PyPDF2.PdfReader('document.pdf')
for page in reader.pages:
    print(page.extract_text())
"

# qpdf 解密
qpdf --decrypt encrypted.pdf decrypted.pdf
```

### Office 文档分析
```bash
# OOXML 是 ZIP — 直接解压
unzip document.docx -d doc_unpacked/
# 搜索
grep -rn 'flag\|secret' doc_unpacked/

# OLE 分析 (旧格式 .doc/.xls)
olevba document.doc          # 提取 VBA 宏
oleid document.doc           # 检测可疑特征
python3 -c "from oletools.olevba import VBA_Parser; v=VBA_Parser('doc.doc'); v.analyze_macros()"

# 隐藏内容
# 白色字体、隐藏文本、批注、修订历史
```

### 压缩包处理
```bash
# ZIP 伪加密修复 (PK 头 bit6 清零)
python3 -c "
data=bytearray(open('fake.zip','rb').read())
# 找到 PK\x01\x02 和 PK\x03\x04 中的 flag byte，将加密标志清零
"

# 嵌套解压
while f=$(ls *.tar* *.gz *.bz2 *.xz *.zip *.7z 2>/dev/null|head -1) && [ -n "$f" ]; do
    7z x -y "$f" && rm "$f"
done

# RAR 密码爆破
john --wordlist=rockyou.txt hash_from_rar2john
```

### PCAP 二级产物辅助分析
```bash
# 原始 .pcap/.pcapng 一律归 Forensics；本节仅用于 Forensics 提取出的二级产物或必要的辅助复核。
# 基本信息
tshark -r capture.pcap -z conv,ip

# HTTP 提取
tshark -r capture.pcap -Y http -T fields -e http.request.uri

# 文件提取
tshark -r capture.pcap --export-objects http,exported/

# USB 键盘流量
tshark -r usb.pcap -T fields -e usb.capdata | python3 decode_usb.py

# DNS 隧道
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name
```

### QR 码
```bash
zbarimg qrcode.png       # 解码
qrencode -o out.png "data"  # 生成
```

**MaxiCode**: 六角形 2D 条码，用 `zxing` (Java) 解码。
**TOPKEK**: `KEK=0`, `TOP=1`, `!` 后缀 = 重复次数。

### Unicode 隐写

```python
# Variation Selectors (U+E0100-U+E01EF)
hidden = ''.join(chr((ord(c) - 0xE0100) + 16) for c in text if 0xE0100 <= ord(c) <= 0xE01EF)

# Unicode Tags (U+E0000-U+E007F)
hidden = ''.join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)
```

### IEEE-754 Float 隐藏
```python
import struct
flag = b''.join(struct.pack('>f', f) for f in float_list)
```

---

## Jail 逃逸

### Python Jail
```python
# 经典 class hierarchy
''.__class__.__mro__[1].__subclasses__()

# 无括号/无引号
# 使用 decorator + walrus operator
# 详见 knowledge/pyjails.md
```

### Bash Jail
```bash
# HISTFILE trick
HISTFILE=/flag bash && history

# bash verbose mode
bash -v flag.txt

# $() 嵌套
$(cat flag.txt)
```

详见 [knowledge/pyjails.md](../knowledge/pyjails.md) 和 [knowledge/bashjails.md](../knowledge/bashjails.md)。

---

## Z3 约束求解

```python
from z3 import *
x = BitVec('x', 32)
s = Solver()
s.add(x ^ 0xdead == 0xbeef)
if s.check() == sat:
    print(s.model())
```

详见 [knowledge/games-and-vms.md](../knowledge/games-and-vms.md)。

---

## 提权与后利用

```bash
find / -perm -4000 2>/dev/null      # SUID
sudo -l                              # sudo 权限
cat /etc/passwd                      # GECOS 字段
getfacl /flag                        # ACL
id | grep docker                     # docker 组 = root
```

详见 [knowledge/linux-privesc.md](../knowledge/linux-privesc.md)。

---

## Knowledge 文件索引

遇到具体场景时按需加载：

| 场景 | 加载 |
|------|------|
| Python jail | [pyjails.md](../knowledge/pyjails.md) |
| Bash jail | [bashjails.md](../knowledge/bashjails.md) |
| 编码/QR/esolang | [encodings.md](../knowledge/encodings.md) |
| 高级编码 | [encodings-advanced.md](../knowledge/encodings-advanced.md) |
| RF/SDR/IQ | [rf-sdr.md](../knowledge/rf-sdr.md) |
| DNS 利用 | [dns.md](../knowledge/dns.md) |
| WASM/VM/Z3/K8s | [games-and-vms.md](../knowledge/games-and-vms.md) |
| Cookie/WebSocket/BF | [games-and-vms-2.md](../knowledge/games-and-vms-2.md) |
| Docker/taint/memfd | [games-and-vms-3.md](../knowledge/games-and-vms-3.md) |
| XSLT/JS/OEIS | [games-and-vms-4.md](../knowledge/games-and-vms-4.md) |
| Linux 提权 | [linux-privesc.md](../knowledge/linux-privesc.md) |
| CTFd API | [ctfd-navigation.md](../knowledge/ctfd-navigation.md) |
| Blockchain/Solidity | [blockchain.md](../knowledge/blockchain.md) |
| AI/ML Security | [ai-security.md](../knowledge/ai-security.md) |

---

## Escalation

需要 `reverse-agent` 当：
- 发现编译逻辑或自定义可执行格式
需要 `web-agent` 当：
- HTTP/DNS/请求流成为关键路径
需要 `crypto-agent` 当：
- 编码问题实际是密码学问题
