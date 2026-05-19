# CTF Misc - RF / SDR / IQ Signal Processing

> **适用版本**: GNU Radio 3.10+, Python 3.8+, numpy/scipy
> **最后更新**: 2026-05-19

Techniques for Software-Defined Radio (SDR) signal processing using In-phase/Quadrature (IQ) data.

---

## Table of Contents
- [IQ File Formats](#iq-file-formats)
- [Signal Identification Decision Tree](#signal-identification-decision-tree)
- [Analysis Pipeline](#analysis-pipeline)
- [Modulation Types & Demodulation](#modulation-types--demodulation)
- [QAM-16 Demodulation with Carrier + Timing Recovery](#qam-16-demodulation-with-carrier--timing-recovery)
- [Common RF CTF Patterns](#common-rf-ctf-patterns)
- [GNU Radio Guidance](#gnu-radio-guidance)
- [Key Insights for RF CTF Challenges](#key-insights-for-rf-ctf-challenges)
- [Common Framing Patterns](#common-framing-patterns)

---

## IQ File Formats
- **cf32** (complex float 32): GNU Radio standard, `np.fromfile(path, dtype=np.complex64)`
- **cs16** (complex signed 16-bit): `np.fromfile(path, dtype=np.int16).reshape(-1,2)`, then `I + jQ`
- **cu8** (complex unsigned 8-bit): RTL-SDR raw format, `(np.fromfile(path, dtype=np.uint8) - 127.5) / 127.5` then reshape
- **cs8** (complex signed 8-bit): HackRF format
- **wav**: sometimes used for IQ, 2-channel (I=left, Q=right)

```python
import numpy as np

def load_iq(path):
    """Auto-detect and load IQ file."""
    if path.endswith('.cf32'):
        return np.fromfile(path, dtype=np.complex64)
    elif path.endswith('.cs16'):
        raw = np.fromfile(path, dtype=np.int16).astype(np.float32)
        return raw[0::2] + 1j * raw[1::2]
    elif path.endswith('.cu8'):
        raw = (np.fromfile(path, dtype=np.uint8).astype(np.float32) - 127.5) / 127.5
        return raw[0::2] + 1j * raw[1::2]
    elif path.endswith('.cs8'):
        raw = np.fromfile(path, dtype=np.int8).astype(np.float32) / 128.0
        return raw[0::2] + 1j * raw[1::2]
    else:
        # Try complex64 as default
        return np.fromfile(path, dtype=np.complex64)
```

---

## Signal Identification Decision Tree

```
IQ 数据 → FFT 频谱分析
├─ 单一窄峰 → AM 或 CW (连续波/摩斯电码)
│   └─ 有节奏通断 → 摩斯电码 → 解码
├─ 对称双边带 → AM (包络检波)
├─ 瞬时频率变化 → FM
│   ├─ 窄带 (~12.5kHz) → NBFM (对讲机/DTMF)
│   └─ 宽带 (~200kHz) → WBFM (广播)
├─ 离散频率跳变 → FSK
│   ├─ 2 个频率 → 2-FSK / GFSK
│   └─ 4 个频率 → 4-FSK
├─ 星座图可识别 →
│   ├─ 2 点 (实轴) → BPSK
│   ├─ 4 点 → QPSK
│   ├─ 8 点 (圆) → 8PSK
│   ├─ 16 点 (方格) → QAM-16
│   └─ 64 点 (方格) → QAM-64
├─ 多载波 (梳状频谱) → OFDM
└─ 图像编码音频 → SSTV (慢扫描电视)
```

---

## Analysis Pipeline
```python
import numpy as np
from scipy import signal
import matplotlib.pyplot as plt

# 1. Load IQ data
iq = np.fromfile('signal.cf32', dtype=np.complex64)

# 2. Spectrum analysis - find occupied bands
fft_data = np.fft.fftshift(np.fft.fft(iq[:4096]))
freqs = np.fft.fftshift(np.fft.fftfreq(4096))
power_db = 20*np.log10(np.abs(fft_data)+1e-10)

# 3. Waterfall / spectrogram (时频图)
f, t, Sxx = signal.spectrogram(iq, fs=1.0, nperseg=1024, noverlap=512,
                                return_onesided=False)
plt.pcolormesh(t, np.fft.fftshift(f), 10*np.log10(np.fft.fftshift(Sxx, axes=0)+1e-10))
plt.ylabel('Frequency'); plt.xlabel('Time'); plt.colorbar(label='dB')
plt.savefig('waterfall.png', dpi=150)

# 4. Identify symbol rate via cyclostationary analysis
x2 = np.abs(iq)**2  # squared magnitude
fft_x2 = np.abs(np.fft.fft(x2, n=65536))
# Peak in fft_x2 = symbol rate (samples_per_symbol = 1/peak_freq)

# 5. Frequency shift to baseband
center_freq = 0.14  # normalized frequency of band center
t_arr = np.arange(len(iq))
baseband = iq * np.exp(-2j * np.pi * center_freq * t_arr)

# 6. Low-pass filter to isolate band
lpf = signal.firwin(101, 0.05, fs=1.0)  # bandwidth/2
filtered = signal.lfilter(lpf, 1.0, baseband)

# 7. Plot constellation
plt.figure(); plt.scatter(filtered.real, filtered.imag, s=0.1, alpha=0.3)
plt.grid(True); plt.axis('equal'); plt.savefig('constellation.png', dpi=150)
```

---

## Modulation Types & Demodulation

### AM (Amplitude Modulation)
```python
# 包络检波 — 最简单的解调
demod = np.abs(iq)  # 取幅度
# 去直流
demod = demod - np.mean(demod)
```

### FM (Frequency Modulation)
```python
# 瞬时频率 = 相邻样本相位差
phase = np.angle(iq)
freq_demod = np.diff(np.unwrap(phase))

# 或用共轭乘法（数值更稳定）
freq_demod = np.angle(iq[1:] * np.conj(iq[:-1]))
```

### BPSK (Binary Phase Shift Keying)
```python
# 2 个星座点: +1, -1 (实轴)
sps = 8  # samples per symbol (从 cyclostationary 分析得到)
# 下采样到 symbol rate
symbols = filtered[::sps]
# 判决
bits = (symbols.real > 0).astype(int)
```

### QPSK (Quadrature Phase Shift Keying)
```python
# 4 个星座点: (1+1j, -1+1j, -1-1j, 1-1j) / sqrt(2)
symbols = filtered[::sps]
bit_I = (symbols.real > 0).astype(int)
bit_Q = (symbols.imag > 0).astype(int)
# 每个 symbol 2 bits
bits = np.column_stack([bit_I, bit_Q]).flatten()
```

### FSK (Frequency Shift Keying)
```python
# 2-FSK: 瞬时频率高/低 → 1/0
freq = np.angle(iq[1:] * np.conj(iq[:-1]))
# 下采样
freq_symbols = freq[sps//2::sps]  # sample at symbol center
bits = (freq_symbols > 0).astype(int)

# 4-FSK: 4 个频率等级 → 2 bits/symbol
# 用 K-means 或固定阈值分成 4 级
```

### OFDM (Orthogonal Frequency Division Multiplexing)
```python
# 关键参数: FFT size, CP (cyclic prefix) length
fft_size = 64   # 常见: 64, 128, 256, 512, 1024, 2048
cp_len = 16     # 循环前缀

# 去 CP + FFT
symbol_len = fft_size + cp_len
n_symbols = len(iq) // symbol_len
for i in range(n_symbols):
    sym = iq[i*symbol_len + cp_len : (i+1)*symbol_len]
    freq_domain = np.fft.fft(sym, fft_size)
    # 每个子载波独立解调 (通常是 QPSK 或 QAM)
```

---

## QAM-16 Demodulation with Carrier + Timing Recovery
QAM-16 (Quadrature Amplitude Modulation) — the key challenge is carrier frequency offset causing constellation rotation (circles instead of points).

**Decision-directed carrier recovery + Mueller-Muller timing:**
```python
# Loop parameters (2nd order PLL)
carrier_bw = 0.02  # wider BW = faster tracking, more noise
damping = 1.0
theta_n = carrier_bw / (damping + 1/(4*damping))
Kp = 2 * damping * theta_n      # proportional gain
Ki = theta_n ** 2                # integral gain

carrier_phase = 0.0
carrier_freq = 0.0

for each symbol sample:
    # De-rotate by current phase estimate
    symbol = raw_sample * np.exp(-1j * carrier_phase)

    # Find nearest constellation point (decision)
    nearest = min(constellation, key=lambda p: abs(symbol - p))

    # Phase error (decision-directed)
    error = np.imag(symbol * np.conj(nearest)) / (abs(nearest)**2 + 0.1)

    # Update 2nd order loop
    carrier_freq += Ki * error
    carrier_phase += Kp * error + carrier_freq
```

**Mueller-Muller timing error detector:**
```python
timing_error = (Re(y[n]-y[n-1]) * Re(d[n-1]) - Re(d[n]-d[n-1]) * Re(y[n-1]))
             + (Im(y[n]-y[n-1]) * Im(d[n-1]) - Im(d[n]-d[n-1]) * Im(y[n-1]))
# y = received symbol, d = decision (nearest constellation point)
```

---

## Common RF CTF Patterns

### 摩斯电码 (Morse Code)
```python
# 从 AM/CW 信号中提取
envelope = np.abs(iq)
threshold = (np.max(envelope) + np.min(envelope)) / 2
on_off = (envelope > threshold).astype(int)
# 分析 on/off 持续时间 → dit (短) / dah (长) / 间隔
# dit:dah:word_gap = 1:3:7

MORSE = {'.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E',
         '..-.':'F', '--.':'G', '....':'H', '..':'I', '.---':'J',
         '-.-':'K', '.-..':'L', '--':'M', '-.':'N', '---':'O',
         '.--.':'P', '--.-':'Q', '.-.':'R', '...':'S', '-':'T',
         '..-':'U', '...-':'V', '.--':'W', '-..-':'X', '-.--':'Y',
         '--..':'Z', '.----':'1', '..---':'2', '...--':'3',
         '....-':'4', '.....':'5', '-....':'6', '--...':'7',
         '---..':'8', '----.':'9', '-----':'0'}
```

### DTMF (Dual-Tone Multi-Frequency)
```python
# 电话按键音，每个键 = 两个频率叠加
# 行频: 697, 770, 852, 941 Hz
# 列频: 1209, 1336, 1477, 1633 Hz
# 检测: 对每段信号做 FFT，找到两个峰值频率 → 查表

DTMF_MAP = {
    (697,1209):'1', (697,1336):'2', (697,1477):'3', (697,1633):'A',
    (770,1209):'4', (770,1336):'5', (770,1477):'6', (770,1633):'B',
    (852,1209):'7', (852,1336):'8', (852,1477):'9', (852,1633):'C',
    (941,1209):'*', (941,1336):'0', (941,1477):'#', (941,1633):'D',
}

# 也可用 multimon-ng:
# sox audio.wav -r 22050 -t wav mono.wav channels 1
# multimon-ng -a DTMF -t wav mono.wav
```

### SSTV (Slow-Scan Television)
```bash
# SSTV 在音频中编码图像
# 特征: 1200Hz 同步脉冲 + 1500-2300Hz 亮度
# 解码工具:
# Linux: qsstv (GUI)
# Python: pip install pysstv (编码), 解码较难

# 快速识别: 频谱中看到 1200Hz 周期脉冲 + 宽带调制
# 常用模式: Scottie 1, Scottie 2, Martin 1, Robot 36
```

### ADS-B (飞机应答)
```python
# 1090 MHz, PPM (Pulse Position Modulation)
# 采样率需 >= 2 Msps
# 前导: 8us (1010000101000000)
# 消息: 56 或 112 bits
# 工具: dump1090 可以直接解码 RTL-SDR 数据
# Python: pyModeS 库

# import pyModeS as pms
# msg = "8D40621D58C382D690C8AC2863A7"
# print(pms.adsb.callsign(msg))
# print(pms.adsb.position(msg, msg_ref, t0, t1, lat_ref, lon_ref))
```

### 频谱图隐写
```python
# 有时 flag 直接画在频谱图中 (waterfall)
# 生成高分辨率 spectrogram 查看
from scipy import signal as sig
import matplotlib.pyplot as plt

# 如果是音频文件
from scipy.io import wavfile
sr, audio = wavfile.read('signal.wav')
f, t, Sxx = sig.spectrogram(audio, fs=sr, nperseg=1024, noverlap=900)
plt.pcolormesh(t, f, 10*np.log10(Sxx+1e-10), cmap='inferno')
plt.ylim(0, sr//2)
plt.savefig('spectrogram.png', dpi=300)
# 查看图片中是否有文字/图案
```

---

## GNU Radio Guidance

### 何时使用 GNU Radio
- 需要实时处理或复杂信号链
- 题目提供 `.grc` 流图文件
- Python 脚本不够高效（大数据量）

### 常用 Block 组合
```
信号源 → 频率偏移校正 → 低通滤波 → 重采样 → 解调 → 解码
```

| 任务 | GNU Radio Block |
|------|----------------|
| 读文件 | File Source → Throttle |
| 频移 | Multiply + Signal Source (NCO) |
| 滤波 | Low Pass Filter / Band Pass Filter |
| 重采样 | Rational Resampler |
| FM 解调 | WBFM Receive / NBFM Receive |
| AM 解调 | Complex to Mag |
| 时钟恢复 | Symbol Sync (Mueller & Muller) |
| 星座解调 | Constellation Decoder |
| 输出 | File Sink / Audio Sink |

### 命令行执行 GRC
```bash
# .grc → Python 脚本
grcc flowgraph.grc -o .
python3 flowgraph.py

# 或直接用 gr_modtool + Python API
```

---

## Key Insights for RF CTF Challenges
- **Circles in constellation** = constant frequency offset (points rotate at fixed rate, forming a ring)
- **Spirals** = frequency offset that drifts over time (ring radius changes as amplitude/AGC also drifts). If you see points tracing outward arcs rather than closed circles, suspect combined frequency + gain instability
- **Blobs on grid** = correct sync, just noise
- **4-fold ambiguity**: DD carrier recovery can lock with 0/90/180/270 rotation - try all 4
- **Bandwidth vs symbol rate**: BW = Rs x (1 + alpha), where alpha is roll-off factor (0 to 1)
- **RC vs RRC**: "RC pulse shaping" at TX means receiver just samples (no matched filter needed); "RRC" means apply matched RRC filter at RX
- **Cyclostationary peak at Rs** confirms symbol rate even without knowing modulation order
- **AGC**: normalize signal power to match constellation power: `scale = sqrt(target_power / measured_power)`
- **GNU Radio's QAM-16 default mapping** is NOT Gray code - always check the provided constellation map
- **采样率未知?** 检查文件名、元数据、题目描述；或用 cyclostationary 分析估算符号率，再反推采样率

---

## Common Framing Patterns
- Idle/sync pattern repeating while link is idle
- Start delimiter (often a single symbol like 0)
- Data payload (nibble pairs for QAM-16: high nibble first, low nibble)
- End delimiter (same as start, e.g., 0)
- The idle pattern itself may contain the delimiter value - distinguish by context (is it part of the 16-symbol repeating pattern?)

---

## Quick Reference: CTF RF 解题流程

```
1. file * / xxd | head → 确认 IQ 格式
2. 加载 → FFT → waterfall → 识别调制类型
3. 频移到基带 → 滤波 → 下采样
4. 时钟恢复 → 载波恢复 → 星座图
5. 判决 → bits → bytes → flag
```

**卡住时检查**:
- 采样率是否正确?
- 是否需要频率校正?
- 字节序 (MSB first vs LSB first)?
- 数据是否还有编码层 (差分编码、Gray mapping、交织)?
