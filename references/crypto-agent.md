# Crypto Agent — 技术速查

> **适用版本**: PyCryptodome 3.x, SageMath 9.x+, Python 3.8+, gmpy2 2.1+

## Mission
密码学分析与攻击：古典密码破译、现代密码攻击、编码转换。

## When Selected
- RSA/AES/ECC/PRNG 相关
- `.sage` 文件或包含大数的 `.txt`
- 挑战描述含 encrypt/cipher/prime/modulus/lattice

---

## First Pass

1. 识别密码体系：古典 / RSA / AES / ECC / Hash / 自定义
2. 提取参数：n, e, c, p, q, d, key, iv, ciphertext
3. 判断攻击面：参数弱 / 实现缺陷 / 已知明文 / 侧信道

---

## 核心技术

### RSA 攻击

```python
from Crypto.Util.number import long_to_bytes, inverse

# 已知 p, q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

| 场景 | 攻击方法 |
|------|---------|
| e 小 (e=3) + m 小 | 直接开 e 次方根：`gmpy2.iroot(c, e)` |
| n 可分解 | factordb.com 或 yafu/msieve |
| e 极大 | Wiener 攻击：`d` 很小 |
| 共模攻击 | 同 n 不同 e 加密同 m：扩展欧几里得 |
| Coppersmith | `small_roots()` 解部分已知明文 |
| Hastad | 多组 (n_i, c_i) 同 e 小 → CRT + 开根 |
| Franklin-Reiter | 相关消息攻击 |
| Boneh-Durfee | d 小于 n^0.292 |

```python
# Wiener 攻击
import owiener
d = owiener.attack(e, n)

# Coppersmith (SageMath)
# P.<x> = PolynomialRing(Zmod(n))
# f = (known_high_bits + x)^e - c
# roots = f.small_roots(X=2^bits, beta=0.5)
```

### AES 攻击

| 模式 | 攻击 |
|------|------|
| ECB | Block shuffling, 选择明文 byte-at-a-time |
| CBC | Padding oracle, bit flipping, IV = key |
| CTR | Nonce reuse → XOR 密文 = XOR 明文 |
| GCM | Nonce reuse → 恢复 auth key |

```python
from Crypto.Cipher import AES

# CBC 解密
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# Padding oracle 攻击模板
def padding_oracle_attack(ciphertext, block_size=16):
    """逐字节恢复明文，需要 oracle(ct) → True/False"""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b''
    for block_idx in range(len(blocks)-1, 0, -1):
        known = b''
        for byte_idx in range(block_size-1, -1, -1):
            pad_val = block_size - byte_idx
            for guess in range(256):
                # 构造篡改块，使 padding 合法
                tampered = bytearray(blocks[block_idx-1])
                tampered[byte_idx] = guess
                for k in range(byte_idx+1, block_size):
                    tampered[k] ^= known[-(block_size-k)] ^ pad_val
                if oracle(bytes(tampered) + blocks[block_idx]):
                    known = bytes([guess ^ pad_val]) + known
                    break
        plaintext = known + plaintext
    return plaintext

# CBC bit-flipping
# 修改 block[i-1] 的第 j 字节 → block[i] 的第 j 字节翻转
# target_byte = original_byte ^ desired_byte
```

### DSA / ECDSA Nonce Reuse
```python
# 两个签名使用相同 nonce k → 恢复私钥
# s1 = k^(-1) * (h1 + r*x) mod q
# s2 = k^(-1) * (h2 + r*x) mod q
# k = (h1 - h2) * inverse(s1 - s2, q) mod q
# x = (s1*k - h1) * inverse(r, q) mod q

from Crypto.Util.number import inverse
k = ((h1 - h2) * inverse(s1 - s2, q)) % q
x = ((s1 * k - h1) * inverse(r, q)) % q
```

### Lattice / LLL 应用
```python
# SageMath — 用 LLL 解 knapsack / 部分已知明文
# 典型场景：已知 MSB/LSB 的 RSA, hidden number problem

# Coppersmith 找小根 (SageMath)
P.<x> = PolynomialRing(Zmod(n))
f = (known_high + x)^e - c
roots = f.small_roots(X=2^64, beta=0.5)

# Wiener 连分数攻击 (直接 Python)
# pip install owiener
import owiener
d = owiener.attack(e, n)
```

### Diffie-Hellman 攻击
```python
# 小子群攻击: g 的阶很小 → 穷举离散对数
# Pohlig-Hellman: p-1 光滑 → 分解后各素数幂上求 DLP
# Logjam: 使用预计算表（1024-bit 弱 DH 参数）

# SageMath
F = GF(p)
g = F(generator)
A = F(public_key)
# discrete_log(A, g)  # 仅限 p-1 光滑时可行
```

### CRT 工具
```python
# 中国剩余定理 — 常用于 Hastad 广播攻击
from sympy.ntheory.modular import crt
remainders = [c1, c2, c3]
moduli = [n1, n2, n3]
result, _ = crt(moduli, remainders)
# 然后 m = gmpy2.iroot(result, e)
```

### 古典密码

```bash
# Caesar / ROT brute-force
for i in $(seq 0 25); do echo "$cipher" | tr "$(echo {a..z} | tr -d ' ')" "$(echo {a..z} | tr -d ' ' | cut -c$((i+1))-; echo {a..z} | tr -d ' ' | cut -c1-$i)"; done

# Vigenère
# 使用 Kasiski 检测确定密钥长度
# 频率分析确定每位密钥

# 替换密码
# 频率分析: quipqiup.com 自动求解
```

| 密码 | 特征 |
|------|------|
| Caesar/ROT | 单表替换，移位 |
| Vigenère | 多表替换，周期性 |
| Playfair | 双字母替换，5x5 矩阵 |
| Rail Fence | 之字形写入 |
| Atbash | a↔z, b↔y... |
| Base64 | `A-Za-z0-9+/=` |
| Base32 | `A-Z2-7=` |

### Hash 攻击

```python
# MD5 弱比较 (PHP)
# "0e" 开头的 MD5 被当作科学记数法 == 0
# 已知: md5("QNKCDZO") = "0e830400451993494058024219903391"

# Length Extension
import hlextend
sha = hlextend.new('sha256')
new_data = sha.extend(b'extension', b'original', secret_len, known_hash)

# CRC32 碰撞/爆破
import binascii
target_crc = 0xDEADBEEF
# 4字节空间爆破: 约 2^32 次
```

### ECC
```python
# SageMath
# E = EllipticCurve(GF(p), [a, b])
# G = E(Gx, Gy)
# 离散对数: G.discrete_log(P)  # 仅限小群阶
# Smart attack: 当 #E(Fp) == p (异常曲线)
# MOV attack: embedding degree 小
# Pohlig-Hellman: 群阶可分解
```

### PRNG 攻击

| PRNG | 攻击 |
|------|------|
| Python random (MT19937) | 624 个 32-bit 输出 → 完全恢复状态 (randcrack) |
| LCG | 3 个连续输出 → 恢复参数 |
| LFSR | Berlekamp-Massey 算法恢复多项式 |

```python
# MT19937 state recovery
from randcrack import RandCrack
rc = RandCrack()
for i in range(624):
    rc.submit(observed_output[i])
predicted = rc.predict_getrandbits(32)
```

---

## SageMath 使用

```bash
# 启动 sage
sage

# 或直接运行脚本
sage script.sage
```

常用:
```python
# 因式分解
factor(n)

# 离散对数
discrete_log(target, base)  # mod p

# 格基约简
M = matrix(ZZ, [...])
M.LLL()

# 多项式求根
R.<x> = PolynomialRing(Zmod(n))
f = x^e - c
f.small_roots(X=2^256, beta=0.5)
```

### Lattice / 格密码

**识别信号**: "已知部分信息"、"截断输出"、"nonce 泄露"、"背包/子集和"

| 场景 | 技术 | 核心方法 |
|------|------|---------|
| RSA 已知明文/密钥高位 | Coppersmith | `f.small_roots(X=bound, beta=0.5)` |
| ECDSA/DSA nonce 泄露 | HNP → LLL | 构造 HNP 格矩阵 |
| 背包加密 | 低密度子集和 | `[I\|w].LLL()` 找 0/1 向量 |
| 截断 PRNG | CVP | Kannan embedding + LLL |
| RSA d < N^0.292 | Boneh-Durfee | 多元 Coppersmith |
| NTRU | 循环矩阵格 | `[I H; 0 qI].LLL()` |

详见 [knowledge/lattice-crypto.md](../knowledge/lattice-crypto.md)。

---

## CyberChef

位于 `tools/CyberChef_v10.19.4/`，打开 HTML 使用（交给用户在浏览器中操作）。

---

## Escalation

需要 `web-agent` 当：
- 加密是 web 认证流程的一部分 (JWT, session cookie)
需要 `misc-agent` 当：
- 需要实现侧信道或交互式 oracle
