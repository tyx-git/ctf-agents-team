---
title: "CTF Crypto - Lattice Cryptanalysis"
categories:
  - crypto
topics:
  - "lattice"
  - "LLL"
  - "Coppersmith"
  - "HNP"
  - "knapsack"
signals:
  - "LLL"
  - "Coppersmith"
  - "small root"
  - "HNP"
  - "nonce leak"
  - "knapsack"
  - "partial key"
load_when: "Crypto 题出现格密码、小根、偏置 nonce、部分密钥泄露或背包问题。"
---
# CTF Crypto - Lattice Cryptanalysis

> **适用版本**: SageMath 9.x+, Python 3.8+, fpylll, flatter
> **最后更新**: 2026-05-19
> **覆盖赛事**: HITCON, PlaidCTF, Google CTF, DEFCON Quals, CryptoHack

---

## Table of Contents
- [格密码基础](#格密码基础)
- [LLL / BKZ 算法](#lll--bkz-算法)
- [Coppersmith Method](#coppersmith-method)
- [Hidden Number Problem (HNP)](#hidden-number-problem-hnp)
- [Knapsack / 子集和问题](#knapsack--子集和问题)
- [NTRU 密码分析](#ntru-密码分析)
- [CTF 常见格构造模式](#ctf-常见格构造模式)
- [解题流程](#解题流程)

---

## 格密码基础

### 核心概念速查

| 概念 | 含义 |
|------|------|
| Lattice (格) | 由基向量 b1,...,bn 的整系数线性组合构成的离散点集 |
| Basis (基) | 生成格的一组线性无关向量 |
| SVP | Shortest Vector Problem — 找格中最短非零向量 |
| CVP | Closest Vector Problem — 找格中离目标最近的向量 |
| LLL | Lenstra-Lenstra-Lovász 格基约简算法，多项式时间近似 SVP |
| BKZ | Block Korkine-Zolotarev，比 LLL 更强但更慢 |
| Hermite factor | 约简质量指标，δ = ‖b1‖ / det(L)^(1/n) |

### 为什么格密码在 CTF 中重要

许多密码学问题可以**归约到格问题**：
- RSA 部分密钥恢复 → CVP
- ECDSA nonce 泄露 → HNP → SVP
- 背包密码 → 低密度子集和 → SVP
- PRNG 状态恢复（截断输出） → CVP
- 多项式小根（Coppersmith） → LLL

**识别信号**: 题目涉及"已知部分信息恢复完整秘密"或"在模数下求小解"。

---

## LLL / BKZ 算法

### SageMath LLL 基本模板

```python
# SageMath 中 LLL 的标准用法
M = matrix(ZZ, [
    [1, 0, 0, a1],
    [0, 1, 0, a2],
    [0, 0, 1, a3],
    [0, 0, 0, N],
])
L = M.LLL()

# 检查约简后的短向量
for row in L:
    print(row)
# 目标: 某一行的前几个元素是解
```

### BKZ (更强的约简)

```python
# 当 LLL 不够时用 BKZ
from fpylll import IntegerMatrix, BKZ as BKZ_algo
from fpylll.algorithms.bkz2 import BKZReduction

A = IntegerMatrix.from_matrix(M.change_ring(ZZ))
BKZ_algo.reduction(A, BKZ_algo.Param(block_size=25))

# 或 SageMath 内置
L = M.BKZ(block_size=25)

# flatter (更快的 LLL 替代, 需安装)
# 安装: git clone https://github.com/keeganryan/flatter && cd flatter && mkdir build && cd build && cmake .. && make
# 用法: 将矩阵写入文件 → flatter < input > output
```

### 缩放技巧 (Kannan embedding)

```python
# CVP → SVP: 将目标向量嵌入格中
# 原问题: 找 L 中离 t 最近的向量
# 转化: 构造新格
#   [B  0]
#   [t  M]
# 其中 M 是缩放因子, 约简后包含 t 的行即为解

def cvp_to_svp(B, target, scale=1):
    """将 CVP 转化为 SVP (Kannan embedding)"""
    n = B.nrows()
    m = B.ncols()
    M = matrix(ZZ, n+1, m+1)
    M[:n, :m] = B
    M[n, :m] = target
    M[n, m] = scale
    return M.LLL()
```

---

## Coppersmith Method

### 理论背景

**定理 (Coppersmith)**: 给定模多项式 f(x) ≡ 0 (mod N)，若 |x0| < N^(1/deg(f))，则可以在多项式时间内找到 x0。

**SageMath 接口**: `f.small_roots(X=bound, beta=1.0, epsilon=...)`

### RSA 已知明文高位

```python
# 场景: 已知 m 的高 (n-k) 位, 求低 k 位
# m = m_high + x, 其中 |x| < 2^k
n, e, c = ...  # RSA 参数
m_high = ...   # 已知高位

PR.<x> = PolynomialRing(Zmod(n))
f = (m_high + x)^e - c
roots = f.small_roots(X=2^k, beta=1.0)
if roots:
    m = m_high + int(roots[0])
    print(bytes.fromhex(hex(m)[2:]))
```

### RSA 已知 p 的高位 (Partial Factorization)

```python
# 场景: 已知 p 的高位, 恢复完整 p
# p = p_high + x, 其中 |x| < 2^k
n = ...
p_high = ...  # 已知的 p 高位 (低位补 0)
k = ...       # 未知位数

PR.<x> = PolynomialRing(Zmod(n))
f = p_high + x
roots = f.small_roots(X=2^k, beta=0.5)
if roots:
    p = p_high + int(roots[0])
    q = n // p
    assert p * q == n
```

### Stereotyped Message

```python
# 场景: m = "The flag is: XXXX", 已知前缀, 求 XXXX
prefix = b"The flag is: "
prefix_int = int.from_bytes(prefix, 'big') << (unknown_bytes * 8)

PR.<x> = PolynomialRing(Zmod(n))
f = (prefix_int + x)^e - c
roots = f.small_roots(X=256^unknown_bytes, beta=1.0)
```

### 多元 Coppersmith (Herrmann-May / Boneh-Durfee)

```python
# Boneh-Durfee: d < N^0.292 时可分解 N
# 比 Wiener (d < N^0.25) 更强
# 实现: https://github.com/mimoo/RSA-and-LLL-attacks

# Herrmann-May 简化版 (SageMath):
# 适用于 e*d = 1 + k*(p-1)*(q-1) 中 d 较小的情况
# 需要自行实现格构造 — 参见论文或 GitHub 实现
```

---

## Hidden Number Problem (HNP)

### 问题定义

给定: t_i, u_i 满足 |α·t_i - u_i| < B (mod p)，求 α。

**常见来源**: ECDSA/DSA nonce 部分泄露。

### ECDSA Nonce 泄露攻击

```python
# 场景: ECDSA 签名中 nonce k 的高 l 位已知
# 给定多组签名 (r_i, s_i, z_i) 和 k_i 的高位 a_i
# k_i = a_i + e_i, |e_i| < 2^(n-l)

# 构造格:
# 1. 从签名方程: s*k = z + r*d (mod q)
# 2. 代入 k = a + e: s*(a+e) = z + r*d
# 3. 整理: e = s^{-1}*(z + r*d) - a (mod q)
# 4. 构造 HNP 格

def ecdsa_hnp_attack(signatures, q, l):
    """
    signatures: [(r_i, s_i, z_i, a_i), ...] — a_i 是 k_i 的已知高位
    q: 曲线阶
    l: 已知位数
    """
    n = len(signatures)
    B = 2^(q.nbits() - l)  # 未知部分的界

    # 构造 t_i, u_i
    ts = []
    us = []
    for r, s, z, a in signatures:
        t = (r * inverse_mod(s, q)) % q
        u = (z * inverse_mod(s, q) - a) % q
        ts.append(t)
        us.append(u)

    # 构造格矩阵 (n+2) x (n+2)
    M = matrix(QQ, n+2, n+2)
    for i in range(n):
        M[i, i] = q
    for i in range(n):
        M[n, i] = ts[i]
        M[n+1, i] = us[i]
    M[n, n] = B / q  # 缩放
    M[n+1, n+1] = B

    L = M.LLL()

    # 从约简结果中提取私钥
    for row in L:
        d_candidate = int(row[n] * q / B) % q
        if d_candidate != 0:
            # 验证: 用候选私钥检查某个签名
            r0, s0, z0, _ = signatures[0]
            k_check = (inverse_mod(r0, q) * (s0 * d_candidate - z0)) % q
            # 检查 k_check 的高位是否匹配
            if k_check >> (q.nbits() - l) == signatures[0][3] >> (q.nbits() - l):
                return d_candidate
    return None
```

### DSA Nonce Reuse (非格方法, 但常一起出题)

```python
# 两次签名用相同 k:
# s1 = k^{-1}(z1 + r*d) mod q
# s2 = k^{-1}(z2 + r*d) mod q
# → k = (z1 - z2) / (s1 - s2) mod q
# → d = (s1*k - z1) / r mod q
k = ((z1 - z2) * inverse_mod(s1 - s2, q)) % q
d = ((s1 * k - z1) * inverse_mod(r, q)) % q
```

---

## Knapsack / 子集和问题

### 低密度背包攻击

```python
# 给定公钥 w = [w1, w2, ..., wn] 和密文 S = sum(x_i * w_i)
# 求 x_i ∈ {0,1}
# 密度 d = n / max(log2(w_i)) < 0.9408 时 LLL 可解

def knapsack_attack(weights, target):
    """低密度背包 LLL 攻击"""
    n = len(weights)
    N = ceil(sqrt(n) / 2)  # 缩放因子

    # 构造格矩阵 (n+1) x (n+1)
    M = matrix(ZZ, n+1, n+1)
    for i in range(n):
        M[i, i] = 1          # 单位矩阵部分
        M[i, n] = N * weights[i]  # 背包权重
    M[n, n] = N * (-target)  # 目标值

    L = M.LLL()

    # 在约简结果中找 0/1 解
    for row in L:
        if row[n] == 0:  # 最后一列为 0
            bits = list(row[:n])
            # 检查是否全是 0 或 1 (可能需要取反)
            if all(b in (0, 1) for b in bits):
                if sum(b * w for b, w in zip(bits, weights)) == target:
                    return bits
            bits_neg = [1 - b for b in bits]
            if all(b in (0, 1) for b in bits_neg):
                if sum(b * w for b, w in zip(bits_neg, weights)) == target:
                    return bits_neg
    return None
```

---

## NTRU 密码分析

```python
# NTRU: h = f^{-1} * g (mod q) in Z[x]/(x^N - 1)
# 公钥 h, 参数 N, q
# f, g 是短多项式 (系数小)

# 格攻击: 构造 2N x 2N 矩阵
# [I  H]
# [0  qI]
# 其中 H 是 h 对应的循环矩阵
# LLL 约简后找到 (f, g)

def ntru_attack(h_coeffs, N, q):
    """NTRU 格攻击"""
    # 构造循环矩阵 H
    H = matrix(ZZ, N, N)
    for i in range(N):
        for j in range(N):
            H[i, j] = h_coeffs[(j - i) % N]

    # 构造完整格
    M = matrix(ZZ, 2*N, 2*N)
    M[:N, :N] = identity_matrix(N)
    M[:N, N:] = H
    M[N:, N:] = q * identity_matrix(N)

    L = M.LLL()
    # 第一行通常是 (f, g)
    f = list(L[0][:N])
    g = list(L[0][N:])
    return f, g
```

---

## CTF 常见格构造模式

### 模式 1: 截断 LCG 状态恢复

```python
# LCG: x_{i+1} = a*x_i + b (mod m)
# 只观察到高位 y_i = x_i >> k (截断)
# 恢复完整状态

def truncated_lcg_attack(outputs, a, b, m, k):
    """截断 LCG 格攻击"""
    n = len(outputs)
    # x_i = y_i * 2^k + e_i, |e_i| < 2^k

    # 构造关系: e_{i+1} = a*e_i + (a*y_i*2^k + b - y_{i+1}*2^k) mod m
    # 整理为格问题

    M = matrix(ZZ, n+1, n+1)
    M[0, 0] = m
    for i in range(1, n):
        M[i, 0] = a^i % m
        M[i, i] = 1
    M[n, 0] = sum(a^i * (a*outputs[i]*2^k + b) for i in range(n)) % m
    M[n, n] = 2^k

    L = M.LLL()
    # 从结果中提取 e_0 → x_0 = y_0 * 2^k + e_0
    return L
```

### 模式 2: RSA 部分私钥恢复

```python
# 已知 d 的低 n/4 位 → 可恢复完整 d
# e*d = 1 + k*(n - p - q + 1)
# e*d_low ≡ 1 + k*(-p - q + 1) (mod 2^(n/4))

# 遍历 k (通常 k < e), 对每个 k 用 Coppersmith 恢复 p
def partial_d_attack(n, e, d_low, bits):
    """RSA 部分私钥恢复 (已知低位)"""
    for k in range(1, e):
        # e*d_low - 1 ≡ k*(n - p - q + 1) mod 2^bits
        # → p + q ≡ n + 1 - (e*d_low - 1)/k mod 2^bits
        if (e * d_low - 1) % k != 0:
            continue
        pq_sum_mod = (n + 1 - (e * d_low - 1) // k) % (2^bits)

        # 构造多项式: x^2 - pq_sum_mod*x + n ≡ 0 (mod 2^bits)
        PR = PolynomialRing(Zmod(n), 'x')
        x = PR.gen()
        f = x + pq_sum_mod  # 简化: p ≡ pq_sum_mod - q
        roots = f.small_roots(X=2^(bits//2), beta=0.5)
        if roots:
            p = int(roots[0])
            if n % p == 0:
                return p, n // p
    return None
```

### 模式 3: 多组线性同余求秘密

```python
# 给定 a_i * s + e_i ≡ b_i (mod q), |e_i| < B
# 这是 LWE (Learning with Errors) 的特殊情况

def lwe_attack(a_list, b_list, q, B):
    """简单 LWE / 带噪线性方程组"""
    n = len(a_list)
    M = matrix(ZZ, n+2, n+2)
    for i in range(n):
        M[i, i] = q
    for i in range(n):
        M[n, i] = a_list[i]
        M[n+1, i] = b_list[i]
    M[n, n] = 1
    M[n+1, n+1] = B

    L = M.LLL()
    # s = row[n] 对应位置
    for row in L:
        s_candidate = int(row[n]) % q
        if s_candidate != 0:
            # 验证
            if all(abs((a * s_candidate - b) % q) < B or
                   abs((a * s_candidate - b) % q - q) < B
                   for a, b in zip(a_list, b_list)):
                return s_candidate
    return None
```

---

## 解题流程

```
1. 识别格密码信号:
   - "已知部分信息" / "泄露了 k 位" / "截断输出"
   - 涉及 LLL / lattice / basis / short vector
   - ECDSA/DSA + nonce leak
   - 背包/子集和
   - RSA + partial key / small d / stereotyped message

2. 确定攻击类型:
   - 部分信息 RSA → Coppersmith (small_roots)
   - Nonce 泄露签名 → HNP + LLL
   - 背包加密 → 低密度攻击
   - 截断 PRNG → 格归约
   - NTRU → 循环矩阵格

3. 构造格矩阵:
   - 确定目标: 什么是"短向量"？(解通常是小整数/0-1向量)
   - 确定维度: 用多少组方程？(更多 = 更准确，但更慢)
   - 缩放: 确保不同列的量级匹配 (Kannan embedding 技巧)

4. 约简与提取:
   - 先 LLL，检查第一行
   - 不行就 BKZ (block_size 从 20 开始，逐步增加到 40)
   - 从约简后的矩阵中提取目标值
   - 验证: 代入原方程检查

5. 常见陷阱:
   - 矩阵维度太大 (>100) → LLL 很慢，考虑减少方程数
   - 缩放不当 → 目标向量不是最短的
   - beta 参数 → small_roots 中 beta=0.5 表示因子约 N^0.5 大小
   - 整数溢出 → 用 SageMath 的 ZZ 而非 Python int
```
