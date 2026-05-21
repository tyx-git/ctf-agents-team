# 分类决策矩阵与时间管理

## 分类决策矩阵 (详细版)

Phase 2 Step 3 使用此矩阵进行题目分类。按优先级从上到下匹配，命中第一个即停止。

| 信号（文件/关键词） | 分类 | Specialist | 典型子类型 |
|---------------------|------|-----------|-----------|
| `.pcap/.pcapng/.evtx/.raw/.dd/.E01`, memory dump, disk image, "packet/traffic/spectrogram/side-channel" | Forensics | `forensics-agent` | PCAP 分析、内存取证、磁盘取证、侧信道 |
| ELF/PE + remote service, "buffer overflow/ROP/shellcode/libc/heap", crash on input | Pwn | `pwn-agent` | 栈溢出、堆利用、格式化字符串、seccomp bypass |
| ELF/PE 无 remote, `.pyc/.wasm`, algorithm recovery, packer, "obfuscate/unpack" | Reverse | `reverse-agent` | 静态分析、动态调试、反混淆、VM 逆向 |
| `.apk/.ipa`, JNI, smali, "android/ios/mobile" | Mobile | `mobile-agent` | APK 逆向、Frida hook、Flutter/RN |
| HTTP URL, PHP/JS/Python web source, "XSS/SQL/injection/JWT/SSRF/SSTI" | Web | `web-agent` | 注入、认证绕过、反序列化、SSRF |
| `.sage`, 大数 `.txt`, "RSA/AES/cipher/encrypt/prime/modulus/lattice/ECC/PRNG" | Crypto | `crypto-agent` | RSA 攻击、AES 模式攻击、格密码、PRNG |
| image/audio stego, encodings, jail, game, VM, QR, "sandbox/escape/encoding" | Misc | `misc-agent` | 隐写、编码、jail、游戏 |
| smart contract, `.sol`, Solidity, EVM, "blockchain/contract/deploy/reentrancy" | Misc (Blockchain) | `misc-agent` | 重入、闪电贷、存储碰撞 |
| ML model file (`.pt/.pkl/.h5/.onnx`), adversarial, "model/classify/AI/neural" | Misc (AI Security) | `misc-agent` | 对抗样本、Pickle RCE、Prompt Injection |

### 边界情况决策

| 场景 | 决策 |
|------|------|
| 有 remote + 有 binary 但主要考源码审计 | 以是否需要 exploit 为准：需 exploit → Pwn, 否则 → Web/Reverse |
| PCAP + 编码层 | 纯 PCAP 流量分析 → Forensics；PCAP 提取物含多层编码/隐写 → Forensics 提取后 Misc 解码 |
| Web + Crypto (JWT) | 先 Web 审计，Crypto 作为子问题 |
| RE + Pwn (先逆向再利用) | 并行: reverse 恢复逻辑 + pwn 确认攻击面 |

---

## 时间管理策略

### 题目选择优先级评分

Phase 1 入场后对所有题目评分，优先选择高分题：

| 因素 | 权重 | 评分标准 |
|------|------|---------|
| 分值/难度比 | 高 | 分值高但难度低的题优先 |
| 附件完整度 | 高 | 有源码 > 有二进制 > 仅描述 |
| 经验库命中 | 高 | exp/ 中有相似题 → 大幅加分 |
| 工具就绪度 | 中 | 所需工具已安装 > 需要安装 |
| 解题人数 | 中 | 已有人解出 → 说明非不可解 |

### 单题时间预算

可按比赛总时长缩放。

| 难度 | 预算 | 超时策略 |
|------|------|---------|
| 简单 (1-2 星) | 15-30 min | 超时 → 跳过，待回 |
| 中等 (3 星) | 30-60 min | 超时 → 检查是否有实质进展，有则续 10min |
| 困难 (4-5 星) | 60-90 min | 超时 → 标记 in_progress，切到其他题 |

### 收益递减检测

- 每 20 分钟检查一次：最近 2 个 Stage 是否有实质性新发现？
- 连续两个检查点无新发现 → 触发 Pivot 或标记 blocker 并跳过
- 在 task_plan.md 中记录每道题的实际用时

### 比赛阶段策略

| 阶段 | 时间占比 | 策略 |
|------|---------|------|
| 开场 (0-20%) | 侦察 | 快速扫描所有题，跑 Auto-Solve Quick Check |
| 中期 (20-70%) | 解题 | 按优先级攻克，严格执行时间预算 |
| 收尾 (70-100%) | 冲刺 | 回顾 in_progress 题目，优先离 flag 最近的 |
