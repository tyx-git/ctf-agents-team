# Orchestrator Playbook

## Lead Agent 职责

Lead Agent（主对话）拥有：
- 比赛目录扫描与题目分类
- 环境 bootstrap
- Specialist reference 加载决策
- 并行 Agent 调度（如需）
- 结果集成与矛盾解决
- 置信度判定
- wp.process 与最终 WP 管理
- flag.txt 维护

**不要把初始分类委托出去。** 先本地分类，再决定是否需要并行。

---

## Specialist 选择矩阵

| 题目特征 | Primary | Secondary 触发条件 | 需加载的 Knowledge |
|---------|---------|-------------------|-------------------|
| ELF/PE + remote service + crash/leak | pwn-agent | 函数恢复、去混淆阻塞 exploit → reverse | linux-privesc |
| APK/IPA/smali/JNI | mobile-agent | native so 逻辑主导 → reverse | — |
| image/audio/archive/PCAP/encoding | misc-agent | 出现 native 逻辑或 web 层 | pyjails, bashjails, encodings, games-and-vms, rf-sdr, dns |
| smart contract/.sol/EVM/Solidity | misc-agent | 需要 crypto 分析 → crypto | blockchain |
| ML model/.pt/.pkl/adversarial/LLM | misc-agent | 含 pickle RCE → forensics 视角 | ai-security |
| URL/source audit/auth/injection/SSTI | web-agent | PCAP/blob 提取主导 → misc | — |
| stripped binary/algorithm/packer | reverse-agent | 逻辑恢复后需 exploit → pwn; 或 mobile 上下文 | — |
| RSA/AES/cipher/lattice/PRNG | crypto-agent | 需要实现侧信道 → misc; 需要 web 交互 → web | — |
| disk/memory/traffic/side-channel | forensics-agent | 发现 exploit 需 replay → pwn; 编码层 → misc | — |

---

## 知识加载指南

### 何时读取 Knowledge 文件

Knowledge 文件是深度技术参考（数百行），**不要一次全部加载**。按需读取：

| 遇到的情况 | 读取 |
|-----------|------|
| Python jail/sandbox | knowledge/pyjails.md |
| Bash jail/restricted shell | knowledge/bashjails.md |
| QR/编码/esolang/多层解码 | knowledge/encodings.md |
| Verilog/Gray code/SMS PDU/MaxiCode | knowledge/encodings-advanced.md |
| RF/IQ/SDR/QAM | knowledge/rf-sdr.md |
| DNS zone/rebinding/ECS/tunnel | knowledge/dns.md |
| WASM/VM/Z3/K8s/game | knowledge/games-and-vms.md |
| Cookie brute/WebSocket/De Bruijn/BF | knowledge/games-and-vms-2.md |
| Docker escape/taint bypass/memfd/shred | knowledge/games-and-vms-3.md |
| XSLT/JS tricks/OEIS/bytebeat | knowledge/games-and-vms-4.md |
| Linux privesc/sudo/cron/NFS/PG | knowledge/linux-privesc.md |
| CTFd API 交互 | knowledge/ctfd-navigation.md |
| Blockchain/Solidity/EVM | knowledge/blockchain.md |
| AI/ML 模型/对抗样本/Prompt Injection | knowledge/ai-security.md |

### 读取策略

1. 先读 specialist reference（~50 行技术速查）
2. 遇到具体技术方向时再加载对应 knowledge 文件
3. knowledge 文件内有目录，可以只读取相关章节

---

## 并行调度规则

使用 Claude Code 的 Agent tool 进行并行仅当：
- 题目明确需要两个 category 的独立工作面
- 两个方向不共享写入目标
- 预计并行比串行显著节省时间

**典型并行模式**：

| 场景 | Agent A | Agent B |
|------|---------|---------|
| RE + Pwn | reverse: 静态分析恢复逻辑 | pwn: checksec + 远程交互 |
| Web + Crypto | web: 路由审计 | crypto: JWT/签名分析 |
| Forensics + Misc | forensics: PCAP 提取 | misc: 编码/解码管道 |

**不要并行** 当：
- 下一步取决于当前步结果
- 题目足够简单，串行 5 分钟内能解
- 只有一个工作面

---

## Agent 返回结果规范

并行 Agent 返回时，Lead Agent 需要结构化地处理结果。

### Agent Prompt 模板

启动 Agent 时，在 prompt 末尾附加：
```
请在分析完成后，按以下格式总结结果：

## 结论
- **hypothesis**: [一句话核心假设]
- **confidence**: guess / evidence / verified
- **evidence**: [支持假设的关键证据，列表]

## 产物
- [创建/修改的文件列表]

## 下一步建议
- [基于发现的推荐行动，列表]

## 阻塞项
- [如有] 需要其他 specialist 或用户协助的事项
```

### 结果合并协议

当多个 Agent 返回后：

1. **无冲突**: 两个 Agent 的发现互补 → 直接合并到 wp.process 新 Stage
2. **部分冲突**: 假设不同但证据不矛盾 → 保留两个 hypothesis，优先追证据更强的
3. **直接冲突**: 结论矛盾 → Lead Agent 独立评估证据质量，选择更可靠的路线
   - 如无法判断，串行验证两个方向（先验证成本更低的）

### 合并输出模板

```markdown
## Stage XXX: 并行结果集成
**Agent A (reverse)**: [一句话结论], confidence=evidence
**Agent B (pwn)**: [一句话结论], confidence=guess
**集成结论**: [Lead Agent 的综合判断]
**冲突解决**: [如有] 选择了 A 因为 [原因]
**下一步**: [基于集成结果的行动]
```

---

## 集成循环

每次分析步骤完成后：

1. 提取本步的 hypothesis 和 evidence
2. 记录创建/修改的文件
3. 与 wp.process 中已有结论对比
4. 发现矛盾立即解决，不要让并行假说漂移
5. 更新 wp.process 当前 Stage
6. 维护一条可复现的解题主线

**Re-dispatch 触发条件**：
- 缺少工具或提取产物
- exploit 被逻辑恢复阻塞
- 逻辑已恢复但无法证明 flag 路径
- 分类判断已改变

**不要仅因为"另一个角度有趣"就 re-dispatch。**

---

## 置信度标准

全局统一：

| 级别 | 含义 |
|------|------|
| `guess` | 有可能的线索，证据不足 |
| `evidence` | 强证据/产物，但未端到端复现 |
| `verified` | 可复现的 flag 路径，或 flag 已被比赛平台接受 |

**只有 Lead Agent 可以做最终 verified 判定。**

---

## WP 与 Flag 维护

### wp.process 更新时机
- Phase 2 分类完成后创建
- 每完成一个分析步骤更新一个 Stage
- 发现 flag 候选时标注 status 变更
- 确认失败路径时记录到失败路径表

### 最终 WP 写作时机
- flag 达到 `verified` 后
- 格式严格遵循 references/wp-format.md

### flag.txt 更新
- 只有 verified 后才写入
- 格式：`[类型][题目名称]flag字符串`
- 类型标签：`Pwn`, `Web`, `Re`, `Mobile`, `Misc`
- 同 key 存在时更新而非追加

---

## 终止条件

**停止扩展调查** 当：
- Lead Agent 可以复现一条 dominant 解题路径
- flag 已被平台接受
- 剩余旁路不会改变最终答案

**题目未解决时**：
- 更新 wp.process 到最新状态
- 在最后 Stage 写明当前 blocker 和推荐下一步
- 更新 task_plan.md 标记为 in_progress
- 不要发起更多投机性工作

---

## Auto-Solve Quick Patterns

**在深度分析前，先用 30 秒检查这些快速路径**：

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 源码/Git 泄露 | `curl -s http://target/.git/HEAD` | Web 题 30%+ |
| robots.txt | `curl -s http://target/robots.txt` | 禁止目录含 flag |
| 默认凭据 | admin:admin, admin:password, root:toor | 弱密码题 |
| Flag 明文 | `strings * \| grep -iE 'flag\|ctf'` | Misc/Forensics |
| 注释/备份 | `curl http://target/index.php.bak` | .bak/.swp/.DS_Store |
| 已知 CVE | 识别框架+版本 → 查 CVE | Web/Pwn |
| Base64 | 识别 Base64 字符串 → 直接解码 | Misc 编码题 |

---

## CTFd Flag 提交

当比赛使用 CTFd 平台且用户已提供 API Token 时：

```bash
# 提交 flag (challenge_id 从 API 获取)
curl -s -X POST https://ctf.example.com/api/v1/challenges/attempt \
  -H "Authorization: Token ctfd_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"challenge_id": ID, "submission": "flag{...}"}'

# 获取题目列表
curl -s https://ctf.example.com/api/v1/challenges \
  -H "Authorization: Token ctfd_TOKEN" | jq '.data[] | {id, name, category}'
```

详见 [knowledge/ctfd-navigation.md](../knowledge/ctfd-navigation.md)。

---

## Windows 操作委托

当解题过程需要 Windows 工具时：

1. 在 wp.process 当前 Stage 中标注"需要 Windows 端操作"
2. 向用户提供精确指令：
   ```
   请在 Windows 端执行：
   1. 打开 x64dbg，加载 challenge.exe
   2. bp 0x401234
   3. 运行到断点
   4. 执行: dump rsp L100
   5. 将输出粘贴回来
   ```
3. 等待用户返回结果
4. 基于结果继续解题，将结果记录到 wp.process
