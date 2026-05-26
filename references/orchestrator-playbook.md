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
- **flag.log 唯一写者**（子 Agent 仅产出 flag.found 中间文件）
- 经验库最终合并（子 Agent 仅产出 exp_candidate.jsonl）

**不要把初始分类委托出去。** 先本地分类，再决定是否需要并行。

---

## Specialist 选择矩阵

| 题目特征 | Primary | Secondary 触发条件 | 需加载的 Knowledge |
|---------|---------|-------------------|-------------------|
| ELF/PE + remote service + crash/leak | pwn-agent | 函数恢复、去混淆阻塞 exploit → reverse | linux-privesc |
| APK/IPA/smali/JNI | mobile-agent | native so 逻辑主导 → reverse | — |
| image/audio/archive/PCAP 提取物/编码 | misc-agent | 出现 native 逻辑或 web 层 | pyjails, bashjails, encodings, games-and-vms, rf-sdr, dns |
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
| Lattice/LLL/Coppersmith/HNP/格密码 | knowledge/lattice-crypto.md |

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
- 当前会话已存在团队上下文时，**复用现有 team**；不要重复调用 `TeamCreate`
- 只有在上一轮并行批次已经结束，且需要开启全新独立批次时，才先 `TeamDelete` 再 `TeamCreate`

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

### Agent 启动上下文模板

启动 Agent 时，在 prompt **开头**附加当前上下文摘要，确保 Agent 不从零开始：

```
## 当前上下文
- **题目**: [名称] ([分类])
- **远程目标**: [IP:Port / URL]（如有）
- **附件**: [文件列表]
- **已知发现**:
  - [wp.process 最近 Stage 的 1-3 条关键结论]
- **当前假设**: [hypothesis], confidence=[guess/evidence/verified]
- **你的任务**: [具体分析方向，如"静态分析 binary 恢复加密函数逻辑"]
- **约束**:
  - [已排除的路径/不要重复的操作]
  - [不要修改的文件]
```

**上下文来源优先级**：
1. wp.process 最后一个 Stage 的"发现"和"结论"
2. task_plan.md 中该题的备注
3. 上一个 Agent 的返回结果（如果是链式调度）

**最小上下文原则**：只传递与该 Agent 任务相关的信息，避免传递整个 wp.process（浪费 Agent 的 context window）。

---

### Agent Prompt 模板

启动 Agent 时，在 prompt **末尾**附加：
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

### flag.log 维护（Lead Agent 唯一写者）

**核心原则**：仅 Lead Agent 有权写入比赛根目录的 `flag.log`。子 Agent 不直接写入。

**flag.found 中间文件格式**（子 Agent 在题目目录根创建）：
```
FLAG: flag{example_here}
STATUS: solved
TIMESTAMP: 2026-05-21T14:30:00Z
```

**flag.log 汇总规则**：
- 格式：`[类型][题目名称] flag字符串`（注意题目名称后有空格）
- 类型标签：`Pwn`, `Web`, `Re`, `Mobile`, `Misc`, `Crypto`, `Forensics`
- **新题加入**：flag 未在 `flag.log` 中出现 → 追加记录
- **已存在题目**：`flag.log` 中已有该题记录 → **不覆盖**
- **多份 flag.found 冲突**：同一题目有多个 `flag.found`（如重复调度）→ 以 mtime 最新者为准
- 汇总完成后更新 task_plan.md 中对应题目状态为 `verified`

**写入时机**：
- 单题模式：Lead Agent 直接解题后立即写入
- Solo 模式：所有品类 Agent 返回后，Lead Agent 统一扫描 flag.found 并汇总写入

### 经验库回写（去并发化）

**子 Agent 产出**：每个子 Agent 将经验写入题目目录内的 `exp_candidate.jsonl`，每行一条完整 JSON 记录。

**⚠️ 凭据过滤**：`exp_candidate.jsonl` 中禁止包含 `token`、`api_key`、`session`、`authorization`、`cookie`、`password` 等敏感字段。CTFd Token 仅允许保留在 `findings.md` 中本地使用。

**Lead Agent 合并**：
1. 收集所有 `exp_candidate.jsonl`
2. 逐条校验 JSON 格式合法性
3. 对每条记录使用 `AddExp.py --commit` 追加（自动去重 + 同步全部仓库）：
   ```bash
   python3 .skills/ctf-agents-team/scripts/AddExp.py --commit '<json_line>'
   ```
   `AddExp.py` 自动发现 `~/.claude/skills/ctf-agents-team/exp/` 和 `~/.codex/skills/ctf-agents-team/exp/` 并同时写入，确保两个用户级仓库一致。**不写入项目本地 `.skills/ctf-agents-team/exp/`**（如需将用户级最新内容拉到项目本地，使用 `python3 .skills/ctf-agents-team/scripts/AddExp.py --debug-syn` 手动同步）。
4. 合并完成后执行 `python3 .skills/ctf-agents-team/scripts/ClearExp.py` 清理所有 `exp_candidate.jsonl`

### 题目状态枚举

| 状态 | 含义 | 触发条件 |
|------|------|---------|
| `enumerated` | 题目已发现，尚未分配 | Lead Agent 完成侦察/分类后设置 |
| `in_progress` | 子 Agent 已接管，正在解题 | Lead Agent 分发任务后标记 |
| `solved` | 解出 flag，已生成 flag.found | 子 Agent 写入 flag.found 后 |
| `verified` | Lead Agent 已确认并汇入 flag.log | Lead Agent 写入 flag.log 后 |

状态流转：`enumerated → in_progress → solved → verified`

---

## Solo 模式调度

### Solo vs 单题并行的区别

| 维度 | 单题内并行 Agent | Solo 品类 Agent |
|------|----------------|----------------|
| 职责 | 单题的单个分析方向 | 该品类下所有题目的完整解题 |
| 生命周期 | 一次分析即返回 | 完成所有题目后返回 |
| wp.process | 不管理 (Lead Agent 管) | 每题独立创建和管理 |
| 最终 WP | 不写 | 每题独立写 |
| exploit.py | 不写 | Pwn/Web/Crypto 等可脚本化的题创建 |
| flag | 不直接产出 | 每题 flag 写入 `flag.found`（不写 flag.log） |
| 经验库 | 不更新 | 写入题目目录 `exp_candidate.jsonl`（Lead Agent 最终合并） |

### Solo 品类 Agent Prompt 模板

启动品类 Agent 时使用以下 prompt 结构：

```
你是一名专业 CTF 选手，专精 [品类名称] 方向。你将独立解决以下题目，按顺序逐题作答。

## 比赛信息
- **比赛名称**: [比赛名]
- **品类**: [web/pwn/re/misc/crypto/forensics/mobile]
- **总时间预算**: [Lead Agent 计算填入] 分钟
- **题目列表** (按优先级排序，最多 5 道):
  1. [题目名A] — [目录路径]
  2. [题目名B] — [目录路径]
  ...

## 你可以加载的技术参考
- 读取 `.skills/ctf-agents-team/references/[品类]-agent.md` 获取技术速查（如 `.skills/ctf-agents-team/references/pwn-agent.md`）
- 按需读取 `.skills/ctf-agents-team/knowledge/` 下的深度文档（参见 orchestrator-playbook.md 知识加载指南）

## 经验库
- 读取 `.skills/ctf-agents-team/exp/[品类]/[品类].jsonl` 查看历史经验（如 `.skills/ctf-agents-team/exp/pwn/pwn.jsonl`）
  - **Mobile Agent 注意**：Mobile 经验存储在 `.skills/ctf-agents-team/exp/re/re.jsonl`（通过 `challenge: "Mobile"` 字段区分），请读取该文件并在搜索时用 `grep '"challenge": "Mobile"'` 过滤 Mobile 相关条目。
- 解完每道题后，若有可复用经验则写入题目目录下 `exp_candidate.jsonl`（纯模板题/签到题跳过）
- **注意**：经验库路径是 `.skills/ctf-agents-team/exp/`，不是比赛目录；写入经验候选到题目目录，由 Lead Agent 最终合并

## 每道题的工作流程
对每道题依次执行：
1. **侦察** — 进入题目目录，file/strings/xxd/curl 等初步分析
2. **Quick Check** — 30 秒快速筛选（按品类执行对应模板，见 Auto-Solve Quick Patterns 章节）
3. **分类确认** — 确认题目确实属于本品类（若发现分类错误，在 wp.process 中标注并继续解题，不回交重分发）
4. **解题** — 应用技术参考中的方法，遵守 2-Action Rule（每 2 次操作更新 wp.process）
5. **验证** — 确认 flag，达到 verified
6. **交付（立即执行，不要延迟）** — 创建 题目名称.md + exploit.py + flag.found + exp_candidate.jsonl（不写 flag.log，由 Lead Agent 汇总）

**⚠️ 逐题交付**：每道题 verified 后立即完成全部交付再进入下一题。不要等所有题做完再统一写 — 上下文压缩会丢失信息。

## 时间管理
- 简单题 ≤30min, 中等题 ≤60min, 困难题 ≤90min
- **总时间预算**: [由 Lead Agent 计算填入，公式: min(题目数 × 45min, 180min)]
- 超过总时间预算后，停止当前题目，立即返回已完成的结果
- 每 20 分钟检查收益递减
- 3-Strike Protocol: 同方向 3 次失败 → 停止该题（状态保持 in_progress，标注 blocker），继续下一题
- **不要在一道题上恋战** — 比赛时间有限
- **每解完一题立即交付** — 防止 context 饱和后丢失信息

## 输出约定
- 每道题创建 wp.process（Stage 编号制）
- verified 后**立即**创建 题目名称.md（如 `overflow.md`，**禁止** `wp：` 或 `wp:` 前缀）
- verified 后创建 exploit.py（Pwn/Web/Crypto 等可脚本化的题必须写，纯手工分析题可跳过）
- verified 后创建 flag.found（三行格式）：
  ```
  FLAG: flag{...}
  STATUS: solved
  TIMESTAMP: 2026-05-21T14:30:00Z
  ```
- **⚠️ 不写 flag.log** — 仅 Lead Agent 有权写入，你只负责 flag.found
- 有价值的经验写入题目目录下 `exp_candidate.jsonl`（每行一条 JSON，遵循经验库 schema）
- 题目无法解决时：wp.process 最后 Stage 写明 blocker，状态保持 `in_progress`

## 完成后返回
所有题目处理完毕后，返回以下格式的摘要：

### [品类] 解题摘要
| 题目 | 状态 | Flag | 用时 |
|------|------|------|------|
| 题目A | solved | flag{...} | 25min |
| 题目B | in_progress (blocker) | — | 45min (blocker: ...) |
...
```

### Solo Dispatch 流程

Lead Agent 在 Phase 1.5 中的具体操作：

1. **扫描** — 遍历比赛目录下所有品类子目录，收集题目列表
   - 标准品类列表：`web`, `pwn`, `re`, `misc`, `crypto`, `forensics`, `mobile`
   - **别名映射**: `reverse/` → `re`，大小写不敏感（`Web/` → `web`）
   - **跳过已解题目**：若题目目录内已存在 `flag.found` 且 TIMESTAMP 有效，视为 solved，直接排除
2. **分组** — 按品类分组，跳过空品类
3. **排序** — 每个品类内按优先级排序（经验库命中 > 附件完整度 > 文件大小）
4. **Dispatch Gate（强制前置条件）** — 逐品类检查，仅满足以下全部条件才启动 Agent：
   - ✓ 品类目录存在（实际 `ls -d` 成功）
   - ✓ 品类目录下至少有 1 个未解题目子目录（无 `flag.found` 或 TIMESTAMP 无效）
   - ✗ 任一条件不满足 → **跳过该品类，不启动 Agent**，在 task_plan.md 记录跳过原因
5. **Dispatch** — 对每个通过 Gate 的品类，用 Agent tool 启动一个品类 Agent
   - 所有品类 Agent **并行启动**（单条消息内多个 Agent tool call）
   - **TeamContext**：若当前已在 `default` 或其他 team 中，直接复用该 team；不要为了分发再次 `TeamCreate`
   - 每个 Agent 使用上方的品类 Agent Prompt 模板
   - **单 Agent 题目上限 5 道**，超出则拆分为多个 Agent
   - 品类 Agent Prompt 中注明总时间预算: min(题目数 × 45min, 180min)
6. **等待与校验** — Agent 返回后执行返回校验（见下方）
7. **汇总** — 校验 flag.log 完整性，补充遗漏，更新 task_plan.md

### Agent 返回校验与容错

品类 Agent 返回后，Lead Agent 对每个 Agent 的结果进行校验：

| 返回状态 | 判定条件 | 处理 |
|---------|---------|------|
| **正常** | 包含结构化摘要表（题目/状态/Flag/用时） | 正常汇总 |
| **部分完成** | 返回内容不完整但有部分结果 | 提取可用信息，标记剩余题目为 in_progress |
| **空返回** | Agent 返回为空或仅有错误信息 | 扫描品类目录下已产出文件，标记所有题目为 in_progress |
| **超时** | Agent 未在预期时间内返回 | 同空返回处理 |

**容错操作**：
1. 在 `progress.md` 记录失败的品类 Agent 及原因
2. 扫描该品类目录：`find $CATEGORY -name "flag.found" -type f` — 检查是否有部分产出
3. 校验每个 `flag.found` 格式（FLAG/STATUS/TIMESTAMP 三行完整）→ 合法者视为 solved，汇入 flag.log
4. 未完成的题目标记为 `in_progress`，在最终摘要中报告给用户
5. **不重试整个品类 Agent** — 成本高且可能重复已完成工作，由用户决定后续

### flag 汇总协议（Solo 模式）

**子 Agent 职责**：
- 解出 flag 后在题目目录根创建 `flag.found`（三行格式：FLAG/STATUS/TIMESTAMP）
- **不直接写入** `flag.log` — 避免并发写入冲突
- 子 Agent 完成解题后自行确认 `flag.found` 已正确写入，作为自检闭环

**Lead Agent 汇总**（Step 4 执行）：
- 扫描所有题目目录：`find $COMPETITION_DIR -name "flag.found" -type f`
- 校验每个 `flag.found` 格式合法性（三行、FLAG 字段非空、TIMESTAMP 有效）
- 按汇总规则写入 `flag.log`（新题追加、已存在不覆盖、冲突取 mtime 最新）
- 写入成功后标记题目状态为 `verified`

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

### 通用（所有品类）

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| Flag 明文 | `strings * \| grep -iE 'flag\|ctf'` | Misc/Forensics |
| Base64 | 识别 Base64 字符串 → 直接解码 | Misc 编码题 |
| 经验库命中 | `grep -ri "关键词" .skills/ctf-agents-team/exp/web/web.jsonl ...` (6 库全部) | 历史相似题 |

### Web

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 源码/Git 泄露 | `curl -s http://target/.git/HEAD` | Web 题 30%+ |
| robots.txt | `curl -s http://target/robots.txt` | 禁止目录含 flag |
| 默认凭据 | admin:admin, admin:password, root:toor | 弱密码题 |
| 注释/备份 | `curl http://target/index.php.bak` | .bak/.swp/.DS_Store |
| 已知 CVE | 识别框架+版本 → 查 CVE | Web/Pwn |

### Pwn

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 保护机制 | `checksec --file=[binary]` | 无 canary/PIE → 简单溢出 |
| 架构确认 | `file [binary]` | 32/64 位、静态/动态链接 |
| 硬编码 flag | `strings [binary] \| grep -i flag` | 签到 Pwn |
| 远程探测 | `echo test \| nc [host] [port]` | 观察交互格式 |

### Reverse

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 文件类型 | `file [binary]` | ELF/PE/Mach-O/pyc |
| 关键字符串 | `strings [binary] \| grep -iE "flag\|key\|secret"` | 明文 flag/密钥 |
| 入口点速览 | `objdump -d [binary] \| head -50` | 简单逻辑直接可见 |

### Crypto

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 密文格式 | `cat [challenge_file]` 观察格式 | 识别编码/算法类型 |
| 简单解码 | `echo "..." \| base64 -d` 或 `xxd -r -p` | 伪 Crypto 编码题 |
| RSA 弱模数 | 检查公钥文件模数位数、是否可分解 | 小 n / 共模攻击 |

### Forensics

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 真实类型 | `file [challenge_file]` | 伪装扩展名 |
| 嵌入文件 | `binwalk -Me [file]` | 隐藏压缩包/图片 |
| 明文流量 | `tcpdump -r [file] -A \| head -50` | HTTP 明文传输 flag |
| 字符串搜索 | `strings [file] \| grep -iE "flag\|CTF"` | 内存/磁盘残留 |

### Mobile

| 检查 | 命令/方法 | 常见命中 |
|------|----------|---------|
| 文件类型 | `file [apk/ipa]` | 确认是 APK/IPA |
| 包内容 | `unzip -l [app.apk]` 或 `zipinfo [app.ipa]` | 异常文件/资源 |
| 字符串线索 | `strings [file] \| grep -iE "flag\|http\|api"` | 硬编码 URL/flag |

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
