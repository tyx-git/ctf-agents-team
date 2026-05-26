# WP 格式规范

本文档定义 `wp.process`（解题过程）和 `题目名称.md`（最终 WP）的格式规范。

> **比赛根目录规则**：用户输入的首个路径分量即为比赛根目录（如 `BugKu/pwn/above` → 根目录 `BugKu/`）。所有比赛级文件（`limit.md`、`task_plan.md`、`findings.md`、`progress.md`、`flag.log`）**始终写入比赛根目录**，不受子路径影响。

---

## 一、wp.process — 解题过程记录

**位置**：`<比赛>/<分类>/<题目>/wp.process`（分类目录小写，如 `ISCC/web/题目名称/wp.process`）
**时机**：Phase 2 分类完成后立即创建，解题过程中持续更新
**原则**：
- 每个 Stage 对应一个逻辑步骤
- 失败路径也要记录（有助于避免重复尝试）
- 每 2 次分析操作后至少更新一次（2-Action Rule）

### 格式模板

```markdown
# wp.process — 题目名称

## Challenge Info
- **比赛**: ISCC 2026
- **类型**: Web / Pwn / Re / Mobile / Misc
- **目录**: ISCC/web/题目名称
- **状态**: enumerated / in_progress / solved / verified
- **Flag 格式**: ISCC{...}（如已知）
- **远程目标**: http://target:port 或 nc target port（如有）

## 关键文件
- `challenge.zip` — 题目附件
- `app.py` — 服务端源码
- ...

---

## Stage 001: 初始侦察
**时间**: 2026-05-19 14:00
**操作**:
- file * 识别文件类型
- strings app.py | head -30
- curl -v http://target:12345/

**发现**:
- Flask 应用，Python 3.11
- /api/login 端点存在
- 使用 JWT 认证

**结论**: Web 类型，可能涉及 JWT 伪造或 SSTI
**下一步**: 审计源码，寻找 JWT 密钥泄露或注入点

---

## Stage 002: 源码审计
**时间**: 2026-05-19 14:15
**操作**:
- 通读 app.py
- 检查 JWT 库和配置
- 搜索 flag 位置

**发现**:
- JWT 使用 HS256 签名
- 密钥硬编码在 config.py: `SECRET = "weak_key_123"`
- /admin 路由检查 JWT 中 role == "admin"

**结论**: 用泄露的密钥伪造 admin JWT 即可
**下一步**: 构造 JWT payload，获取 flag

---

## Stage 003: 漏洞利用
**时间**: 2026-05-19 14:25
**操作**:
```python
import jwt
token = jwt.encode({"user": "admin", "role": "admin"}, "weak_key_123", algorithm="HS256")
# curl -H "Authorization: Bearer $token" http://target:12345/admin
```

**发现**:
- 返回 flag: ISCC{jwt_f0rg3ry_is_fun}

**结论**: 确认 flag，路径已验证
**状态更新**: solved → verified

---

## Stage 004: [如有更多步骤继续编号]

---

## 失败路径记录
| Stage | 尝试 | 失败原因 |
|-------|------|---------|
| 002 | 尝试 SQLi on /api/login | 无 SQL 后端，全部内存存储 |

## Errors
| 时间 | 错误 | 尝试次数 | 解决 |
|------|------|---------|------|
| 14:20 | jwt.encode TypeError | 1 | PyJWT 版本差异，加 algorithm= 参数 |
```

### 格式要点

1. **Stage 编号**：三位数 `001`, `002`, `003`... 保持排序
2. **每个 Stage 必含**：时间、操作、发现、结论、下一步
3. **操作**中贴实际命令/代码片段，不要只写"分析了源码"
4. **发现**中写具体的值、地址、关键信息
5. **失败路径**单独记录，不删除
6. **状态更新**：在 flag 确认的 Stage 中标注 `solved → verified`

---

## 二、题目名称.md — 最终详细 WP

**位置**：`<比赛>/<分类>/<题目>/题目名称.md`（如 `ISCC/pwn/overflow/overflow.md`）
**时机**：题目 `verified` 后撰写
**原则**：一个从未见过此题的人，照着 WP 能完整复现

### 格式模板

```markdown
[类型] + 题目名称

## 解题思路
1. [高层步骤概述，如：探测 GraphQL 端点，获取 Schema]
2. [如：发现 Timing Oracle 侧信道]
3. [如：逐字符盲注管理员密码]
4. [如：用密码登录获取 flag]

---

## 复现

### 步骤 1：[标题，如：确认 GraphQL 端点]

[1-2 句说明这步在做什么]

```bash
# 实际执行的命令（完整、可复制粘贴）
curl -s -X POST http://target:12345/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'
```

**命令解释**：
- `-X POST` — GraphQL 使用 POST 请求
- `__schema` — 内置 Introspection 查询

**预期结果**：
```json
{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "Mutation"}]}}}
```

**发现**：
- 存在 login mutation
- 有 currentUser 查询（需认证）

### 步骤 2：[标题]

[继续按同样格式...]

---

## EXP：

```python
#!/usr/bin/env python3
"""
题目名称 - 完整 Exploit
用法: python3 exploit.py
"""
# 完整可运行的 exploit 代码
# 包含必要的 import，无参数即可运行
```

**注意事项**：
- [如：时序攻击受网络波动影响，需多轮采样]
- [如：需要 pwntools >= 4.0]
- ...
```

### 独立 exploit.py

对于可脚本化的题目（Pwn、Web、Crypto 等），**必须**在题目目录下创建独立的 `exploit.py` 文件。
纯手工分析题（取证、纯逆向无交互、纯 stego 只需一条命令）可跳过。

**位置**：`<比赛>/<分类>/<题目>/exploit.py`

```python
#!/usr/bin/env python3
"""
题目名称 - Exploit
比赛: [比赛名]
类型: [Pwn/Web/Misc/...]
用法: python3 exploit.py
"""
from pwn import *  # 或其他需要的库

# ===== 配置 =====
HOST = 'target.host'
PORT = 12345
BINARY = './binary_name'

# ===== exploit 逻辑 =====
def exploit(r):
    # 核心利用代码
    pass

if __name__ == '__main__':
    r = remote(HOST, PORT)
    exploit(r)
    r.interactive()
```

**规则**：
- 判断标准：解题过程中执行了多步交互或构造了 payload → 写成脚本
- **`python3 exploit.py` 无参数即可直接运行获取 flag**
- 脚本必须独立可运行（包含 shebang、import、配置变量）
- 非 Pwn 题（如 Web/Crypto/Misc）可使用 requests/subprocess/sage 等库替代 pwntools

### 格式要点

1. **开头**：`[类型] + 题目名称`，如 `Web + Oracle's Whisper`
2. **解题思路**：3-6 步编号列表，高层概述
3. **复现**：每步包含 `命令/代码` + `命令解释` + `预期结果` + `发现`
4. **EXP**：完整可运行代码，含 docstring/用法说明
5. **注意事项**：网络条件、版本依赖、时间限制等

---

## 三、flag.log — 集中索引

**位置**：`<比赛>/flag.log`
**格式**：每行一条

```
[类型][题目名称] flag字符串
```

**类型标签**：`Pwn`, `Web`, `Re`, `Mobile`, `Misc`, `Crypto`, `Forensics`

**示例**：
```
[Web][Oracle's Whisper] ISCC{timing_0racle_graphql}
[Pwn][Stack Master] ISCC{r3t2libc_g0t_1t}
[Misc][Hidden Signal] ISCC{rf_d3m0d_qam16}
```

**规则**：
- 同一 `[类型][题目名称]` 已存在时**不覆盖**（已验证的 flag 不应被后续写入替换）
- 新题目追加到文件末尾
- 只有 `verified` 状态的 flag 才写入
- 只有 Lead Agent（主对话）可以修改此文件

---

## 四、limit.md — 比赛/平台解题限制

**位置**：`<比赛>/limit.md`

此文件记录该比赛或平台对解题行为的限制条件，帮助 Agent 调整解题策略（如降低请求频率、增加超时等）。

**格式**：纯文本 / Markdown，空文件表示无特殊限制。

**示例**：
```markdown
# ISCC 2026 平台限制

- 请求频率：每分钟不超过 30 次 API 请求
- 全局超时：单次连接 30 秒无响应视为超时
- CTFd Token 有效期：8 小时，过期需重新登录
- 禁止操作：端口扫描、DoS 测试
```

**读取时机**：Phase 1（比赛入场）时读取，Agent 在 Phase 2+ 中根据限制内容调整请求策略。

---

## 五、task_plan.md — 比赛级任务计划

**位置**：`<比赛>/task_plan.md`

```markdown
# Task Plan: [比赛名称]

## Goal
[比赛目标，如：ISCC 2026 全品类解题]

## Current Focus
[当前正在解的题目路径]

## Challenge Status

| # | 类型 | 题目 | 状态 | Flag |
|---|------|------|------|------|
| 1 | Web | Oracle's Whisper | verified | ISCC{...} |
| 2 | Pwn | Stack Master | in_progress | — |
| 3 | Misc | Hidden Signal | enumerated | — |

## Decisions
| 决策 | 原因 |
|------|------|
| 先做 Web 题 | 文件最完整，预计较快 |

## Errors
| 错误 | 尝试 | 解决 |
|------|------|------|
| pip install pwntools 超时 | 1 | 换清华源 |
```

---

## 六、比赛级 findings.md

```markdown
# Findings: [比赛名称]

## 平台信息
- Flag 格式: ISCC{...}
- 平台: CTFd at https://ctf.iscc.org.cn
- Token: ctfd_xxx（用户提供）
<!-- ⚠️ 安全提示：提交或分享前务必移除 Token，禁止将 Token 写入经验库或公开仓库 -->

## 跨题目发现
- 所有 Web 题共用同一 Docker 集群，内网可互通
- Flag 前缀统一为 ISCC{

## 各题速记
### web/Oracle's Whisper
- GraphQL Timing Oracle, 逐字符盲注

### pwn/Stack Master
- [待分析]
```

---

## 七、比赛级 progress.md

```markdown
# Progress: [比赛名称]

## Session: 2026-05-19

### 14:00 — 入场
- 扫描目录，发现 3 Web + 2 Pwn + 1 Misc
- 创建 task_plan.md

### 14:10 — web/Oracle's Whisper
- Stage 001-003 完成
- Flag verified: ISCC{timing_0racle_graphql}
- WP 已写

### 15:30 — pwn/Stack Master
- Stage 001 完成：识别为栈溢出
- Stage 002 进行中：泄露 libc
```
