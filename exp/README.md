# exp 知识库

`exp/<category>/<category>.jsonl` 存放已解/已尝试题目的可复用经验。

---

## Schema（严格执行，CI 会校验）

```jsonc
{
  "challenge": "PWN",             // 必填 · 题目分类 · 枚举值见下表
  "name":      "Format String",   // 必填 · 题目原名 · ≤60 字符
  "technique": "A + B + C",       // 必填 · 主利用链 · 用 " + " 连接 · ≤120 字符
  "status":    "solved",          // 必填 · 只能是 "solved" 或 "partial"
  "experience": [                 // 必填 · 数组 · 3-8 条
    "一条可复用经验。"              //   每条 15-150 字符
  ],
  "artifacts": {                  // 可选 · 仅放可复用的技术参数
    "offset": "0x108"             //   值只能是 string 或 number
  }
}
```

### 字段约束一览

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| `challenge` | string | Y | 枚举：`Web` `PWN` `RE` `MOBILE` `MISC` `Crypto` `Forensics`，必须与所在目录对应 |
| `name` | string | Y | 题目原名，1-60 字符 |
| `technique` | string | Y | 技术链，用 ` + ` 分隔各步骤，1-120 字符 |
| `status` | string | Y | `solved` 或 `partial` |
| `experience` | string[] | Y | 3-8 条，每条 15-150 字符 |
| `artifacts` | object | N | key=参数名，value=string\|number；禁止嵌套对象 |

### 禁止内容（任何字段均适用）

1. **Flag 值**：任何 `XXX{...}` 格式的字符串（`ISCC{`, `flag{`, `CTF{` 等）
2. **远程地址**：IP、端口、URL（如 `39.96.193.120:10000`, `http://...`）
3. **完整代码**：超过 1 行的代码片段；可以提及函数名/工具名，但不贴代码
4. **未验证推测**：`status=solved` 的条目中不允许出现"可能"、"猜测"、"未确认"
5. **多余字段**：只允许上表列出的 6 个字段，其他一律拒绝

---

## experience 条目写法

### 格式

每条经验是**一句话**，表达**一个**可迁移结论。推荐结构：

```
[场景/条件]，[动作/结论]。
```

或含坑点的三段式：

```
[场景/条件]，[正确做法]，[常见错误/坑点]。
```

### 好的示例

```
✓ "格式化字符串先定位可变参数偏移，再用 %N$p 读取 canary 或指针。"
✓ "send() 和 sendline() 的区别必须严格控制，格式串题里多一个换行就可能导致 payload 失效。"
✓ "ZIP 伪加密修复时，遍历 local header 和 central directory，把通用标志位 GPBF 的 bit6 清零。"
✓ "Echo Hiding 的正确做法是 cepstrum，不要用简单的幅度或平均能量比较代替，结果通常是乱码。"
```

### 坏的示例

```
✗ "用 pwntools 写 exploit"                          → 太笼统，无可迁移信息
✗ "from pwn import *; r = remote('1.2.3.4', 9999)"  → 包含代码和远程地址
✗ "flag 是 ISCC{abcdef}"                            → 包含 flag 值
✗ "可能是栈溢出也可能是堆"                              → 未验证推测不能出现在 solved 条目
✗ "这道题先 checksec 看保护再 gdb 调一下看看栈布局然后构造 ROP 链最后打远程" → 流水账，应拆成多条
```

---

## artifacts 用法

只存**可跨场景复用的技术参数**，不存一次性值。

```jsonc
// 好 — 可复用的偏移和结构信息
"artifacts": {"canary_offset_fmt": 21, "main_return_site": "0x13fb", "libc": "Ubuntu GLIBC 2.39"}

// 坏 — 一次性值 / 敏感信息
"artifacts": {"flag": "ISCC{xxx}", "remote": "39.96.193.120:9999", "password": "admin123"}
```

---

## 分类目录

| 目录 | 覆盖范围 |
|------|---------|
| `web/web.jsonl` | Web 安全 |
| `pwn/pwn.jsonl` | 二进制利用 |
| `reverse/reverse.jsonl` | 逆向 + Mobile |
| `misc/misc.jsonl` | 杂项 / 隐写 / 编码 |
| `crypto/crypto.jsonl` | 密码学 |
| `forensics/forensics.jsonl` | 取证 |

支持脚本和辅助文件（如 `pwn/*.py`, `web/*.py`），但 JSONL 是唯一被检索的格式。
