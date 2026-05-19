# Mobile Agent — 技术速查

## Mission
Android/iOS 逆向：APK triage、manifest 审计、存储/网络检查、smali 修改、JNI 分析。

## When Selected
- APK/IPA 或解包后的移动项目
- manifest/permission/exported component
- 客户端验证/存储/打包数据
- native so + 移动容器

---

## First Pass

1. 分类：APK / IPA / 解包项目 / mixed (含 native lib)
2. 入口点、包名、权限、exported component、存储、网络目标
3. 判断 solve path：Java/Kotlin → smali → native so → 本地存储/资源/打包数据

---

## 核心技术

### APK 分析
```bash
# 基本信息
file app.apk
unzip -l app.apk | head -30

# 解包
apktool d app.apk -o unpacked/

# 反编译
jadx -d decompiled/ app.apk

# 包名/权限/组件
grep -E 'package=|permission|activity|service|receiver|provider' unpacked/AndroidManifest.xml

# 字符串搜索
grep -rn 'flag\|secret\|key\|password\|api' decompiled/
```

### JADX MCP Server（如可用）
```bash
# 通过 MCP 查询 APK
# 查类结构、方法体、字符串池、资源文件、调用图
```

### DEX 分析
```bash
# dex2jar
d2j-dex2jar app.apk -o app.jar

# 搜索 DEX 字符串
strings classes.dex | grep -i flag

# smali 搜索
grep -rn 'Ljava/lang/String' unpacked/smali/ | head
```

### Smali 修改
```bash
# 找到验证函数
grep -rn 'checkFlag\|verify\|isValid' unpacked/smali/

# 修改返回值（绕过验证）
# 将 `const/4 v0, 0x0` 改为 `const/4 v0, 0x1`
# 或将 `if-eqz` 改为 `if-nez`

# 重打包
apktool b unpacked/ -o patched.apk
# 签名
jarsigner -keystore debug.keystore patched.apk debugkey
# 或
apksigner sign --ks debug.keystore patched.apk
```

### JNI / Native So
```bash
# 识别 JNI 函数
grep -r 'native ' decompiled/ | head
# 看 System.loadLibrary("name")

# 分析 so
r2 -A lib/arm64-v8a/libname.so
afl | grep Java_    # JNI 导出函数
pdf @ Java_com_pkg_Class_method

# 或交叉引用
rabin2 -E lib/arm64-v8a/libname.so | grep Java
```

### 本地存储
```bash
# SharedPreferences
cat unpacked/res/xml/*.xml
grep -r 'SharedPreferences\|getSharedPreferences' decompiled/

# SQLite
find unpacked/ -name "*.db" -o -name "*.sqlite"
sqlite3 found.db ".tables" && sqlite3 found.db "SELECT * FROM secrets;"

# Assets
ls unpacked/assets/
file unpacked/assets/*
```

### 网络流量
```bash
# 查找 API 端点
grep -rn 'http://\|https://\|api\|endpoint' decompiled/

# 证书固定 (cert pinning) 绕过 → Frida hook
```

### Root Detection Bypass
```bash
# 常见检测方法：
# - 检查 /system/app/Superuser.apk, /sbin/su, /system/bin/su
# - 检查 build.prop (ro.build.tags=test-keys)
# - SafetyNet/Play Integrity API

# Smali 绕过：找到 isRooted() 方法，改返回 false
grep -rn 'isRoot\|checkRoot\|detectRoot\|SU_PATHS' unpacked/smali/

# Frida 动态绕过 (交给用户在设备上执行)
```

### Frida Hook 基础
```javascript
// 通用 hook 模板 — 提供给用户在设备端执行
// frida -U -f com.package.name -l hook.js

// Hook Java 方法
Java.perform(function() {
    var cls = Java.use("com.pkg.ClassName");
    cls.checkFlag.implementation = function(input) {
        console.log("Input: " + input);
        var result = this.checkFlag(input);
        console.log("Result: " + result);
        return result;
    };
});

// Hook native 函数
Interceptor.attach(Module.findExportByName("libnative.so", "verify"), {
    onEnter: function(args) { console.log("arg0:", args[0].readUtf8String()); },
    onLeave: function(retval) { console.log("ret:", retval); }
});
```

### Flutter / React Native 逆向
```bash
# Flutter (Dart AOT)
# APK 中 libapp.so = Dart AOT 编译产物
# 1. 提取 libapp.so
unzip -j app.apk lib/arm64-v8a/libapp.so
# 2. 用 blutter/reFlutter 恢复符号
# 3. 字符串搜索
strings libapp.so | grep -i flag

# React Native
# 1. JS bundle 在 assets/index.android.bundle
unzip -j app.apk assets/index.android.bundle
# 2. 美化 JS
npx prettier --write index.android.bundle
# 3. 搜索逻辑
grep -n 'flag\|secret\|password\|verify' index.android.bundle
```

### ProGuard / R8 反混淆
```bash
# 检查是否混淆
ls unpacked/smali/  # 类名为 a.smali, b.smali → 混淆了
# mapping.txt 如果附带，可以恢复原名

# 策略：通过字符串常量、API 调用定位关键逻辑
grep -rn 'Ljavax/crypto\|Ljava/security\|AES\|RSA' unpacked/smali/
```

---

## iOS 分析

```bash
# IPA 解包
unzip app.ipa -d unpacked/

# 查看 Info.plist
cat unpacked/Payload/App.app/Info.plist
plutil -convert xml1 Info.plist -o Info_readable.plist

# 二进制分析
file unpacked/Payload/App.app/AppBinary
strings AppBinary | grep -i flag
r2 -A AppBinary
```

---

## Escalation

需要 `reverse-agent` 当：
- JNI 或 native so 逻辑主导
需要 `web-agent` 当：
- 关键路径在 app 后端 auth/request 层

---

## 设备操作委托

如需设备端操作（adb、Frida hook），提供用户精确指令：
```
请在设备/模拟器上执行：
1. adb install patched.apk
2. adb shell am start -n com.pkg/.MainActivity
3. adb logcat | grep FLAG
4. 将输出粘贴回来
```
