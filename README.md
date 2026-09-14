# 软件口袋（com.rjkd.ruanku）逆向分析 — 配置解密与分发链路取证

> 本文档记录对非法软件下载库 **「软件口袋」`com.rjkd.ruanku`（域名 rjkd.cc）** 的逆向分析全过程，用于**举报取证与安全防御**。
> 线索来源：某游戏外挂「齿轮辅助」`com.huage.egaocl` 的更新提示会跳转到本软件（齿轮辅助本体见 Task B）。

---

## 一、结论速览（TL;DR）

| 项目 | 结论 |
|---|---|
| 目标 | 软件口袋 `com.rjkd.ruanku`（非法软件下载库，域名 rjkd.cc） |
| 加固壳 | 盈安/ABCD壳（`libabcdProtect.so` + `abcd/libabcd.enc` + `abcdef/YingAn.bin`） |
| 权限 | 极危险（SYSTEM_ALERT_WINDOW、REQUEST_INSTALL/DELETE_PACKAGES、RECORD_AUDIO、CAMERA、QUERY_ALL_PACKAGES 等） |
| 真实基础设施 | **蓝奏云** + **GitCode** + 百度统计 + 图片CDN，**无独立 API 服务器** |
| 配置文件 | `https://raw.gitcode.com/RJKD/RJKD2/raw/main/XL1`（GitCode 仓库，单文件） |
| 配置加密 | XL1 = hex 编码的 AES 密文（66180 hex → 33090 字节），密钥藏在壳的字符串解密器里 |
| 解密结果 | 外挂/破解软件下载目录 + VPN 导航链接（见 §六 完整链接清单） |

---

## 二、环境与工具

| 工具 | 版本/位置 | 用途 |
|---|---|---|
| MuMu 模拟器 | MuMu15 / Android 15 / KernelSU root，`127.0.0.1:16416` | 动态运行 app |
| adb | `platform-tools/adb.exe` | 设备控制 |
| mitmproxy | `mitmdump.exe` | 中间人抓包 |
| frida | 17.18.0 (python) + frida-server | 运行时 hook（被壳反调试拦截） |
| androguard | 4.1.4 | dex 反汇编 |
| pycryptodome | — | AES 测试 |
| 内存转储 | `dd if=/proc/PID/mem` | 免 frida 脱壳取明文 |

---

## 三、完整分析过程

### 3.1 定位目标

1. 某游戏外挂「齿轮辅助」`com.huage.egaocl`（360加固）的更新提示，跳转到本软件 **`com.rjkd.ruanku`（软件口袋）**。
2. 域名 `rjkd.cc` 302 跳转到蓝奏云文件夹 `https://wwasb.lanzoum.com/b01bjn5kcd`，解析到阿里云香港 `8.210.31.46`。

APK 的 classes.dex 被盈安壳保护（指令抽取），jadx 反编译零输出，**静态分析到极限，必须动态分析**。

### 3.2 模拟器 + MITM 抓包（拿到配置 URL）

```bash
adb connect 127.0.0.1:16416
# 设备代理指向宿主机 mitmproxy（MuMu 网关 = 10.0.2.2）
adb shell settings put global http_proxy 10.0.2.2:8080
```

mitmproxy 脚本（`logurl.py`，记录所有请求/响应）：

```python
from mitmproxy import ctx, http

def request(flow: http.HTTPFlow) -> None:
    ctx.log.info("REQ %s %s" % (flow.request.method, flow.request.pretty_url))

def response(flow: http.HTTPFlow) -> None:
    ct = flow.response.headers.get("Content-Type", "") if flow.response else ""
    body = flow.response.get_text() if flow.response else ""
    if body:
        ctx.log.info("RESP %s [%s] %s" % (flow.response.status_code, ct, body[:500].replace("\n", " ")))
```

**关键**：软件口袋 **不校验 TLS 证书**，自签 CA 直接解密，无需系统证书。

**抓到的配置 URL**：

```
https://raw.gitcode.com/RJKD/RJKD2/raw/main/XL1
```

- owner = `RJKD`，repo = `RJKD2`，分支 = `main`，文件 = `XL1`（仓库只有这一个文件）
- sha = `eacdc6509b7bf746eb7b0d2ca4e0e6e50d037d63`
- XL1 内容 = **纯 hex 字符串**（66180 字节，无空白）

### 3.3 免 frida 内存转储（绕过盈安壳反调试）

盈安壳反调试：扫 `/proc/maps` 找 "frida" + grep `/data/tombstones` + jdwp/JVMTI 检测 + arm64 内联 svc 自杀。frida attach 会被杀。

改用 root 直接读内存：

```bash
# 设备 shell 是 32 位整数会溢出，页偏移用宿主机算 64 位
adb shell "dd if=/proc/PID/mem bs=4096 skip=<page> count=<n>" > mem.bin
```

得到 `mem.bin`（3.8GB 完整进程内存）。之后扫描 `dex\n035` 魔数提取 dex、扫 UTF-16LE/UTF-8 字符串取明文。

### 3.4 提取并还原解密后的配置（拿到链接清单）

内存里 `lanzou` 出现在两类编码：
- **UTF-8 区域（offset ~4701334，136 处）**：AppConfig 对象的 URL 字段 = 外挂/破解软件目录
- **UTF-16LE 区域（offset ~9884346）**：一个 16 条的 VPN 导航 JSON

全文件 URL 提取脚本（提取所有蓝奏/图片/官网链接）：

```python
import mmap, re
f = open('mem.bin','rb')
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
urls = set()
for m in re.finditer(rb'https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{6,200}', mm):
    u = m.group().decode('utf-8','replace').rstrip('.,;)\"')
    if any(d in u for d in ['lanzou','imgos','meituan','gitcode','rjkd']):
        urls.add(u)
for u in sorted(urls):
    print(u)
```

UTF-16LE 小配置解析（16 条 VPN 导航）：

```python
import mmap, json
f = open('mem.bin','rb'); mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
data = mm[9884090:9884090+200000].decode('utf-16-le', errors='replace')
dec = json.JSONDecoder()
obj, end = dec.raw_decode(data, data.find('['))
print(obj)  # 16 条 {图片,打开方式,副标题,标题,链接}
```

### 3.5 逆向解密算法

#### 3.5.1 字符串常量混淆（控制流平坦化 + 自定义 XOR 流）

dex 反汇编发现 `run` 方法被**控制流平坦化**（`packed-switch` 合并大量方法），类/方法名用卢恩字符（`ᛱᛱᛱᛷᛷ` 等）混淆。

字符串常量解密算法（从 `run` 方法反汇编还原）：

```java
// hex 解码（"0123456789abcdef" 是 hex 字符映射表，不是 AES 密钥）
byte[] b = hexDecode(hexString, "0123456789abcdef");
// XOR 流解密
b[0] ^= salt;
for (int i = 1; i < b.length; i++)
    b[i] = (byte)(b[i-1] ^ b[i] ^ key);
return new String(b, "UTF-8");
```

> **重要更正**：`0123456789abcdef` 一开始被误判为 AES 密钥，实为 hex 解码的**字符映射表**（`map.indexOf(c)` 查值）。

#### 3.5.2 配置解密（AES）

定位到加密工具类 `Lᛱᛱᛱᛲᛸ/ᛱᛱᛱᛷᛶ;`（dex 2 内），关键方法反汇编：

```java
// <clinit> 里初始化 AES 密钥数组
static String[] ᛱᛱᛱᛱᛱ = { abcdstr(8244), abcdstr(8242), abcdstr(8243) };

// 解密方法：mode=2(DECRYPT)
byte[] decrypt(byte[] data, int index) {
    String key = ᛱᛱᛱᛱᛱ[index - 1];            // 3 选 1
    SecretKeySpec spec = new SecretKeySpec(key.getBytes(), abcdstr(7902));  // "AES"
    Cipher c = Cipher.getInstance(abcdstr(8122));  // 变换(ECB 等)
    c.init(Cipher.DECRYPT_MODE, spec);
    return c.doFinal(data);
}
```

- 算法名 `abcdstr(7902)`、变换 `abcdstr(8121/8122)`、密钥 `abcdstr(8242/8243/8244)` 全部由**壳的字符串解密器 `Lv/m/p;->abcdstr(I)`** 在运行时解密。
- `v/m/p` 类在壳自己的 dex 里（dump 中损坏），且反调试杀 frida，**密钥确切值仅运行时物化**，未能离线抓取。

#### 3.5.3 XOR 流排除

对 XL1 尝试用字符串常量的 XOR 流算法暴力破解（salt/key 各 0~255），前两字节可解出 `[{` 但第三字节起乱码，证明**配置不是 XOR 流，而是 AES**。

---

## 四、完整链接清单（解密结果）

### 4.1 蓝奏云分享文件夹（外挂/破解软件分发，核心证据）

| # | 链接 | 备注 |
|---|---|---|
| 1 | https://wwasl.lanzoul.com/b01bjff59c | 外挂目录 |
| 2 | https://wwasl.lanzoul.com/b01bjff5ad | |
| 3 | https://wwasl.lanzoul.com/b01bjff5be | |
| 4 | https://wwasl.lanzoul.com/b01bjkow4d | |
| 5 | https://wwasl.lanzoul.com/b01bjmzm5c | |
| 6 | https://wwasl.lanzoul.com/b01bjmzrjg | |
| 7 | https://wwasb.lanzoul.com/b01bjfkdcd | 《软件口袋》3 |
| 8 | https://wwasb.lanzoux.com/b01bjfkdab | 《软件口袋》1 |
| 9 | https://wwasb.lanzoux.com/b01bjfkdbc | 《软件口袋》2 |
| 10 | https://wwasl.lanzoum.com/b01bjff50d | VPN 须知入口 |

### 4.2 官网 / 导航域名

| 链接 | 用途 |
|---|---|
| http://rjkd.top/fxkd | 分享 |
| https://rjkd.top/bdwt/ | 问题 |
| https://rjkd.top/kdjs/ | 介绍 |
| https://rjkd.top/rjwt/ | 软件问题 |
| https://rjkd.top/swhz/ | |
| https://rjkd.top/yjdz1/ | |
| https://rjkd.app/2/1/ ～ /2/3/ | API 端点 |
| https://t.me/rjkd666 | Telegram 频道 |

### 4.3 蓝奏云代理 API（带一次性 token）

```
https://api.ilanzou.com/unproved/pd/url?id=13518563&time=1789376596&token=207d2f9db746f7b3378c65ede3d6b806&type=2
https://api.ilanzou.com/unproved/pd/url?id=13518564&time=1789376597&token=c515f4edd622747ad9965e390ce6739e&type=2
https://api.ilanzou.com/unproved/pd/url?id=13764473&time=1789376597&token=6c57828f1d349ce724049913c74cfc42&type=2
https://api.ilanzou.com/unproved/pd/url?id=13871682&time=1789376596&token=ff3b25c7da94f148162e029f04a91d6d&type=2
https://api.ilanzou.com/unproved/pd/url?id=13871876&time=1789376597&token=b4ff9af6ac8a3afa678dd6039e1a2509&type=2
```

### 4.4 图片 CDN

- `https://cdn.imgos.cn/`（vip 图片）
- `https://img.meituan.net/`（美团图床，存软件封面）
- `https://image.woozooo.com/`（蓝奏云图床）

### 4.5 VPN 导航小配置（16 条，UTF-16LE，需 VPN 进入）

Telegram、X、TikTok、YouTube、Instagram、Facebook、ChatGPT、BBC 中文、AfreecaTV、Potato、Fyptt、成人网站等，配图来自 `cdn.imgos.cn`。

---

## 五、核心代码

脚本已归档到 `code/` 目录：

| 文件 | 用途 |
|---|---|
| `logurl.py` | mitmproxy 抓 URL |
| `dex_disasm.py` | 最小 DEX 解析器 + 反汇编器（uleb128/MUTF-8/const-string 扫描） |
| `ag_findkey.py` | androguard 方法定位 + 反汇编 |
| `scan_keys.py` | mem.bin 分块扫描加密/URL 特征 |
| `hook_abcdstr.js` | frida hook 壳字符串解密器（被反调试拦截） |
| `run_frida_key.py` | frida spawn 运行器 |
| `find_crypto.py` | 定位 dex 里 AES/Cipher 加密方法 |
| `extract_config.py` | 从 mem.bin 提取明文配置 + 链接清单 |
| `xor_stream_test.py` | 验证配置是否 XOR 流（排除法） |

> `dex_disasm.py` 是独立手写的 DEX 解析器，用于在没有 androguard 的情况下定位 `const-string` 引用的方法。

---

## 六、反调试与脱壳技术备忘

- **frida 17 API 变化**：`Module.findExportByName` 移除 → 用 `Process.getModuleByName('libc.so').findExportByName(name)`；不自动注入 Java bridge。
- **盈安壳反调试**：扫 `/proc/maps` 找 "frida" + grep `/data/tombstones` + jdwp/JVMTI 检测 + arm64 内联 svc 自杀（libc hook 拦不住 svc）。
- **免 frida 内存转储**：root 下 `dd if=/proc/PID/mem`（按 maps 可读区，页对齐 skip/count 用宿主机算 64 位），再扫 `dex\n035` 魔数提 dex、扫 UTF-16LE 字符串。
- **解壳产物**：`/data/user/0/com.rjkd.ruanku/.abcedf/libabcdProtect_64.so`（解密后的壳 so）。

---

## 七、GitCode 仓库信息（配置源）

- 平台：GitCode（`raw.gitcode.com`，解析 `116.205.2.202`）
- 仓库：`RJKD/RJKD2`（owner=RJKD，仅一个文件 XL1）
- 搜索 API：`https://gitcode.com/api/v5/search/repositories?q=...`、`https://gitcode.com/api/v5/repos/{owner}/{repo}/git/trees/{branch}?recursive=1`

---

## 八、取证结论

1. 软件口袋（rjkd.cc）→ 蓝奏云 + GitCode 的分发链已完全摸清，**无独立后端服务器**，全部寄生在免费网盘/代码托管平台。
2. 配置文件 XL1 通过 GitCode 公开仓库分发，hex+AES 加密，密钥藏于盈安壳字符串表（运行时物化）。
3. 完整外挂/破解软件下载目录（10 个蓝奏文件夹）已提取，可直接作为举报证据。
4. 附带传播 VPN 翻墙导航与成人内容，涉嫌多类违法。
