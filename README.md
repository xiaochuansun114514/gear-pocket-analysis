# 软件口袋 & 齿轮辅助（华哥）系列 — 逆向分析

> 本笔记记录同一条线索上两个关联目标的逆向分析全过程，用于**安全防御**：
> - **软件口袋** `com.rjkd.ruanku`（软件下载库，域名 rjkd.cc）
> - **齿轮辅助（华哥）系列**（齿轮辅助 / 冰糖雪梨 / 哔可防封，作者 By.羽霖咲华Unishua / 华哥）
> 线索来源：「齿轮辅助」`com.huage.egaocl` 的更新提示会跳转到「软件口袋」`com.rjkd.ruanku`。
>
> 该系列后续的进展（案件、作者现状、软件今天的形态）见 **§B7**。

---

# Task A — 软件口袋 `com.rjkd.ruanku`

## A1、结论速览（TL;DR）

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

## A2、环境与工具

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

## A3、完整分析过程

### A3.1 定位目标

1. 某游戏外挂「齿轮辅助」`com.huage.egaocl`（360加固）的更新提示，跳转到本软件 **`com.rjkd.ruanku`（软件口袋）**。
2. 域名 `rjkd.cc` 302 跳转到蓝奏云文件夹 `https://wwasb.lanzoum.com/b01bjn5kcd`，解析到阿里云香港 `8.210.31.46`。

APK 的 classes.dex 被盈安壳保护（指令抽取），jadx 反编译零输出，**静态分析后，动态分析**。

### A3.2 模拟器 + MITM 抓包（拿到配置 URL）

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

### A3.3 免 frida 内存转储（绕过盈安壳反调试）

盈安壳反调试：扫 `/proc/maps` 找 "frida" + grep `/data/tombstones` + jdwp/JVMTI 检测 + arm64 内联 svc 自杀。frida attach 会被杀。

改用 root 直接读内存：

```bash
# 设备 shell 是 32 位整数会溢出，页偏移用宿主机算 64 位
adb shell "dd if=/proc/PID/mem bs=4096 skip=<page> count=<n>" > mem.bin
```

得到 `mem.bin`（3.8GB 完整进程内存）。之后扫描 `dex\n035` 魔数提取 dex、扫 UTF-16LE/UTF-8 字符串取明文。

### A3.4 提取并还原解密后的配置（拿到链接清单）

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

### A3.5 逆向解密算法

#### A3.5.1 字符串常量混淆（控制流平坦化 + 自定义 XOR 流）

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

#### A3.5.2 配置解密（AES）

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

#### A3.5.3 XOR 流排除

对 XL1 尝试用字符串常量的 XOR 流算法暴力破解（salt/key 各 0~255），前两字节可解出 `[{` 但第三字节起乱码，证明**配置不是 XOR 流，而是 AES**。

---

## A4、完整链接清单（解密结果）

### A4.1 蓝奏云分享文件夹（外挂/破解软件分发，核心证据）

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

### A4.2 官网 / 导航域名

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

### A4.3 蓝奏云代理 API（带一次性 token）

```
https://api.ilanzou.com/unproved/pd/url?id=13518563&time=1789376596&token=207d2f9db746f7b3378c65ede3d6b806&type=2
https://api.ilanzou.com/unproved/pd/url?id=13518564&time=1789376597&token=c515f4edd622747ad9965e390ce6739e&type=2
https://api.ilanzou.com/unproved/pd/url?id=13764473&time=1789376597&token=6c57828f1d349ce724049913c74cfc42&type=2
https://api.ilanzou.com/unproved/pd/url?id=13871682&time=1789376596&token=ff3b25c7da94f148162e029f04a91d6d&type=2
https://api.ilanzou.com/unproved/pd/url?id=13871876&time=1789376597&token=b4ff9af6ac8a3afa678dd6039e1a2509&type=2
```

### A4.4 图片 CDN

- `https://cdn.imgos.cn/`（vip 图片）
- `https://img.meituan.net/`（美团图床，存软件封面）
- `https://image.woozooo.com/`（蓝奏云图床）

### A4.5 VPN 导航小配置（16 条，UTF-16LE，需 VPN 进入）

Telegram、X、TikTok、YouTube、Instagram、Facebook、ChatGPT、BBC 中文、AfreecaTV、Potato、Fyptt、成人网站等，配图来自 `cdn.imgos.cn`。

---

## A5、核心代码

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

## A6、反调试与脱壳技术

- **frida 17 API 变化**：`Module.findExportByName` 移除 → 用 `Process.getModuleByName('libc.so').findExportByName(name)`；不自动注入 Java bridge。
- **盈安壳反调试**：扫 `/proc/maps` 找 "frida" + grep `/data/tombstones` + jdwp/JVMTI 检测 + arm64 内联 svc 自杀（libc hook 拦不住 svc）。
- **免 frida 内存转储**：root 下 `dd if=/proc/PID/mem`（按 maps 可读区，页对齐 skip/count 用宿主机算 64 位），再扫 `dex\n035` 魔数提 dex、扫 UTF-16LE 字符串。
- **解壳产物**：`/data/user/0/com.rjkd.ruanku/.abcedf/libabcdProtect_64.so`（解密后的壳 so）。

---

## A7、GitCode 仓库信息（配置源）

- 平台：GitCode（`raw.gitcode.com`，解析 `116.205.2.202`）
- 仓库：`RJKD/RJKD2`（owner=RJKD，仅一个文件 XL1）
- 搜索 API：`https://gitcode.com/api/v5/search/repositories?q=...`、`https://gitcode.com/api/v5/repos/{owner}/{repo}/git/trees/{branch}?recursive=1`

---

## A8、结论

1. 软件口袋（rjkd.cc）→ 蓝奏云 + GitCode 的分发链已完全摸清，**无独立后端服务器**，全部寄生在免费网盘/代码托管平台。
2. 配置文件 XL1 通过 GitCode 公开仓库分发，hex+AES 加密，密钥藏于盈安壳字符串表（运行时物化）。
3. 完整外挂/破解软件下载目录（10 个蓝奏文件夹）已提取。
4. 附带传播 VPN 翻墙导航与成人内容。
5. 嘿嘿嘿。


---

# Task B — 齿轮辅助（华哥）系列

## B1、结论速览（TL;DR）

| 项目 | 结论 |
|---|---|
| 目标 | 齿轮辅助 `com.huage.egaocl`（PUBG/和平精英 游戏辅助工具，圈内称"华哥"） |
| 同源变体 | 冰糖雪梨 `com.huage.pubgm.btxl` 2.3.0 / 哔可防封 `com.huage.pink.fangfeng` 6.5.1 |
| 作者 | By.羽霖咲华Unishua（华哥），三款应用共用同一套 iapp3(爱根) 脚本引擎，仅身份常量不同 |
| 加固层次 | **四层**：360加固(libjiagu) + beingyi(别疑惑) SubApp 壳 + armadillo 云注入 + iapp3(Lua) 引擎 |
| ~~真实作弊框架~~ | ~~VirtualApp 改名版（`com.px` + `mirrorb`）~~ **已推翻**，`com.px` 只是云注入壳的宿主占位组件包，见 §B3 / §B5.7 |
| **开挂逻辑** | **静态样本里没有任何游戏内存读写 / 注入 / hook**；菜单控件是真的、**接线是空的**；真实能力由 CloudInject 云端下发 —— 详见 **§B5** |
| 实际业务 | **裂变推广漏斗**：逼用户往 QQ 群分享 15 次换"解锁"，满额后弹"本版本已失效"的强制更新页（§B5.5） |
| 脱壳结果 | 3 个 dex **全部离线解密**（XOR 密钥 = 包名，无需动态 dump） |
| 支付/卡密 | iapp 官方支付 `iapp.yx93.com` + 发卡网 `sidai.wmrerey.cn`（带追踪参数） |
| **C2 服务器** | **`http://yun.dzpgrw.cn:8080`**（`202.189.4.117`，卡密验证 + 配置下发，DES 加密已破解） |
| **真实外挂脚本** | **`assets/lib.so` 是 iapp3 加密脚本包，已离线完全解密**（齿轮辅助/哔可防封全解出，冰糖雪梨仅剩约 1.06 万字节） |
| 反分析 | 字符串 AES 加密、卢恩字符混淆、app_ded 目录即时删除、反模拟器 SIGSEGV |
| 日志上报 | `https://log-report.com/report` |

## B2、目录说明

本部分完整内容位于 [`taskb/`](taskb/) 子目录：

| 文件/目录 | 内容 |
|---|---|
| [`taskb/taskb_gear_辅助.md`](taskb/taskb_gear_辅助.md) | 完整分析笔记（加固、反分析、脱壳、脚本解密、C2、支付卡密、结论） |
| [`taskb/dec_all.py`](taskb/dec_all.py) | 三款应用通用 iapp bundle 离线解密器（已验证） |
| [`taskb/dec_names.py`](taskb/dec_names.py) | **条目名离线字典攻击**（K1 指纹 find），无需设备/hook 即可枚举未知名条目（已验证） |
| [`taskb/dec_iyu.py`](taskb/dec_iyu.py) | 齿轮辅助单应用版解密器（已验证） |
| [`taskb/decrypt_src.py`](taskb/decrypt_src.py) | beingyi(别疑惑) 壳 `src/` 真实 dex 解密器 |
| [`taskb/unpacked/`](taskb/unpacked/) | 从三款应用解出的明文 `.iyu` / `.mjs` 脚本（作弊菜单、C2、悬浮窗、权限等） |
| [`taskb/会画画的圈钱狗作品集.zip`](taskb/) | 从 APK 提取的原件（6 张明文图片 + 1 个尚未解密的加密项 `作者坦白`） |
| [`taskb/圈钱狗作品集_明文/`](taskb/圈钱狗作品集_明文/) | 上述 zip 中可解出的 6 个明文图片 |
| [`taskb/AAA拆包狗看这里.txt`](taskb/AAA拆包狗看这里.txt) | APK 内自带的一段文字（针对拆包者） |
| [`taskb/样本包_齿轮辅助系列_加密码.zip`](taskb/) | 三款 APK 原件的加密样本包 |
| [`taskb/齿轮辅助_v14.0.1_官方版.zip`](taskb/) | 2026-09 从官网取的当前版本安装包存档（免费版，已无外挂功能，详见 §B7） |

## B3、核心突破

1. **beingyi 壳的 dex 加密 = 「包名循环 XOR」**，可直接离线解密，3 个 dex 共 7384 个类全部还原，无需动态 dump。
2. ~~**作弊核心技术 = 改名版 VirtualApp**（`com.px` + `mirrorb`），虚拟化运行「和平精英」并注入功能，逃避游戏反作弊检测。~~
   > **已推翻**。`com.px` 的 `BuildConfig` 里 `APPLICATION_ID` 直接写成 `com.px`、版本 1.0，包内 304 个类全是 Stub 组件（`ProxyActivity` 及 240 个空内类、`ProxyContentProvider$P0-P19`、`FService`/`FBroadcastReceiver` 等）与 R 资源，**没有一行 VirtualApp 核心逻辑**。它是**云注入壳自己的"宿主占位组件包"**，不是虚拟化游戏进程的框架。完整结论见 **§B5**。
3. **iapp3 脚本包 `assets/lib.so` 离线完全解密**：三级密钥派生（`slky` 加盐 MD5 置换 + AES-128-CBC（IV==KEY）+ `djyj` 循环 XOR），三款应用共用同一算法，仅 `DNGB` 身份常量不同。
4. **`DNGB` 是每个应用各编各的 Java 常量**：`com.iapp.app.f.b()` → egaocl=5556367、btxl=3401192、fangfeng=2405525。
5. **云注入 + 卡密验证**：armadillo SDK 通过 DES/CBC（key=IV=`KbMMxfM,`）的 C2 配置下发真实 payload，卡密用 RSA 公钥加密上报。

## B4、样本包口令

| 包 | 加密方式 | 口令 |
|---|---|---|
| `taskb/样本包_齿轮辅助系列_加密码.zip` | AES-256（pyzipper） | **`infected`** |
| `taskb/会画画的圈钱狗作品集.zip` | ZipCrypto，仅 `作者坦白` 一项加密 | 未知，见 §B6 |

`样本包_齿轮辅助系列_加密码.zip` 里装的是三款 APK 的原件，**口令就是 `infected`**，恶意样本分析里通用的那个口令。

解压：

```bash
python -c "import pyzipper; pyzipper.AESZipFile('样本包_齿轮辅助系列_加密码.zip').extractall(pwd=b'infected')"
```

>  §B6 的和这个不一样：**`作者坦白` 是另一个 zip 里的条目**，它用的是 ZipCrypto，口令至今没解出来。
> 两个包的口令不是一回事。

## B5、开挂逻辑：它到底怎么"开挂"、怎么"防封"

> 本节是本次新增的核心内容，同时**更正 §B3 第 2 条**。
> 起点是一句自问：静态样本里到底有没有"读游戏内存 / 注入游戏进程"的代码？
> 答案：**没有，一行都没有**。

### B5.1 一句话结论

| 问题 | 结论 |
|---|---|
| 有没有读写游戏内存 / 注入进程 / hook？ | **没有**。native 引擎只有 24 个自有符号、可逐个穷举；dex 关键词零命中 |
| 菜单上那些自瞄 / 透视 / 穿墙是真的吗？ | 控件是真的，**接线是空的** —— 37 个开关点击后要么 `exec("su")` 申请 root、要么弹一句 toast，随即被强制复位 |
| 那"功能"到底在哪？ | **云端下发**。dex 侧是 CloudInject 云注入框架，能力在运行时才落地（§B5.7） |
| "防封"模块做了什么？ | 9 个开关的**回调体里逐字只有 toast**，没有一行功能代码（§B5.6） |
| 这软件真正在跑的业务是什么？ | **裂变推广漏斗**：逼你往 QQ 群刷 15 次，然后告诉你"本版本已失效，去下新版"（§B5.5） |

### B5.2 引擎的能力面可以穷举 —— 24 个符号里没有一个是内存操作

以 `libygsiyu.so`（x64，223 KB）为例，`.dynsym` 中**引擎自己定义**的符号总共 **24 个 = 15 个 C++ 函数 + 9 个 `Java_com_iapp_app_b_*` JNI 入口**。逐个反汇编，能力只有三类：

| 类别 | 函数 | 实际做什么 |
|---|---|---|
| 加密 | `iapp::mete::slky` @0x8be0 | 就是 Java JCA 的 MD5（`MessageDigest.getInstance("MD5")` → `update` → `digest`） |
| 加密 | `iapp::mete::asendn` @0x9390 | 就是 Java JCA 的 AES/CBC/PKCS5（`SecretKeySpec` + `IvParameterSpec` + `Cipher.init` + `doFinal`） |
| 环境 | `iapp::Interact::fjdg` @0x9780 | **枚举本机已安装应用 + 取签名**（`getInstalledPackages` → `PackageInfo.signatures` → `toByteArray`） |
| 其余 | `Aid_String::split/substring`、`Interact::idbfj`、`burden::b`、`h3`–`h8` | 字符串工具 + 脚本包解包 + 脚本解释器入口 |

调用链里**只有** `memset`/`memcpy`/`memcmp`/`strlen`/`operator new`/JNI 反射，**没有** `ptrace`、`process_vm_readv`、`/proc/<pid>/mem`、`mprotect`、`dlopen`、`mmap`、`syscall`、`insmod`、`kallsyms` 中的任何一个。

跨 5 个 ABI 对账也一致：x64 / arm64 / x86 各 24 个符号且**完全相同**；armeabi-v7a 与 armeabi 各 44 个，比 x64 多的那 20 个（`Aid_String::trim/replace/endsWith`、`Aid_ArrayUtil::indexOf`、`Aid_Dataconversion::*`、`iapp::h`/`h2`/`h9`、`mete::djyj` 等）**全是同一批字符串工具的另一套写法**，没有一个引入新的能力类别（差异只来自 NDK 工具链 gabi++ vs llvm-libc++）。

dex 侧全量检索同样是零：`ptrace` / `process_vm_*` / `/proc/<pid>/mem` / `mprotect` / `dlopen` / `/dev/mem` / `insmod` / `kallsyms` —— 0 命中；hook 框架（epic / Dobby / xhook / ShadowHook / SandHook / YAHFA / Whale / Pine / bhook / frida / Cydia）—— 0 命中；反作弊产品名 —— 0 命中；效果词（自瞄 / 透视 / 穿墙 / 无后座 / 方框 / 骨骼）—— 0 命中。

### B5.3 菜单是个"样机"：控件接线统计

解出全部脚本后，把 `xf.iyu`（冰糖雪梨的作弊菜单）和 `null.iyu`（齿轮辅助的功能菜单）的接线数了一遍：

| 脚本 | 控件总数 | 真正有事件回调的 | 空 `<event>` 块 |
|---|---|---|---|
| `btxl__xf.iyu` | 37 Switch + 30 CheckBox + 33 RadioButton + 4 SeekBar + 1 Spinner | 37 个 Switch + 1 ImageView（拖动悬浮图标）+ 1 LinearLayout | **152 个** |
| `egaocl__null.iyu` | 10 Switch + 8 CheckBox + 3 SeekBar + 1 Spinner | 仅 1 个 ImageButton（拖动悬浮图标） | **44 / 45** |

也就是说：**所有 CheckBox / RadioButton / SeekBar / Spinner 的事件块一律为空**，齿轮辅助的整张功能菜单（10 个开关 + 8 个勾选框 + 3 个滑条 + 1 个下拉）**一个回调都没有**。

而冰糖雪梨那 37 个开关，**每个都挂了两个事件**。以「枪无后座」为例：

```
<eventItme type="clicki">
javax(run,null,"java.lang.Runtime","getRuntime")
javax(null,run,"java.lang.Runtime","exec","String","su")
</eventItme>
<eventItme type="oncheckedchanged">
f(st_iC)
{
fn fx.o("开启")
us(st_vW,"checked",false)
}
</eventItme>
```

四个观察：

1. **点一下，先偷偷申请 root**：`clicki` 里 `Runtime.getRuntime().exec("su")`，`xf.iyu` 全文 60+ 处、几乎每个开关各一处 —— 这是整个菜单里唯一真实发生的"动作"；
2. `f(st_iC)` 只在**打开**那一瞬间成立；
3. 唯一带业务含义的动作是 `fn fx.o("开启")` —— 一个**不在这 15 个脚本里定义**的外部函数；
4. 紧接着 `us(st_vW,"checked",false)` —— **立刻把开关强制按回关闭**。

（顺带纠正一个计数口径：37 个开关的回调并非"完全相同"，而是 5 种形态 —— 30 个为 `exec("su") + fx.o("开启")`，4 个防封开关的 `clicki` 改调 `fx.o("开启防封")`，1 个额外播放 `@r.mp3`、1 个缺 `clicki`、1 个 `oncheckedchanged` 不含 `su`。但万变不离其宗：**要么弹 toast，要么 `exec("su")`，没有任何一个开关触达"作弊"本身。**）

结果是这个界面**在 UI 上根本不可能显示成"已开启"**：它不是开关，是一个一次性的"申请 root + 弹 toast"按钮。

再看被作者重点宣传的「驱动」模式：字符串 `驱动` 在全部 15 个脚本里**只出现 1 次**，就是自瞄模式单选组里的一个标签（`id=95`）。它所在的 `RadioGroup`（`id=94`）`<event>` 是空的，`id=95`/`id=97` 自身的事件也是空的，全文没有任何一处 `us()` / `ug()` / `gvs()` 去读这个单选结果 —— **选择结果从未被任何脚本读取**。旁边作者自己写的提示是「参数配置仅对触摸模式生效」，即他本人在文案上就承认驱动模式不吃这些参数。

同样的情况在齿轮辅助的主界面（`egaocl__mian.iyu`）也在上演：「重置游客账户」「画质帧率解锁」「修复游戏崩溃」三个"功能"按钮，回调各只有一行 `tw("设置成功")`；「录屏时屏蔽绘制」的开关 `id=41` `<event>` 为空，**在界面上根本开不了**；游戏客户端选择组（和平精英 / PUBGM GL/KR/TW/VN/IN）与 32/64bit 组同样一个事件处理器都没有。整张主菜单唯一的"真动作"，是 `uapp("com.tencent.ig", c)` 启动 PUBG MOBILE 本体，以及 `uapp("com.huage.pink.fangfeng", c)` 拉起自家那个防封壳。

### B5.4 `fx.o` 的真身：一道分享门禁

`fx` 命名空间总共只被调用 5 个函数（`fx.o` / `fx.go` / `fx.sc` / `fx.start` / `fx.goto`），**在 15 个脚本里一个都没定义**。它们的本体在冰糖雪梨 bundle 偏移 `36544` 的 `fx.myu` 里 —— 这条目在本轮用离线字典法解出（见 §B6）：

```
fn o(x)
ss("你还未完成分享任务，暂不可"+x, n)
tw(n)
end fn
```

**三行，无条件分支。** 所以那 37 个开关点下去，无论解没解锁，永远只会弹这一句。

还有一道更敷衍的**激活门禁**（`btxl__mian.iyu`）：登录输入框的 hint 直接写着「输入666直接进入」，点「激活」后：

```
ug(9,"text",psw)
f(psw==666)
{
fw(".pw",666)
tw("登录成功\n到期时间：1970-01-01 00:00:00")
uigo("mian1.iyu")
end()
}
else
{
tw("卡密不存在")
}
```

口令写死在脚本里、到期时间是个 `1970-01-01`（Unix 纪元 0，纯摆设）、唯一的持久化键 `.pw` 就是「已激活」标志位；「解绑」按钮的回调更是只有一句 `tw("你解绑个寂寞啊")`。所谓卡密/激活/解绑，**全套都是假的**。

### B5.5 唯一的"功能"是裂变推广，而且奖励是死路

`fx.goto()` 自己把推广文案拼好，然后**指定组件**投递给 QQ：

```
s yu="[有人@我]还在为PUBGM3.0找不到稳定科技而发愁吗？\n791426562点开群号码看群介绍，进群点击群公告、群文件随便你拿\n群号：791426562\n备用群号：673110655\n电报@UNISHUAMP本消息由软件推送，如有打扰请管理员撤回"
sit(a, "action", "android.intent.action.SEND")
sit(a, "type", "text/plain")
sit(a,"classname","com.tencent.mobileqq", "com.tencent.mobileqq.activity.JumpActivity")
sit(a, "extra", "android.intent.extra.TEXT", c)
uit(a, "chooser", "分享")
```

`分享.iyu`（bundle 偏移 `42816`）的界面文案把条件写得很清楚：

> 温馨提示 / 本软件制作不易
> **你需要完成分享到100人以上群的任务15次**
> **才可开始使用，而且不能分享至一样的群**
> 你已经分享：**N** 个群，赶快去分享吧！

计数逻辑在 `fx.sc()`：读分享返回码，成功才让 `sss.ts` 加一；失败弹「取消分享或者分享到同一个群是没用的哦！」。阈值在两个文件里出现过 `sss.ts>=14` 与 `fxcs`（=15）两种写法。

**这里有个必须点破的地方**：`ACTION_SEND` 的返回码只能告诉程序"分享完成了 / 被取消了"，**它不可能知道用户分享到了哪个群**。「不能分享至一样的群」**没有任何技术手段支撑**，是一句用来逼用户多刷几个群的话术。另外，`sit(a,"classname",...)` 指定组件只是**绕过了系统选择器**、把 QQ 直接拉起来并预填好文案，发送动作仍需用户在 QQ 里确认一次 —— 不是静默群发。

那刷满 15 次之后呢？`fx.sc()` 会 `addv(ss.载体, "egaocl.iyu")` 弹出一个页面。这个 `egaocl.iyu` 在冰糖雪梨自己的 bundle 里（偏移 `67024`，文件名叫 `egaocl.iyu`，是从齿轮辅助那边抄过来的）：

> 发现新版本
> **冰糖雪梨已更新！该版本已失效（您可以不用继续分享了，新版本无需再完成分享任务，新版本会记录你完成任务的次数）**
> 【以后再说】　【前往下载】

`前往下载` 的动作是 `hws("https://www.123pan.com/s/4m9Tjv-iPf4.html")`，然后 `end("egaocl.iyu")`。

**也就是说：把推广刷满 15 个 QQ 群，换来的报酬是一个"本版本已失效，请去下载新版"的强制更新弹窗。**

### B5.6 "防封"模块：9 个只弹 toast 的开关

「哔可防封」在脚本层的全部内容是 4 个文件（`mian.iyu` / `qx.iyu` / `sto.iyu` / `import.mjs`，其中 `import.mjs` 与作弊主程序的**逐字相同**，仅文件尾 2 个填充字节不同）。逐字读完之后：

**悬浮菜单 `sto.iyu`**：9 个 SwitchCompat（大厅防①②③④、logo页面防（必须提前开）、大厅防⑤（Ca内存）、全局离线、防高风险、防追封（退出游戏前开））+ 4 个 RadioButton（区域选择）。这 13 个开关的 `oncheckedchanged` 回调体**逐字只有**：

```
tw("正在开启")
tw("开启成功")
```

（防追封那条多一句 `tw("开启成功，请退出游戏")`，RadioButton 是 `tw("已选择")`。）**没有任何变量赋值、任何文件读写、任何引擎调用** —— 开关随即复位，后端逻辑为零。

**权限页 `qx.iyu`**：全模块唯一有实际动作的地方，四张权限卡，全是**申请权限**：

| 卡片 | 动作 |
|---|---|
| 基础权限配置 | `call(null,"mjava","cd.getAppDetailSettingIntent",activity)` → 打开本应用的系统详情设置页 |
| 显示在其他应用上方 | `Settings.canDrawOverlays` 检测，为假则拉起 `android.settings.action.MANAGE_OVERLAY_PERMISSION` |
| 电池优化白名单 | `call(null,"mjava","cd.addWhiteList2",activity,bool)` |
| **ROOT** | `javax(null,run,"java.lang.Runtime","exec","String","su")` |

ROOT 那张卡旁边作者写的说明是「**应用于读写游戏内存（框架用户无需操作）**」—— 但整个样本里**没有任何一行代码在做这件事**。这是"宣称"与"实现"之间最直白的一处断裂。

那引擎里有没有一点反检测？有，但方向是反的：一类是**检测开关**（`getOpen_xposed_check` / `getOpen_vxp_check` / `getOpen_vpn_check` / `getOpen_secure_check` / `getOpen_apps_check` / `getOpen_apps_sign_check`），另一类是**hook 框架黑名单**（`com.saurik.substrate`、`de.robv.android.xposed.XposedBridge`）。它查的是"**我自己有没有被 hook**"，不是"怎么过游戏的反作弊"。两者不是一回事。

### B5.7 真正的能力在云上 —— 所以静态样本里永远看不到"外挂实现"

dex 侧的第三个 dex 整体是 **`com.cloudinject`（CloudInject 云注入）**：`com.cloudinject.feature.App`、`cloudinject.customview.FeatureButton` / `FeatureLinearLayout`，配合 `InMemoryDexClassLoader` / `VMRuntime` / `DexClassLoader`。这是**云端下发 + 内存加载 DEX** 的宿主框架，`FeatureButton` 这类类的存在说明它专为"下发一个功能按钮/功能模块"设计。

所以整个链路是：**APK 里留下的只有菜单骨架 + 门禁 + 导流；能力体在运行时从云上下发。**静态分析能证明的，就是"能静态拿到的那部分里没有作弊实现"这一条 —— 不能反过来断言"它一定没有作弊能力"。但可以断言：**这些样本自己声称"用 ROOT 读写游戏内存"的那部分，在其全部可静态分析的代码里不存在。**

同时这也解释了 §B3 第 2 条的误判 —— 把云注入壳的宿主占位包 `com.px` 当成了虚拟化框架。`mirrorb` 这个包名同样属于云注入体系，其 hook 面是 **Android 框架层**（`HCallbackStub`、`IActivityManagerSingleton`、`HookManager`、LSPosed HiddenApiBypass、`InMemoryDexClassLoader`/`VMRuntime`），是插件化容器的手法，不是游戏进程注入。

### B5.8 要区分"反分析"和"反反作弊"

这款样本在**对抗逆向分析**上做得很多，但这跟"对抗游戏反作弊"是两码事，不要混着读：

| | 有什么 | 属于 |
|---|---|---|
| **反分析**（真实存在） | 四层加固（360加固 + beingyi SubApp 壳 + armadillo 云注入 + iapp3 引擎）、字符串 AES 加密、卢恩字符混淆、`app_ded` 目录即时删除、反模拟器 SIGSEGV、日志上报 `https://log-report.com/report` | 防"人"分析它 |
| **反反作弊**（不存在） | —— | 防"游戏"发现它 |

### B5.9 对防御方的价值

从防御视角看，这批样本反而比"真有内存读写"的外挂**更好抓**，因为它的行为指纹非常固定：

1. 一上来就**权限收割**：全盘文件访问 + 悬浮窗 + 电池白名单 + `exec("su")`；
2. 用**指定组件的 `ACTION_SEND`** 拉起 `com.tencent.mobileqq/…JumpActivity` 并预填推广文案 —— 这个组合在正常应用里极少见，是很好的检测点；
3. 把"分享次数"记在本地文件里做门禁，满额后**跳转 123 云盘**下载新版；
4. 全部 UI 模板来自同一套买卖源码（资源属性里带着 `ps=爱源码:www.2ym.cn` 的署名水印）。

可落地的检测 / 封禁线索：

| 类型 | 值 |
|---|---|
| QQ 群（推广落地） | `791426562`、`673110655`、`930273991`（群二维码 `qm.qq.com/...group_code=930273991`） |
| Telegram | `@UNISHUAMP` |
| 更新下载（123 云盘） | `https://www.123pan.com/s/4m9Tjv-iPf4.html`、`https://www.123pan.com/s/4m9Tjv-vzp4.html` |
| 蓝奏云盘（访问密码 6666） | `https://wwr.lanzoui.com/b0ezcm31i` |
| 发卡网 | `https://916.vin//links/4C26E9C9` |
| UI 模板来源水印 | `爱源码` / `www.2ym.cn` |
| 包名 | `com.huage.pubgm.btxl`、`com.huage.egaocl`、`com.huage.pink.fangfeng` |
| 日志上报 | `https://log-report.com/report` |

---

## B6、尚未解决

1. 作者放置的 `会画画的圈钱狗作品集.zip` 内加密项 `作者坦白`（ZipCrypto 传统加密）口令未知，字典 + 1.7 亿掩码均未命中；口令不在任何 dex 内（应用运行时不打开该 zip）。
2. ~~冰糖雪梨 bundle 中约 2.76 万字节脚本因条目名未枚举完，尚未解出。~~
   **已解决**。改用**离线字典攻击**：每个条目开头的 16 字节 `K1 = slky(名字, gdth+dngb)` 是一个可搜索标记，于是拿候选名字算出 K1 后在解密结果里 `find()` 验证即可。字典用「全部已解出脚本 + 全部 dex/so 里的 token」自动生成。一次解出 4 个条目：`fx.myu`（分享门禁本体，@36544）、`alms.myu`（动态提示卡片，@56624）、`分享.iyu`（分享任务界面，@42816）、`egaocl.iyu`（强制更新弹窗，@67024）。齿轮辅助与哔可防封两个包**已完全解出**；冰糖雪梨仅剩两段共约 1.06 万字节（@46096–55328、@65664–67024）条目名未命中。
3. 每个包偏移 `0..4128` 的第 1 个条目名（4096 B 密文）未知。已确认它**确实是一个条目**而非固定头部 —— 三款样本这 4128 字节的 MD5 互不相同（`egaocl 9ed9a152…` / `btxl d0db81c6…` / `fangfeng 72341798…`），说明密钥随各自身份常量变化，只是名字没枚举出来。

## B7、后续进展

上面整段分析针对的是 **2026 年之前的旧版本**。这条线后来还有下文，一并记在这里：

| 时间 | 事项 |
|---|---|
| 2026-04-12 | 案件在**佛山市三水区人民法院**开庭 |
| 之后 | 作者已释放 |
| 2026 年 | 应用**仍在持续更新**（当前 `14.0.1.beta`），但**已不再带外挂功能** |

需要说清楚的一点：**这个案子本身跟齿轮辅助不是一回事。** 起因是另一款「开盒」（人肉/社工）类软件 **「灵动骇客」**，跟本次逆向分析的目标没有关系——不要把它读成"做外挂被判了"。

「灵动骇客」是作者与另一位同案人员（网名「阿通」）共同开发的，两人都因该案被追究。

> **这条的来源要说清楚**：作者与「阿通」共同开发、两人均被追究，是**知情者提供的说法**，不是从公开报道里查到的。
> 2026-09 按公开渠道做过一轮检索，结论是**查不到**：
> - 「灵动骇客」在中文互联网上主要指向一款**同名游戏**（英文名 *Jack Move*），没有任何公开材料把某个开盒软件叫这个名字；
> - 佛山三水法院确有若干「侵犯公民个人信息」的公开公告与判决，但**没有一份提到「灵动骇客」或「阿通」**；
> - 2026 年最高法典型案例里最受关注的开盒/社工库案在**北京海淀**，与佛山无关；
> - 三水区检察院 2026-05 有一份同类公益诉讼诉前公告，但通篇未点名任何软件。
>
> 因此本笔记只记录"有这么个说法"，**不把它当作已证实的公开事实**。检索失败的原因也一并说明：百度、搜狗、微博均被验证码拦截，境外搜索引擎对中文长尾内容覆盖有限。

本笔记只记录与软件本身有关的公开事实，涉案人员的真实姓名、出生日期、籍贯、住址、联系方式等个人信息一律不收录。

现在的齿轮辅助已经转成一个**免费的多功能工具箱**，形态接近「一个木函」那类合集应用：一堆日常小工具 + 内置扩展/插件系统 + 游戏优化和系统清理，不再有注入游戏的那部分。

2026-09 从官方站点取的安装包（62 MB，`assets/lib.so` 涨到 1.2 MB）核对过以下几项：

- 包名仍是 `com.huage.egaocl`，`versionCode` 仍是 `100005`，`versionName` 为 `14.0.1.beta`；
- 5 个 `classes*.dex` **全部是明文**，不再有 beingyi 壳那层 XOR 加密；
- 在全部 dex 的字符串里检索 `自瞄 / 透视 / 方框 / 锁头 / 无后座 / 除草 / 卡密 / 激活码`，**零命中**；
- 资源目录里是 galgame 素材、音乐、小游戏，不是脚本化的游戏功能。

**官方渠道**（开发团队 Huakus Club）：

- 官网：<https://ouo.huakus.club/>
- 官方安装包直链：<https://ouo.huakus.club/cdnanmsljdjrbgiskksodjxosoajddjdkow/oul/klop.apk>（61,888,184 B，Android 8.0+，版本 v14.0.1）

软件本身免费，需要的直接去官网下最新版就行。仓库里也放了一份当时的官方安装包存档（`taskb/齿轮辅助_v14.0.1_官方版.zip`，见 **§B2 目录说明**），

APK 的 MD5 是 `3cf5d89096e9566f0e23505794c30fe4`，与各下载站标注的官方包一致，可以拿它核对下载到的是不是原版。

---

## 附：详细逆向思路

口袋与齿轮两款目标的完整解密思路（含**失败方法与成功方法**的逐步记录）见 [`逆向思路.md`](逆向思路.md)。

---

*本笔记仅供安全防御研究使用。*
