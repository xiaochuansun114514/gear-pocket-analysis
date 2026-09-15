# 齿轮辅助（com.huage.egaocl）逆向分析 — 360加固脱壳与作弊框架

> 本笔记记录对 PUBG/和平精英 外挂 **「齿轮辅助」`com.huage.egaocl`（俗称"华哥"）** 的完整脱壳与逆向分析过程，用于**安全防御**。
> 线索链：齿轮辅助 → 更新提示 → 软件口袋 `com.rjkd.ruanku`（见 Task A）→ rjkd.cc → 蓝奏云。

---

## 一、结论速览（TL;DR）

| 项目 | 结论 |
|---|---|
| 目标 | 齿轮辅助 `com.huage.egaocl`（PUBG/和平精英 外挂，俗称"华哥"） |
| 加固层次 | **四层**：360加固(libjiagu) + beingyi(别疑惑) SubApp 壳 + armadillo 云注入 + iapp3(Lua) 引擎 |
| 真实作弊框架 | **VirtualApp 改名版**（`com.px` + `mirrorb` 包）虚拟化游戏进程注入 |
| 脱壳结果 | 3 个 dex **全部离线解密**（XOR 密钥 = 包名，无需动态 dump） |
| 支付/卡密 | iapp 官方支付 `iapp.yx93.com` + 发卡网 `sidai.wmrerey.cn`（带追踪参数） |
| **C2 服务器** | **`http://yun.dzpgrw.cn:8080`（`202.189.4.117`，卡密验证 + 配置下发，DES 加密已破解）** |
| **真实外挂脚本** | **`assets/lib.so` 是 iapp3 加密脚本包，已离线完全解密**（`mian.iyu`/`import.mjs`/`null.iyu`），无需设备 |
| 反分析 | 字符串 AES 加密、卢恩字符混淆、app_ded 目录即时删除、反模拟器 SIGSEGV |
| 日志上报 | `https://log-report.com/report` |
| 关联分包 | `com.huage.pink.fangfeng`（"哔可防封"模块，脚本内跳转） |

---

## 二、加固壳结构（四层）

```
齿轮辅助 APK (27MB)
├─ 360加固壳
│   ├─ assets/libjiagu.so (660KB, x86)
│   ├─ assets/libjiagu_x86.so (702KB)
│   └─ classes.dex (7KB, 仅 1 类 Lmuhua/yun; 方法 Ultra()V = 云注入入口)
├─ beingyi(别疑惑) SubApp 壳
│   ├─ classes2.dex (123KB, 56 个壳类)
│   │   ├─ Application = cn.beingyi.sub.apps.SubApp.SubApplication
│   │   ├─ com.beingyi.encrypt.BYDecoder (AES/ECB/PKCS5Padding 字符串解密)
│   │   ├─ com.beingyi.encrypt.StringPool (208 个加密字符串字段)
│   │   └─ Native 类 (native 方法 getKey/getStringKey/getHead)
│   └─ src/ 三个「加密」dex 文件（见 §四）
├─ armadillo 云注入 SDK (360 云注入)
│   ├─ assets/cloudinject (25KB, 内嵌 mini-APK = 卡密输入 UI)
│   ├─ assets/.appkey = "2449186c83907774" (云注入 APP_ID)
│   └─ small.dex + third.dex 里的 armadillo.* / com.cloudinject.* 类
└─ iapp3(爱根) 引擎
    ├─ com.iapp.app.* (Aid_YuCodeX/Aid_javaCode/Aid_jsCode/Aid_luaCode)
    ├─ libluajava.so (Lua 引擎) + libygsiyu.so (玉码脚本)
    └─ main_activity = com.iapp.app.run.mian
```

**应用入口**：`AndroidManifest.xml` 声明 `application = cn.beingyi.sub.apps.SubApp.SubApplication`，`main_activity = com.iapp.app.run.mian`。运行时壳释放真实 native 库 **`libFlySub.so`**（不在 APK 内）。

---

## 三、反分析手段

| 手段 | 表现 |
|---|---|
| 字符串加密 | 每个字符串独立 AES/ECB 密钥，BYDecoder 运行时解密 |
| 类/方法名混淆 | 卢恩字符（ʿ ˆ ˈ ˉ ˊ 等）类名 + 方法名 |
| 反模拟器 | `/dev/qemu_pipe`、`/sys/block/mmcblk0/device/cid` 检测 |
| 反调试 | 360 壳 libjiagu 检测 frida/调试器，MuMu 模拟器上直接 SIGSEGV 崩溃 |
| 反分析 | 解密后 dex 写入 `/data/user/0/com.huage.egaocl/app_ded/`，加载后**立即删除** |
| 辱骂/挑衅 | `AAA拆包狗看这里.txt`（辱骂逆向者）+ `会画画的圈钱狗作品集.zip` |

---

## 四、脱壳过程（关键突破：XOR 密钥 = 包名）

### 4.1 发现密钥

`src/` 下三个文件开头 8 字节均为 `07 0a 15 24 58 46 54 67`，与 dex 魔数 `dex\n035\0`（`64 65 78 0a 30 33 35 00`）逐字节异或：

```
64 ^ 63 = 07   ('d' ^ 'c')
65 ^ 6f = 0a   ('e' ^ 'o')
78 ^ 6d = 15   ('x' ^ 'm')
0a ^ 2e = 24   ('\n'^ '.')
30 ^ 68 = 58   ('0' ^ 'h')
33 ^ 75 = 46   ('3' ^ 'u')
35 ^ 61 = 54   ('5' ^ 'a')
00 ^ 67 = 67   ('\0'^ 'g')
```

异或密钥 = `63 6f 6d 2e 68 75 61 67` = **`"com.huag"`**，即包名 `com.huage.egaocl` 的前缀。

### 4.2 完整解密

beingyi 壳用 **`包名 "com.huage.egaocl"` 循环 XOR** 加密 src/ 下的 dex：

```python
def xor(data, key):
    kb = key.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
# 解密后直接是合法 dex（dex\n035 魔数验证通过）
```

**三个 dex 全部离线解密成功**（无需内存 dump、无需运行 app）：

| src 文件名 | 密文大小 | 解密结果 | 类数 | 内容 |
|---|---|---|---|---|
| `2e15f58d32a5ff652706ef41ec85a763` | 5451032 | big.dex | **4592** | iapp3 引擎 + 主业务（androidx 2477 / com 1218 / c 393 / bsh 158） |
| `ab59b2d465027c91ef7bcfe0a82f251b` | 1590000 | third.dex | **1207** | 云注入 SDK + VirtualApp 改名版（com 583 / mirrorb 389 / android 187） |
| `2ba5b2615b9b71b48c7694d6489e0171` | 1126428 | small.dex | **1145** | armadillo SDK（armadillo.* 200+ 混淆类） |

> 完整解密脚本见 `../tb/decrypt_src.py`。

---

## 五、三个 dex 分析

### 5.1 big.dex（主业务 dex，4592 类）

本质是 **iapp3(爱根) 开发引擎运行时**——`com.iapp.app.*` 全部是引擎内置桥接类：

- `Aid_YuCodeX` / `Aid_javaCode` / `Aid_jsCode` / `Aid_luaCode`（Lua/Java 脚本桥接）
- 主 Activity `com.iapp.app.run.mian`（iapp 引擎宿主）
- 支持 `.iyu` / `.lua` 脚本格式，`libluajava.so` 提供 Lua 引擎
- **真正的外挂功能在 Lua 脚本里**（脚本本身另行加密/下载），dex 只是引擎壳

仅发现的明文 URL：`iappoay://iapp.yx93.com:`（**iapp 官方支付网关**，外挂用 iapp 支付收款）。

### 5.2 small.dex（armadillo 云注入 SDK，1145 类）

360「云注入」SDK 的 UI/封装层：

- `armadillo.CloudApp` / `armadillo.Global` / `armadillo.VerifyActivity`（卡密验证界面）
- `armadillo.ip` / `armadillo.io` / `armadillo.zn`（网络层）
- `com.cloud.verify_java.MainActivity` / `Test`（云卡密验证）
- 内嵌两把 **RSA 公钥**（用于加密卡密/设备信息上报 C2）+ 两个 SHA1 指纹
- `assets/cloudinject`（25KB）= 内嵌 mini-APK，含 `cloudinject_password.xml` / `cloudinject_register.xml` / `cloudinject_input_*.xml`（卡密输入/注册 UI）

### 5.3 third.dex（云注入核心 + VirtualApp，1207 类）

| 包 | 类数 | 身份 |
|---|---|---|
| `com.px` | 304 | **VirtualApp 改名版**（`ProxyActivity` SingleInstance/SingleTask/SingleTop、`DaemonService`、`FContentProvider`、`FService`） |
| `mirrorb` | 389 | VirtualApp 的 `mirror.*` 反射包改名（`mirror.android/com/java/oem/libcore/dalvik` + `RefClass/RefMethod/RefObject` 等） |
| `com.cloudinject` | 276 | 云注入 SDK 核心（`com.cloudinject.feature.App`、`RemoteShareInfo`、`HookManager`） |
| 混淆包（卢恩字符） | 19 | 云注入字符串解密/工具类 |

**关键**：`com.cloudinject.feature.App` 类字段：

| 字段 | 值 | 用途 |
|---|---|---|
| `APP_ID` | `b511f38fae0b82b50000242d50cf1ffd` | 云注入应用 ID（**DES 密钥来源**） |
| `A` | `43082785f7b20e90...`（DES 密文） | **被替换的原 Application 入口** |
| `INCREMENT_DATA` | `296bf0812ac7553b` | 增量配置（加密） |
| `PLUGIN_VERIFY` | `47ad424dc93ce95c6b8b400c4a698dc5` | 插件校验值 |
| `VERSION_CODE` / `VERSION_NAME` | `23` / `2.3` | 云注入 SDK 版本 |

> 这里容易混：`assets/.appkey` = `2449186c83907774` 是**另一套**标注为云注入 APP_ID 的值；真正用于加解密的是 `App.APP_ID` = `b511f38fae0b82b50000242d50cf1ffd`。

云注入用 **DES** 保护配置，两套独立密钥（详见 §5.5）。

### 5.4 作弊机制推断

```
齿轮辅助启动
  → 360 壳 libjiagu 释放真实代码
  → beingyi 壳 XOR 解密 src/ 三个 dex 加载
  → iapp3 引擎启动，加载 Lua 脚本（UI）
  → armadillo 云注入连接 C2（地址 DES 加密）
      ├─ 卡密验证（VerifyActivity，卡密 RSA 加密上报）
      ├─ 无效卡密 → 跳转发卡网 sidai.wmrerey.cn 购买
      └─ 有效卡密 → 下发真实外挂 payload
  → com.px/mirrorb (VirtualApp) 虚拟化「和平精英」进程
      → HookManager 注入内存读写/自瞄/透视等功能
```

### 5.5 云注入 C2 服务器与 DES 加密算法（已完全破解）

#### 5.5.1 C2 服务器

云注入 SDK（`armadillo.*`）的命令与控制服务器：

```
http://yun.dzpgrw.cn:8080
├─ /Auth/Verify                    ← 卡密验证接口（提交卡密 + 设备指纹）
└─ /apis/usersoft/getico?uuid=     ← 配置/图标下发接口（uuid = 设备或应用标识）
```

- 域名 `yun.dzpgrw.cn` → **`202.189.4.117`**（中国大陆，AS139180）
- 服务器**当前在线**：`/Auth/Verify` 返回 `HTTP 444`（nginx 反探测），`/` 返回 `404`
- 调用方：`armadillo.VerifyActivity`、`armadillo.c6`、`armadillo.p5`、`armadillo.z3`

另有日志上报通道（third.dex）：`https://log-report.com/report`（Cloudflare 前置）。

#### 5.5.2 字符串加密算法

云注入对敏感字符串做 **DES/CBC/PKCS5Padding** 加密，以 hex 存储、运行时解密：

| 用途 | 模式 | 密钥 | IV |
|---|---|---|---|
| 配置字符串（ROM 类型等） | DES/CBC/PKCS5Padding | `KbMMxfM,` | `KbMMxfM,` |
| 原 Application 入口（`App.A`） | DES/ECB | `b511f38f`（= `APP_ID` 前 8 字节） | — |

**密钥 `KbMMxfM,` 的构造**（藏在扁平化控制流里，由三段 const-string 拼接）：

```
"KbMMxfM"  +  "."  +  ","
  ↓ StringBuilder 拼接 → String.getBytes("UTF-8")
  ↓ 取前 8 字节 → DESKeySpec / IvParameterSpec
```

**解密验证**（DES/CBC/PKCS5，key = IV = `KbMMxfM,`）：

| 密文 | 明文 |
|---|---|
| `1E21D241FB2B81CA` | `EMUI` |
| `A7B0A11A5AA072E5` | `MIUI` |
| `CEC9565C412F902B` | `FLYME` |
| `491A55DC89E6FC11571B3460B8CCA37D` | `COLOR_OS` |
| `5AA4016D5AB38135` | `LETV` |
| `0AF43215CF70F0D7` | `VIVO` |
| `6421234A1B7D138D` | `_360` |
| `0DBA781B12DFB91C` | `SAMSUNG` |
| `1AF39A84751305E3` | `OTHER` |
| `97745B701803821F4238DB8735FEF03D` | `activity_task` |

**原 Application 入口还原**（DES/ECB，key = `b511f38f`）：

```
App.A = 43082785f7b20e90...  →  "com.iapp.app.x5.APPAplication"
```

即：云注入把原入口（iapp3 的 Activity）替换为自己的 `com.cloudinject.feature.App`，
卡密通过 `VerifyActivity` 提交到 `yun.dzpgrw.cn` 验证通过后，才放行真实外挂代码。

> 说明：云注入是**通用 SDK**，密钥 `KbMMxfM,` 对该 SDK 打包的所有应用相同，
> 可用于批量脱壳其他同类外挂。

---

### 5.6 真实外挂脚本 assets/lib.so —— 已完全离线解密

`assets/lib.so`（36896 字节）**不是 ELF、不是 Lua、不是任何已知压缩格式**（熵 7.9952，10 个偏移量上
zlib/gzip/deflate/lzma/bz2 全部失败）。它是 iapp3 引擎自己的**加密脚本包（bundle）**，
解密算法完全在 `libygsiyu.so` 的 native 代码里，**可以离线复现，无需运行 App、无需设备**。

#### 5.6.1 加载链

```
Java com.iapp.app.run.mian.d()   Intent extra "OpenFilexmlui"，缺省 "mian.iyu"
  → native iapp::h3(env, obj, jclass, jstring)            @0xb26c
  → iapp::burden::b(arg1=NULL, arg2="mian.iyu")           @0xa1f4
      1. fp = LuaStateFactory.a（静态缓存）；为空时 = com.iapp.app.f.b("lib.so", ctx) 读 assets/lib.so
      2. arg1==NULL ⇒ r8 = com.iapp.app.e.af(ctx)（读 files/config/userencryption.xml 的 <s>…</s>）
      3. r8 = Interact::idbfj(<该串>)  → 16 字节根密钥
      4. sb = slky(r8, slky(r8, r8))  （因 assets/extra_conf1g.xml = "<signature>1</signature>" 走无签名分支）
      5. fp = djyj( asendn(lib.so, sb, MODE=2), sb )  → 明文包，缓存进 LuaStateFactory.a
```

> 动态验证：在真机 hook `asendn` 入口，实测 `mode=2`（解密），第 2 参数 = **16 字节密钥**，
> 与推导出的 `sb` 完全一致 —— 证实 `IV == KEY`、`MODE=2 为解密`。

#### 5.6.2 密钥派生（完整算法）

**① 身份串 `S`**（`Interact::idbfj` @0x965c 拼接）：

```
S = gdth + versionName + packageName + label + versionCode + dngb
  = "A21FE8A824QQQQQQQQQQWWWWWWWWWWEE"   ← libygsiyu.so 内置常量（32B）
  + "11.1.0"                              ← AndroidManifest versionName
  + "com.huage.egaocl"                    ← packageName
  + "齿轮辅助"                             ← application android:label（UTF-8 12B）
  + "100005"                              ← versionCode
  + "5556367"                             ← libygsiyu.so 内置常量（7 位）
  （共 79 字节）
```

**② 盐选择器**：`sel = (S[末] * S[首] + len(S) + ΣS) % 6`
→ `(55*65 + 79 + 7205) % 6 = 5` ⇒ 第 6 项 = `dngb` = `"5556367"`
（6 个候选依次为 versionName / packageName / label / versionCode / gdth / dngb）

**③ 根密钥**：`r8 = slky(S, "5556367")` = `c03169faef051641b5df5503eadaea37`

**④ 包密钥**：`sb = slky(r8, slky(r8, r8))` = `205152ed541566e96eec16538c501ba1`

**⑤ `slky` = 自定义加盐 MD5**（`iapp::mete::slky`）：

```
L     = len(a1)
ssum  = L + Σ (int8)a1[i]          # 有符号字节求和
q     = ssum / L   (C 截断)         rem = ssum % L  (C 取余)
h     = ((int8)a1[-1] * int8(a1[0]) + ssum) / L
buf   = a1 + str(h) [+ a2]
mask  = (8 + rem + len(a2)) & 0xFF
buf 每字节 ^= (q & 0xFF)
M     = MD5(buf)
扰动：for i in 0..15: j = |int8(M[i])| % 16
        if j > 8: M[i] ^= mask
        swap(M[i], M[j])
→ 返回 16 字节
```

**⑥ `asendn` = AES-128-CBC**：`Cipher.getInstance("AES/CBC/PKCS5Padding")`，
`SecretKeySpec(KEY,"AES")` + `IvParameterSpec(同一 KEY)`（**IV == KEY**），`init(MODE)`，`doFinal(DATA)`。
**⑦ `djyj` = 循环 XOR**：`data[i] ^= key[i % len(key)]`

**⑧ 解包**：`fp = djyj( asendn(lib.so, sb, 2), sb )`

#### 5.6.3 包内分片格式与取条目

```
每条目 = [K1:16B] [AES-CBC 密文] [K2:16B]
K1 = slky(条目名, gdth + dngb)
K2 = slky(条目名, dngb + gdth)
K3 = slky(条目名 + gdth + dngb, 条目名)
条目明文 = djyj( asendn(密文, K3, MODE=2), K3 )
```

| 条目 | 偏移 | 大小 | 内容 |
|---|---|---|---|
| （未知名） | 0–4128 | 4096 | 名字未爆破出（非常见名） |
| `import.mjs` | 4128–20128 | 15968 | iapp JS 桥（`function fn(name){…document.getElementsByTagName('HEAD')…}`） |
| `mian.iyu` | 20128–28192 | 8032 | **主界面脚本** |
| `null.iyu` | 28192–36896 | 8576 | 物品列表页脚本 |

三级的 PKCS5 填充全部校验通过，明文为完整可读 iapp 工程 XML —— 密钥确证
（2^-128 级巧合不可能）。**复现脚本：`../tb/w/dec_iyu.py`（可直接运行）**，
产物 `../tb/w/mian_iyu.txt` / `import_mjs.txt` / `null_iyu.txt`。

#### 5.6.4 脚本还原出的作弊事实（`mian.iyu`）

| 证据 | 内容 |
|---|---|
| **目标游戏** | 和平精英、**PUBG MOBILE GL / KR / TW / VN / IN**（6 个地区版本）、32bit/64bit 选择 |
| **ROOT 依赖** | `javax(…"java.lang.Runtime","getRuntime")` → `Runtime.exec("su")`；界面明示"本程序依赖于 ROOT 环境或虚拟容器内运行" |
| **启动游戏** | `uapp("com.tencent.ig", c)` |
| **关联分包** | `uapp("com.huage.pink.fangfeng", c)` —— **"哔可防封"**，作者自己的反封号模块，未安装时提示"如果不安装容易导致账号封禁" |
| **功能按钮** | 重置游客账户 / 画质帧率解锁 / 修复游戏崩溃 / 悬浮窗 / 录屏时屏蔽绘制 |
| **物品透视数据** | `null.iyu` 内完整游戏物品表：一块金砖、一根金条、GPU处理器、镜头、精密仪器蓝图、**密码信函（黑/白/红/黄/绿）**、生物样本、平板电脑、探测器、狗牌、科技部件、信号发生器、CPU处理器、净水器、汽车钥匙、笔记本、军用手表、润滑油、柴油、燃气瓶、零件袋、爱心项链、防震耳机、便携展示柜、崭新军靴、机油、怀表、粉色手枪、小钱箱、玩具匕首、指南针、老式录像带、军用水壶、便携手礼、扑克牌、明信片、罐头、杂志 |
| **作者 QQ** | `2785687263`（脚本内 QQ 群图片 `http://gchat.qpic.cn/gchatpic_new/2785687263/3563891951-0-92094660719EAE7ADBA30D0997CDD794/0?term=2`）；`2482608331`（「圈钱狗作品集」图片内，该号已因违规被封/状态异常） |
| **免责话术** | "你只管操作，剩下的交给我" |

> **重要限制**：`mian.iyu` 只是**启动器 UI**（选游戏 → 申请 ROOT → 拉起游戏 + 防封模块）。
> 真正注入游戏内存的作弊逻辑在 `com.huage.pink.fangfeng`（哔可防封）里，属另一 APK，本次未获取。

---

### 5.7 通用化解密：三款同源应用全部离线还原

**（2026-09-15 突破）** 本节把 §5.6 的单应用结论推广到同作者的另外两款应用，
三款应用的 `assets/lib.so`（iapp3 加密脚本包）**现已全部离线解密**。

#### 5.7.1 引擎同一性 —— 三款应用只差一串身份串

同作者三款应用的 native 引擎 `libygsiyu.so` 做逐字节比对：

| 比对 | 长度 | 差异区段 | 差异字节数 |
|---|---|---|---|
| btxl ↔ fangfeng (arm64-v8a) | 403040 | 1 段 | **8 B** |
| egaocl ↔ fangfeng (x86) | 279852 | 2 段 | **9 B** |

差异**全部**落在那串 34 字符身份串的中段数字体上（如 `A21FE8A824` ↔ `883963988B`），
其余字节**完全相同**。结论：**三款应用共用同一份 iapp3 引擎二进制，只是每应用内嵌一段不同的身份串。**

| 应用 | 引擎身份串（即 `Interact::gdth()` 的返回值） |
|---|---|
| `com.huage.egaocl` | `A21FE8A824QQQQQQQQQQWWWWWWWWWWEE` |
| `com.huage.pubgm.btxl` | `8014598C3BQQQQQQQQQQWWWWWWWWWWEE` |
| `com.huage.pink.fangfeng` | `883963988BQQQQQQQQQQWWWWWWWWWWEE` |

#### 5.7.2 DNGB 是每个应用各编各的 Java 常量（关键）

`Interact::dngb()` 的实现是 `to_string(com.iapp.app.f.b())` —— **值来自 Java 侧，不是 native 常量**。
所以在三份 `.so` 里 `grep 5556367` 均为空。

反汇编 `Lcom/iapp/app/f;->b()I`，字节码就是一个立即数：

```smali
# com.huage.egaocl     (classes.dex 内，beingyi 壳加密后经包名 XOR 解出)
const v0, 5556367
return v0

# com.huage.pubgm.btxl (classes.dex，明文无壳)
const v0, 3401192
return v0

# com.huage.pink.fangfeng (classes2.dex，明文无壳)
const v0, 2405525
return v0
```

**这是此前 `btxl`/`fangfeng` 解密失败的唯一原因**：误用了 egaocl 的 `5556367`。
算法本身（§5.6.2）完全一致，无需改动。

#### 5.7.3 三款应用解密参数与结果

| 应用 | pkg | verName | verCode | label | sel | 16 字节密钥 `sb` |
|---|---|---|---|---|---|---|
| egaocl | `com.huage.egaocl` | 11.1.0 | 100005 | 齿轮辅助 | 5 | `205152ed541566e96eec16538c501ba1` |
| btxl | `com.huage.pubgm.btxl` | 2.3.0 | 100001 | 冰糖雪梨 | 5 | `d0cf48bd89656675c88dcd66179da975` |
| fangfeng | `com.huage.pink.fangfeng` | 6.5.1 | 100005 | 哔可防封 | 1 | `8256428d169bcad93e6748db022f7012` |

已还原的条目（产物在 `../tb/unpacked/`，复现脚本 `../tb/w/dec_all.py`）：

| 应用 | 条目 | 包内偏移 | 明文大小 |
|---|---|---|---|
| egaocl | `import.mjs` | 4128 | 15968 B |
| egaocl | `mian.iyu` | 20128 | 8032 B |
| egaocl | `null.iyu` | 28192 | 8576 B |
| btxl | `import.mjs` | 4128 | 15968 B |
| btxl | `mian1.iyu` | 20128 | 9952 B |
| btxl | `null.iyu` | 30112 | 5840 B |
| btxl | `mian.iyu` | 38656 | 4128 B |
| btxl | `test.iyu` | 55328 | 1264 B |
| btxl | `qzhtc.iyu` | 60512 | 5136 B |
| btxl | `tc.iyu` | 65680 | 1312 B |
| btxl | `xf.iyu` | 71312 | **44384 B** |
| fangfeng | `import.mjs` | 4128 | 15968 B |
| fangfeng | `mian.iyu` | 20128 | 4192 B |
| fangfeng | `sto.iyu` | 24352 | 7744 B |
| fangfeng | `qx.iyu` | 32128 | 7792 B |

**条目名是运行期拼出来的**（不在 dex/引擎字符串表中），本次用「解密 → 从明文里挖出被引用的脚本名 → 再解密」的迭代扩散法收敛。

**`import.mjs` 在三款应用中大小与内容完全一致（15968 B，且同在偏移 4128）** ——
它是 iapp3 引擎自带的 JS 桥，定义 `tw`/`ss`/`syso`/`fn` 等基础函数，与业务无关。

#### 5.7.4 新还原出的事实

**`btxl`（冰糖雪梨）`mian.iyu`：**

```
s psw = <输入框>
f(psw==666) { fw(".pw",666); tw("登录成功\n到期时间：1970-01-01 00:00:00"); uigo("mian1.iyu"); end() }
else        { tw("卡密不存在") }
```

- **硬编码进入口令 `666`**（界面提示文字即「输入666直接进入」）
- 启动后遍历已安装应用，检测关联包 **`com.unizone.egaoqzh`** 是否存在
- 作者签名 **`By.羽霖咲华Unishua`**
- 官方卡网 **`https://916.vin//links/4C26E9C9`**
- 网盘分发 **`//www.123pan.com/s/4m9Tjv-vzp4.html`**

**`btxl` `xf.iyu`（44384 B，作弊菜单本体）：**

- 作弊功能项：**自瞄 / 自瞄模式（含「驱动」模式）/ 自瞄范围 / 穿墙 / 无后座 / 加速 / 防封**
- 分区：越南 / 日韩 / 台湾 / 印度 / 国际 / 体验 / 轻体
- 环境：Root / NoRoot；32bit / 64bit
- 界面文本含 `官方卡网`（对应上面的 916.vin）
- 整个脚本**唯一**的 Java 反射调用是 `Runtime.getRuntime().exec("su")`（取 root），
  作弊落地逻辑由 native 引擎承担

**`btxl` `qzhtc.iyu`（5136 B）：**

- 含水印 `爱源码 www.2ym.cn` —— iapp 脚本源码共享站，其更新停在 2025-09，佐证脚本来源与停更时间线

**`fangfeng`（哔可防封）`mian.iyu`：**

- 「悬浮窗」开关 → 加载 `sto.iyu` 悬浮窗（`uxf("sto.iyu", …)`）
- 「高级权限配置」按钮 → `uigo("qx.iyu")`
- 「下载齿轮辅助」按钮 → **`https://wwr.lanzoui.com/b0ezcm31i`，访问密码 `6666`**（新分发渠道）
- 加 QQ 群链接 group_code **`930273991`**
- 启动即申请 `android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION`（**全盘文件访问**）

#### 5.7.5 本次已覆盖的字节范围

| 应用 | 包大小 | 已解出条目 | 未覆盖字节 |
|---|---|---|---|
| egaocl | 36896 | 3 | 4240 |
| btxl | 115840 | 8 | ~27648 |
| fangfeng | 40064 | 4 | 4256 |

三个包开头的 `0..4128` 段（4096 B 密文）位置相同、密文各异，其条目名尚未取得；
`btxl` 余量最大。未解事项统一列在 **§八**。

---

## 六、支付与卡密分发链

### 6.1 iapp 官方支付

- 支付协议：`iappoay://iapp.yx93.com:`（iapp 引擎内置支付网关，外挂作者直接用 iapp 平台的收款能力卖卡密）。

### 6.2 发卡网（卡密购买链接）

用户点击 App 内「购买卡密」跳转（**运行时从 C2 动态下发**，不在 APK 明文里）：

```
https://sidai.wmrerey.cn/moc/by/index.html?rtkcid=6aa7e8399a51898e39081a32&rtkcmpid=698a16c2096ba2187cc270aa
```

- 域名 `sidai.wmrerey.cn` = 卡密发卡平台
- `rtkcid=6aa7e8399a51898e39081a32` = 本外挂的追踪 ID（作者靠此收卡密分成）
- `rtkcmpid=698a16c2096ba2187cc270aa` = 推广活动 ID

### 6.3 卡密购买后的下载物

用户购买卡密后下载到的 APK 名称是一串乱码，实际是一个 **类 Telegram 的聊天软件**（用于售后/更新群，规避封号与审查）。

---

## 七、结论

1. **齿轮辅助 = 四层加固**（360 + beingyi + armadillo 云注入 + iapp3），其中 beingyi 壳的 dex 加密算法是 **「包名循环 XOR」**，可直接离线解密，3 个 dex 共 7384 个类全部还原。
2. **作弊核心技术 = 改名版 VirtualApp**（`com.px` + `mirrorb`），用于虚拟化运行「和平精英」并注入外挂功能，逃避游戏反作弊检测。
3. **云注入 + 卡密验证**：armadillo SDK 通过 DES 加密的 C2 配置下发真实外挂 payload，卡密用 RSA 公钥加密上报；无效卡密引导至发卡网 `sidai.wmrerey.cn`。
4. **收款链**：iapp 官方支付 `iapp.yx93.com` + 发卡网 `sidai.wmrerey.cn`（追踪参数可直接定位外挂作者收益）。
5. **反分析**：反模拟器（SIGSEGV）、反调试、字符串 AES 加密、卢恩字符混淆、解密目录即时删除，且附辱骂逆向者的挑衅文件。
6. **作者身份（据公开裁判文书/抖音公开信息，需与执法机关核实）**：本名王泽华，男，2004-07-27 生，江西省吉安市安福县人，因「提供侵入、非法控制计算机信息系统程序、工具罪」（刑法第285条第3款）于 2026-05-11 被逮捕（羁押于广东佛山三水区看守所），现缓刑释放；与脚本内签名「By.羽霖咲华Unishua」对应。羁押地在广东而籍贯在江西，表明该案由广东司法机关管辖（受害游戏方腾讯总部在深圳）。

   > 该案具体案号/判决书尚未在公开检索中索引到（本条身份信息经抖音公开视频检索所得），
   > 需向安福县司法机关核实。同罪名 2026 年在江西已被用于打击游戏外挂产业——参考案例：
   > 鹰潭市余江区人民法院 2026-05-06 宣判「全国首例 AI 游戏外挂案」（被告人王某合，同罪名，
   > 有期徒刑三年、缓刑五年，并处罚金、没收违法所得）。
   > 另有抖音评论区说法（未经核实）：该作者入狱原因或与「开盒（人肉/社工）软件」有关，
   > 而非仅游戏外挂——若属实，说明其同时涉足公民个人信息黑产，情节更重。

## 八、待进一步验证（未解事项汇总）

### 已解决

| 事项 | 结论 |
|---|---|
| 云注入 C2 服务器域名 | `http://yun.dzpgrw.cn:8080`，DES 密钥 `KbMMxfM,` 已还原（§5.5） |
| 云注入字符串加密算法 | DES/CBC/PKCS5Padding，key = IV = `KbMMxfM,`（§5.5） |
| 真实外挂脚本 `assets/lib.so` | iapp3 加密脚本包离线完全解密（§5.6） |
| 作弊脚本本体所在分包 | egaocl / btxl / fangfeng 三款的 `assets/lib.so` **全部**离线解密（§5.7） |

### 未解

1. **每个包偏移 `0..4128` 的第 1 个条目名**（4096 B 密文）。
   该段在三款应用中位置相同、密文各异，说明是按各应用密钥加密的真实条目；
   名字不在脚本、dex、引擎字符串表中，短词干（≤4 字符 × 15 种扩展名）穷举未命中，
   需运行期 hook `iapp::h3(JNIEnv*, jobject, jclass, jstring)` 抓第 4 参数。
2. **`btxl` 的包（115840 B）仍有约 2.76 万字节未解**（首条目 4128 B + 4 个间隔段）。
   已用「扩散挖名 + 20.8 万短名暴力 + 中文/项目名 + 引擎字符串挖掘」穷举，本次新增还原 `test.iyu`（作者残留测试页），
   剩余条目名需运行期 hook `iapp::h3` 抓取。
3. **「作者坦白」zip 口令**。该条目是 ZipCrypto + deflate，包内其余 6 项未加密，
   不存在同密码的已知明文，故 bkcrack 已知明文攻击原理上不适用。
   已穷尽且零命中：4.2 MB 变形字典、465k 条 dex 字符串、定向候选（QQ 号 / huage 变体）、
   1.72 亿掩码（8 位内纯数字 + 5 位内小写 + 5 位小写含数字，耗时 13458 秒）。
   下一步方向：更大规模中文语境字典，或换未加密的同一文件副本。

---

*本笔记仅供安全防御研究使用。*
