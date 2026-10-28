# bee1.txt / bee3.txt 排查定论

> 结论：**密钥不在本 APK 内，离线无法解密**。本文记录完整排查过程与证据，避免重复劳动。
> 如需解开，见 §5「唯一可行路径」。

---

## 1. 三个文件的关系

服务器固定目录 `https://strongteam.co/api/bee/bee1/`，内容为：

| 文件 | 大小 | `len % 4` | 尾部 | 解码后 | 状态 |
|---|---|---|---|---|---|
| `bee1.txt` | 1,293,136 | **0**（合法 base64） | `A==` | 969,850 B | ❌ 解不开 |
| `bee2.txt` | 831,216 | **0**（合法 base64） | `=` | 623,411 B | ✅ **解开** → 623,367 B JSON（v6.99） |
| `bee3.txt` | 1,127,877 | **1**（非法 base64！） | `0Q=` | 845,907 B | ❌ 解不开 |

补充探测：

```
GET /api/bee/           -> 连接失败
GET /api/bee/bee1/      -> 403（目录禁止列出）
GET /api/bee/bee2/      -> 200，内容 === bee2.txt（831,216 B，同一份）
GET /api/bee/bee3/      -> 404
GET /api/bee/bee4/      -> 404
GET /api/bee/bee1/bee{4,5,6,0}.txt -> 404
```

`CU` 函数硬编码的是 `bee3.txt`，但**该文件不是合法 base64**（长度 mod 4 == 1），
理论上 App 自己也解不开 —— 这本身就说明它不服务于当前客户端。

---

## 2. 已排除的全部假设（含具体组合）

### 2.1 密码空间（12,569 个候选，逐个试算）

| 候选来源 | 数量 |
|---|---|
| `libgojni.so` `.rodata` 全量可打印串（8~40 字符，字符集 `[A-Za-z0-9+/=_!@#$%^&*.-]`） | ~12,000 |
| `bee2` 解密后 JSON 的全部字符串值（6~64 字符） | ~500 |
| 已知两把密码 + 常见后缀变体（`1`/`2`/`2024`/`2025`/`@123`/`Team`/`_key`…） | ~70 |
| 明文候选：`BinkeVPNTeam` / `1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+` / `TroJanP@ss` / `mmTroJanP@ssMM` / `TunnelCore` / `sandoki` / `beevpn` / `strongteam` | 8 |

固定结构 `salt(16) | nonce(12) | ct`、`AAD = salt`、`argon2id(3, 8192, 1, 32)`：

```
re_bee1.txt: 12569 tried, no hit (205s)
re_bee3.txt: 12569 tried, no hit (156s)
```

### 2.2 Argon2 参数空间（对 bee1，800 次）

`time ∈ {1,2,3,4,5}` × `memory ∈ {4096, 8192, 16384, 32768, 65536}` ×
`parallelism ∈ {1,2,3,4}` × 2 把密码 × 4 种结构 = **800 次 argon2**，全失败。

### 2.3 结构布局变体

| 布局 | 结果 |
|---|---|
| `salt16 + nonce12 + ct` | ❌ |
| `nonce12 + salt16 + ct` | ❌ |
| `salt16 + nonce16 + ct` | ❌ |
| `salt12 + nonce12 + ct` | ❌ |
| `salt24 / salt32 + nonce12` | ❌ |
| `tag` 前置（`tag + ct`） | ❌ |

### 2.4 KDF 变体

| KDF | 参数 | 结果 |
|---|---|---|
| PBKDF2-HMAC-SHA256 | iterations 1,000 / 10,000 / 100,000 | ❌ |
| scrypt | (N,R,P) = (1024,8,1) / (16384,8,1) / (32768,8,1) | ❌ |

### 2.5 编码层

- 首尾偏移：`start ∈ 0..8` × `end ∈ 0..8` 全组合，用两把密码试 → ❌
- bee3 特判：长度 mod4==1，去掉末 0~8 字符后重试 → ❌
- 字符集核查：三份文件均为纯标准 base64（含 `+` `/`，无 `-` `_`，无换行/空格）
- 结果字节特征：高熵（7.575 / 7.664 bit/byte），无 gzip magic、无 JSON 明文片段

### 2.6 密码常量是否被遗漏

对 `libgojni.so` `.rodata`（564,960 B）全量扫描，
"像密码"且长度 12/14/16/20/24/28/32/36/40 的串只有 287 个，逐一人工核对后
**只有两把**：

```
0x391a99  "BinkeVPNTeam"                      (12 B, DO()  使用)
0x3b3739  "1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+"   (32 B, decrypt() 使用)
```

其余全是 Go 字符串池的相邻碎片（如 `mmTroJanP@ssMM` 实为 `mm` + `TroJanP@ss` + `MM` 三段拼接，
`TroJanP@ss` 是配置里的 `TrojanPass` 字段值，不是 KDF 密码）。

---

## 3. 反向证据：方案本身是对的

同一套代码路径解 `bee2.txt` 一次成功：

```
pw12 OK  623367 bytes  ->  {"Version":"6.99","ReleaseNotes":"🇲🇦 MA Maroc Telecom 0 DH⚡️…"}
```

400+ 个节点字段同样用它解开。所以 **base64 → argon2id(3,8192,1,32) → AES-256-GCM(AAD=salt)**
这套流程无误，问题只可能出在 **bee1/bee3 的密码不属于本 APK**。

---

## 4. 判定

| 假设 | 判定 | 依据 |
|---|---|---|
| 密码在本 APK 其他位置 | **否定** | 12,569 候选 + .rodata 全量扫描 |
| KDF/参数/布局不同 | **否定** | 800 次参数矩阵 + 6 种布局 + PBKDF2/scrypt |
| 编码层问题 | **否定** | 17×17 首尾偏移 + 字符集核查 |
| **密钥不在本客户端** | **成立（唯一剩余）** | 上述全部排除后仅剩此项 |
| bee3 本身损坏/非本产品 | **强证据** | 长度 mod4==1，非合法 base64，App 自己也解不开 |

最可能的情形：
- `bee1.txt` / `bee3.txt` 服务于**同一开发者的其他产品线或其他版本的客户端**；
- 或服务端已轮换密钥，当前 APK（Build 64 / app-update 2.1.0）已不再匹配。

---

## 5. 唯一可行路径（按成本排序）

### 路径 1：拿对应版本的 APK（成本最低，成功率最高）

密码常量在 native 库 `.rodata` 里，换版本即换常量。找 Bee VPN 的旧版/新版：

```
apkpure / apkmirror 搜 co.strongteam.beevpn 历史版本
拿到后重复本次流程：
  ① 解包取 lib/arm64-v8a/libgojni.so
  ② 解析 .gopclntab 恢复函数名（见 docs/PROTOCOL.md 附带的 pclntab 手法）
  ③ 反汇编 AndroidLibXrayLite.DO / .Encrypt / .decrypt，读 adrp/add 常量
  ④ 用新密码 + 本仓库 tools/decrypt.py --field 试解 bee1/bee3
```

判定标准：`tools/decrypt.py <file>` 打印 `[+] pwNN OK <n> bytes` 且输出以 `{"Version"` 开头。

### 路径 2：动态 Hook（成本高，需 arm64 真机）

APK 仅 arm64，x86_64 模拟器无法加载（ndk_translation 会 SIGILL）。
需 arm64 真机 + Frida：

```javascript
// 直接拦截解密入口，拿明文，绕开密码推导
Java.perform(function () {
    const Libv2ray = Java.use("libv2ray.Libv2ray");
    Libv2ray.do_.implementation = function (s) {
        const r = this.do_(s);
        console.log("[do_] in=" + s.length + "B out=" + (r ? r.length : 0) + "B");
        if (r && r.length > 1000) console.log(r.substring(0, 300));
        return r;
    };
});
```

或 hook Go 侧：`java_libv2ray_Libv2ray_do_1` / `AndroidLibXrayLite.DO` 的地址
（可从 `.gopclntab` 解析得到偏移，见 §2 引用的手法）。

### 路径 3：横向扫同框架 App

`v2rayNG + SocksHttp/UltraSSH` 这套缝合怪是免流圈模板化产物。
识别特征：`assets/` 有 `custom1.json` / `v2inject.json`；
dex 同时含 `com.v2ray.ang.*` 与 `com.vpn.sandok.ultrasshservice`；
配置走 `https://<品牌域>/api/<x>/beeN.txt`。

新 App 的密码提取后可回头试 `bee1`/`bee3`（同一开发者常复用密钥体系）。

### 不建议：继续在本 APK 里穷举

密码空间已扫到 12,569 个候选 + 800 组 KDF 参数 + 6 种布局 + 17×17 偏移，
继续投入的边际收益已趋近于零。

---

## 6. 复现本排查

```bash
# 1) 下载三份
for n in bee1 bee2 bee3; do
  curl -x http://127.0.0.1:10808 -A "Bee VPN" -o $n.txt \
    https://strongteam.co/api/bee/bee1/$n.txt
done

# 2) 确认 bee2 可解（基准对照）
python tools/decrypt.py bee2.txt          # 必须打印 [+] pw12 OK 623367 bytes

# 3) 试 bee1/bee3
python tools/decrypt.py bee1.txt          # [-] 解密失败
python tools/decrypt.py bee3.txt          # [-] 解密失败

# 4) 若拿到新密码，单字段验证
python tools/decrypt.py --field "<任一 base64 字段>"
```
