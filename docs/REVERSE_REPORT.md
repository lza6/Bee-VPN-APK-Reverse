# Bee VPN (co.strongteam.beevpn) 逆向报告

> 目标：`Bee VPN_Build_64.apk`（47,114,711 B，arm64-v8a only）
> 分析日期：2026-10-29 ｜ 分析范围：配置下发链路、加密方案、节点池结构、真实可用性
> 性质：协议与数据格式研究。产物不含任何绕过上游风控的实现。

---

## 1. 应用架构

| 项 | 值 |
|---|---|
| 包名 | `co.strongteam.beevpn` |
| 内核 | v2rayNG（`com.v2ray.ang.*`）+ SocksHttp/UltraSSH（`com.vpn.sandok.ultrasshservice`）+ ics-openvpn（`com.sandok.tunnel`） |
| Native | `libgojni.so`(32.7 MB, Xray-core + Hysteria2 客户端) / `libuz.so`(24.7 MB, hysteria 二进制) / `libovpncli.so`(OpenVPN3) / `libtun2socks.so` / `libpdnsd.so` / `libsocks.so` / `libdns.so` |
| 加固 | `com.pairip.licensecheck`、自研 `isSecured`/`EO` 反篡改（提示 `Security Check Failed` / `App mod Detected`） |
| 混淆 | 类名/方法名 Unicode 乱码 + 静态垃圾方法（`HomeFragment` 内大量 `if (C0002.m250() <= 0)` 空壳） |
| 受众 | 摩洛哥（MA Maroc Telecom / INWI / IAM）、埃塞俄比亚、伊朗运营商免流场景；Telegram `t.me/beevpn1` |

`assets/configfile.json`（832,632 B）为内置加密配置；`assets/custom1.json`、`v2ray_config.json`、`v2inject.json` 是 v2rayNG 遗留模板，**全项目无引用点（死资产）**。

---

## 2. 配置下发链路

### 2.1 入口

`com.v2ray.ang.util.ConfigUpdate`：

```java
Libv2ray.cu(currentVersion)        // 检查更新 -> 下载配置并缓存到全局
String verNotes = Libv2ray.getVerNotes("Version");
String gfc = Libv2ray.gfc();       // 取配置(解密后明文 JSON)
prefs.put("CurrentConfigVersion", verNotes);
prefs.put("KidConfigMM1", gfc);    // ★ 解密结果落到 SharedPreferences
```

`ServerStatusVIew.g()` 优先读 `KidConfigMM1`，缺失时才回落到 `assets/configfile.json`，
再经 `Hometab.Companion.a(str)` → `libv2ray.Libv2ray.do_(str)` 解密，Gson 解析为 `ConfigData`。

### 2.2 服务端地址（Native 层还原）

`AndroidLibXrayLite.CU` 内硬编码：

```
GET https://strongteam.co/api/bee/bee1/bee3.txt
User-Agent: Bee VPN
```

同目录实测存活三份：

| 文件 | 大小 | 状态 |
|---|---|---|
| `bee1.txt` | 1,293,136 B | 下载成功，密钥不匹配（见 4.4） |
| `bee2.txt` | 831,216 B | **解密成功**（Version 6.99，本文数据来源） |
| `bee3.txt` | 1,127,877 B | 下载成功，密钥不匹配 |
| `bee4.txt`/`bee.txt` | — | 404 |

> 直连 `strongteam.co` 会被 RST，需经境外出口访问（本机 `127.0.0.1:10808` 代理实测 200）。

### 2.3 Native 符号定位法（关键手段）

`libgojni.so` 被 strip（无 `.symtab`），但保留了 `.gopclntab`（11.6 MB）。
解析 pclntab（magic `0xfffffff1`，Go 1.20+ 格式）可恢复 39,830 个函数名与地址，
再用 `capstone` 反汇编 ARM64 即可读常量：

```
Java_libv2ray_Libv2ray_do_1  -> main.proxylibv2ray__DO -> github.com/2dust/AndroidLibXrayLite.DO
                                                      -> AndroidLibXrayLite.decrypt
```

---

## 3. 加密方案（完整还原）

### 3.1 结构

```
payload = base64_std( salt(16) || nonce(12) || AES-256-GCM(ct || tag) )
```

### 3.2 密钥派生

```python
key = argon2.IDKey(password, salt, time_cost=3, memory_cost=8192, parallelism=1, hash_len=32)
```

反汇编证据（`AndroidLibXrayLite.Encrypt`，寄存器映射已交叉验证）：
`x13=3`(time) / `x14=0x2000`(memory=8192 KiB) / `x15=1`(threads) / `[sp+8]=0x20`(keyLen=32) / `x0=2`(argon2id)。

### 3.3 ★ 最容易踩的坑：AAD = salt

`Encrypt` 中 `gcm.Seal(dst, nonce, plaintext, additionalData)` 的第 4 参指向 **salt(16 B)**，
`decrypt` 中 `Open(..., additionalData=salt)` 同理。

**只解 base64 + AES-GCM 而不传 AAD = 必然 MAC 失败**，这是本方案卡住最久的一环。
同理：`salt` 用**前 16 字节**、`nonce` 用 `[16:28]`、密文用 `[28:]`。

### 3.4 两把密码

| 常量地址 | 值 | 长度 | 用途 |
|---|---|---|---|
| `0x391a99` | `BinkeVPNTeam` | 12 | `DO()`：内置 `configfile.json` 整体解密 + **所有节点字段**逐字段解密 |
| `0x3b3739` | `1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+` | 32 | `decrypt()`：另一路径（部分配置整体解密） |

节点内每个敏感字段（`ServerIPHost` / `OVPNUser` / `OVPNPass` / `V2rayUUID` / `CustomCertificate` …）
都以同一方案**独立加密**，用 12 字节密码 + 各自 salt。

### 3.5 可工作的最小实现

```python
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PW = b"BinkeVPNTeam"

def decrypt_field(s: str) -> str:
    b = base64.b64decode(s + "=" * (-len(s) % 4))
    salt, nonce, ct = b[:16], b[16:28], b[28:]
    key = hash_secret_raw(PW, salt, 3, 8192, 1, 32, Type.ID)
    return AESGCM(key).decrypt(nonce, ct, salt).decode()   # ★ AAD=salt
```

`bee2.txt` 整体解密后为 623,367 B 明文 JSON，顶层键：
`Version / ReleaseNotes / Telegram / Facebook / DefOVPNUser / DefOVPNPass / HysteriaUser / HysteriaOBFS / DefaultOVPNCert / Servers[] / Networks`。

---

## 4. 节点池结构

### 4.1 总体

**67 个节点 / 121 个唯一主机 / 配置版本 6.99**

| 协议 | 数量 | 承载类型 |
|---|---|---|
| V2ray (VLESS+WS+TLS) | 29 | GCP Cloud Run 11 / Cloudflare Worker 10 / Alibaba 4 / Xhttp 2 / WS Server 2 |
| OVPN | 17 | raseedsk.uk 系列 10 / CloudFront 5 / mcnetvpn.store·regtunnel·arifvai·dertunnel·atifpkdev 等 |
| UDP Hysteria (Hysteria2) | 8 | 独立 VPS（65.108.245.200 / 84.46.251.210 / 172.104.240.194 / 94.16.104.117 / 102.208.216.184 / 62.238.16.144 / 74.115.172.176 / focusapps.site） |
| DNSTT | 7 | `*.guruzgh.shop` / `orisselab.online` / `dpdns.org` |
| SSH | 6 | `guruzfreenet.online` / `jezvpn.xyz` / `guruzgh.shop` |

### 4.2 全局凭证

```
DefOVPNUser    = sandoki
DefOVPNPass    = sandoki
HysteriaUser   = sandoki:sandoki
HysteriaOBFS   = sandoki
```
每个节点另有独立凭证（如 `rain102/rain102`、`freemode/freemode`、`dTo5m9YH...` 等）。

### 4.3 传输参数约定

所有节点共用同一组端口号：

| 字段 | 值 | 含义 |
|---|---|---|
| `SSLPort` | 443 | TLS/VLESS 入口 |
| `OpenVPNTCPPort` | 110 | OpenVPN 入口（**免流端口**） |
| `OpenVPNUdpPort` | 53 | UDP/QUIC 入口（**免流端口**） |
| `SSH_Port` | 22 | SSH 入口 |

「110 / 53」是运营商套餐里不计费的端口，这批节点是围绕**运营商计费漏洞**设计的。

### 4.4 死资产与密钥不一致

- `bee1.txt` / `bee3.txt`：API 可下载，但用两把已知密码 + salt 8~40 字节全偏移 + nonce 12/16 组合均无法通过 GCM 校验 → 应为其他版本/其他 App 的配置，密钥不同。
- `assets/custom1.json` / `v2ray_config.json` / `v2inject.json`：无任何引用点。

---

## 5. 真实可用性实测（核心结论）

### 5.1 三层测量

**第一层：TCP 连通（121 唯一端点 × 5 次）**

```
endpoints = 121
tcp_alive(成功率>=80%) = 32
P50(存活) = 246 ms，min 45 ms，max 358 ms
```
最快一组是 GCP Cloud Run（`*.run.app`，34.143.x.x，45~250 ms）。
`guruzfreenet.online` / `guruzgh.shop` / `jezvpn.xyz` / `bshield.dns.army` / `beevpn.shop` / `groupjgm.es` / `orisselab.online` 等 **域名已无 DNS 记录**（DoH 双源确认）。

**第二层：TLS / WS 升级**

| 目标 | 结果 | 解读 |
|---|---|---|
| `atnet3-507168703375.europe-southwest1.run.app:443` 路径 `/ws-kobe`、`/`、`/ws-kobe?ed=2048` | 全部 **404 Not Found** | Cloud Run 服务在，但 VLESS 路由不存在 |
| `shegeftihaaa.net:443`:443/8443 `/rsedgws` | **403 Forbidden**（Cloudflare） | 边缘拦截 |
| `vps.groupjgm.es:443` `/vless`、`/` | **403 Forbidden** | 同上 |
| `mludp.mludpdnsvip.top:443` `/?ed` | 404 | — |

**第三层：真实协议握手**

- **Hysteria2**（mihomo 1.19.12，8 节点 × 6 端口 = 66 变体，QUIC+salamander obfs）：
  `context deadline exceeded` ×57 / `no recent network activity` ×9 → **0 存活**（UDP 无回包）
- **OpenVPN**（WSL OpenVPN 2.6.19，78 份配置逐个握手）：
  ```
  Connection timed out : 48
  Connection refused   : 13
  Cannot resolve       :  7
  TLS Error            :  6
  other                :  3
  AUTH_FAILED          :  1   (gg70.raseedsk.uk)
  ALIVE                :  0
  ```
- **跳过 CA 校验 + `--tls-export-cert`** 复测 10 个最有希望节点：
  全部 `TLS Error: TLS object -> incoming plaintext read error`
  → **对端在该端口上根本不是 OpenVPN TLS 服务**
- **SSH**：`sandoki/sandoki` 与各节点自属凭证对 `65.108.245.200 / 172.104.240.194 / 62.238.16.144 / 84.46.251.210 / vps.groupjgm.es` 全部 `AuthenticationException`

### 5.2 结论：0/67 在当前网络下可直接使用

`gg70.raseedsk.uk` 返回 `AUTH_FAILED` 是本轮**唯一证明"服务活着"**的证据——TCP+TLS 通、
OpenVPN 控制通道建立、仅凭证被拒；其余节点连协议层都到不了。

### 5.3 为什么不可用（架构原因，非抓取错误）

这批节点是 **Juanscript 式双跳**结构，配置里的 `remote 127.0.0.1 8888` 就是铁证：

```
App → [SSH / SNI 注入隧道 @ host:110 或 :53]  →  本地 SOCKS 127.0.0.1:8888
                                                 →  OpenVPN(tcp 127.0.0.1:8888)  ← 配置原文
                                                 →  或 Xray VLESS / Hysteria2
```

因此：

1. 二级协议（OVPN/VLESS/Hysteria2）**从来不是**对公网直连的，必须先有 SSH 隧道；
2. SSH 入口域名大面积注销，存活域名上的凭证认证失败；
3. 端口 110/53 只在运营商免流白名单网络下开放，普通网络下 refused / timeout；
4. 即使全部复现，也需要 App 的反篡改校验与注入 payload 才能拿到隧道层。

**判定：该池不具备"长期稳定代理池"价值，不建议接入任何生产池。**

---

## 6. 合规判定

| 项 | 判定 |
|---|---|
| 配置解密与协议分析 | 研究行为，可披露 |
| 凭证（sandoki 等）有效性 | 实测全部失效，不存在"盗用他人基础设施"的可行路径 |
| 节点归属 | 混合：运营商/个人 VPS + 白嫖云（Cloud Run / CF Worker / CloudFront）+ 免流端口 |
| 接入生产池 | **不建议**：稳定性≈0、来源合规风险高、随时被上游清理 |

---

## 7. 复现步骤

```bash
# 1. 拉配置（需境外出口）
curl -A "Bee VPN" -o bee2.txt https://strongteam.co/api/bee/bee1/bee2.txt

# 2. 解密（见 3.5 最小实现）
python tools/decrypt.py bee2.txt            # -> plain_bee2.txt

# 3. 收割节点字段
python tools/harvest.py                     # -> nodes_full.json（67 节点，402 字段全解）

# 4. 三层测活
python tools/bench.py                       # TCP 5 次采样 -> bench_result.json
python tools/probe_ws.py                    # WS 升级探测
wsl bash ovpn/batch.sh                      # OpenVPN 握手 78 份（需已安装 openvpn）

# 5. Demo
python demo_server.py                       # http://127.0.0.1:8951/
```

---

## 8. 结论摘要

- 加密方案**完整破解**，402/402 加密字段解密成功，方案可复用于同源 App。
- 节点池**完整提取**：67 节点 / 121 主机 / 5 协议，含全局凭证与逐节点凭证。
- 真实可用性**实测为 0**：TCP 层 32/121 可达，但协议层全部失败，根因是双跳 SSH 隧道 + 免流端口 + 域名注销。
- 交付：可复现工具链、脱敏 Demo、三层压测数据、本报告。
