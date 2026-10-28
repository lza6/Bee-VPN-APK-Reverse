# PROTOCOL.md — Bee VPN 配置下发协议实现手册

给二次开发者/对接方看的实现手册。照着这份可以独立复现整套链路。

---

## 1. 常量表

| 名称 | 值 | 来源 |
|---|---|---|
| 配置服务器 | `https://strongteam.co/api/bee/bee1/bee2.txt` | `AndroidLibXrayLite.CU` 硬编码 |
| 请求方法 / UA | `GET` / `Bee VPN` | 同上（43 字节 URL + 7 字节 UA，`0x3c70ca` / `0x38b377`） |
| 备用文件 | `bee1.txt`(1.29 MB) / `bee3.txt`(1.13 MB) | 同目录，密钥不同（见 §6） |
| 密码 A（字段级） | `BinkeVPNTeam`（12 B） | `.rodata 0x391a99`，`DO()` 使用 |
| 密码 B（整包） | `1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+`（32 B） | `.rodata 0x3b3739`，`decrypt()` 使用 |
| 全局 SSH/OVPN 用户 | `sandoki` | JSON `DefOVPNUser` |
| 全局 Hysteria 认证 | `sandoki:sandoki` | JSON `HysteriaUser` |
| 本地代理端口 | `127.0.0.1:8888` | OVPN 配置 `remote` 字段 |

> 直连 `strongteam.co` 会被 RST；需境外出口。域名解析到 Cloudflare（`172.67.160.19` / `104.21.14.168`）。

---

## 2. 加密信封

### 2.1 结构

```
payload = base64_std( SALT(16) || NONCE(12) || CIPHERTEXT+TAG )
```

| 偏移 | 长度 | 内容 |
|---|---|---|
| `[0:16]` | 16 | Salt（同时充当 GCM 的 additionalData） |
| `[16:28]` | 12 | Nonce / IV |
| `[28:]` | N | AES-GCM 密文 + 16 B tag |

### 2.2 密钥派生

```
key = Argon2id(password, salt, time_cost=3, memory_cost=8192 KiB, parallelism=1, key_len=32)
```

### 2.3 解密（含唯一卡点）

```python
key = argon2.IDKey(pw, salt, 3, 8192, 1, 32)      # argon2id
pt  = AESGCM(key).decrypt(nonce, ct, salt)         # ★ AAD = salt
```

**`AAD=salt` 是硬性要求。** 传 `None` 会得到 `InvalidTag`，
且很容易误判成"密码错 / 参数错"，从而白跑几千次参数暴力。

反汇编佐证（`AndroidLibXrayLite.Encrypt`）：`gcm.Seal(dst, nonce, plaintext, additionalData)` 的第 4 个 slice 参数
落在 `x10/x11/x12`，其值正是 salt 指针 / 长度 16 / 容量 16。

### 2.4 最小实现（可直接抄）

```python
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PW = b"BinkeVPNTeam"

def bee_decrypt(s: str) -> str:
    b = base64.b64decode(s + "=" * (-len(s) % 4))
    salt, nonce, ct = b[:16], b[16:28], b[28:]
    key = hash_secret_raw(PW, salt, 3, 8192, 1, 32, Type.ID)
    return AESGCM(key).decrypt(nonce, ct, salt).decode()
```

单次调用约 20 ms（Argon2 8 MiB × 3 轮），67 节点 × 6 字段 ≈ 400 次 ≈ 8 s。

---

## 3. 顶层 JSON 结构

```jsonc
{
  "Version": "6.99",
  "ReleaseNotes": "...",                  // 运营商免流文案（MA/ET/IR）
  "Telegram": "https://t.me/beevpn1",
  "Facebook": "https://www.facebook.com/bee.vpn.2024",
  "DefOVPNUser": "<enc>",                 // -> sandoki
  "DefOVPNPass": "<enc>",                 // -> sandoki
  "HysteriaUser": "<enc>",                // -> sandoki:sandoki
  "HysteriaOBFS": "<enc>",                // -> sandoki
  "DefaultOVPNCert": "<明文模板>",         // 见 §4.3
  "isTimerOn": true,
  "timetoadd": 3,
  "Servers": [ /* 节点数组，见 §4 */ ],
  "Networks": [ /* 运营商图标资源 */ ]
}
```

---

## 4. 节点对象

### 4.1 字段表

| 字段 | 加密 | 说明 |
|---|---|---|
| `Name` / `Flag` / `ServerType` / `ServerProtocol` | 否 | 显示名 / 国旗 / 承载类型 / 协议 |
| `ServerIPHost` | ✅ | host，多值以 `;` 分隔（备用列表） |
| `OpenVPNTCPPort` | 否 | 固定 `110` |
| `OpenVPNUdpPort` | 否 | 固定 `53` |
| `SSH_Port` | 否 | 固定 `22` |
| `SSLPort` | 否 | 固定 `443` |
| `OVPNUser` / `OVPNPass` | ✅ | 逐节点凭证（`rain102/rain102`、`freemode/freemode`…） |
| `UDP_user` | ✅ | Hysteria2 认证，形如 `user:pass` |
| `UDP_obfs` | ✅ | Hysteria2 obfs 密码（`kobe` / `boy` / `tfn` / `serverudp`） |
| `V2rayProtocol` | 否 | `VLESS` |
| `V2rayUUID` | ✅ | VLESS UUID（可非标准格式，如 `9282027871777-9282027871777`） |
| `V2rayPath` | 否 | WS 路径（`/ws-kobe`、`/binke`、`/vless`、`/xhttp`、`/?ed`） |
| `H2pass` | ✅ | Hysteria2 备用密码 |
| `SlowDNSHost` / `SlowDNSKey` | ✅ | DNSTT 参数 |
| `CustomCertificate` | ✅ | 完整 `.ovpn` 文本（内联 `<ca>`） |
| `Default_cert` | 否 | 是否使用全局默认证书 |
| `isdefUser` | 否 | 是否使用全局凭证 |

### 4.2 协议分布（v6.99）

| ServerProtocol | 数量 | ServerType |
|---|---|---|
| `V2ray` | 29 | GCP(11) / CF Worker(10) / Alibaba(4) / Xhttp(2) / WS Server(2) |
| `OVPN` | 17 | WS Server(10) / Cloudfront(5) / Alibaba(2) |
| `UDP Hysteria` | 8 | WS Server(8) |
| `DNSTT` | 7 | WS Server(7) |
| `SSH` | 6 | WS Server(6) |

### 4.3 `DefaultOVPNCert` 模板（明文）

```conf
client
dev tun
proto tcp
port 1194
remote X.X.X.X          # 替换为 ServerIPHost
cipher none
auth none
auth-user-pass
ping-timer-rem
redirect-gateway def1
setenv CLIENT_CERT 0
verb 3
<ca>
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
</ca>
```

### 4.4 节点自带 `CustomCertificate` 的形态（关键）

```
client
dev tun
proto tcp
remote 127.0.0.1 8888     ← ★ 指向本地 SOCKS，不是公网服务器
remote-cert-tls server
...
<ca>...</ca>
```

部分节点写的是真实地址（如 `remote 138.68.135.182 1194`），部分写 `0.0.0.0`（占位）。

**`remote 127.0.0.1 8888` 是判定 Juanscript 双跳架构的决定性证据**，详见 §5。

---

## 5. 真实连接架构（决定"能不能用"）

```
App ──► SSH / SNI 注入隧道 ──► 本地 SOCKS 127.0.0.1:8888 ──► 二级协议
        (host:110 或 host:53)                                (OpenVPN / VLESS / Hysteria2)
```

推论（均经实测）：

1. 二级协议**不向公网提供直连**，直接连 `host:443 / :110 / :53` 会得到
   404（Cloud Run）、403（Cloudflare）、`TLS object -> incoming plaintext read error`（非 OVPN TLS）或 UDP 无回包。
2. `110` / `53` 是运营商免流白名单端口，普通网络下 refused / timeout。
3. 隧道层需要 App 内置的注入 payload 与反篡改校验（`isSecured` / `EO`），静态无法复现。

实测数据见 `docs/REVERSE_REPORT.md` §5，结论 **0/67 可用**。

---

## 6. 已知未解项

| 项 | 状态 | 已排除的可能 |
|---|---|---|
| `bee1.txt` / `bee3.txt` | 未能解密 | 两把密码 × salt 8~40 B（4 步长）× nonce 12/16 × AAD∈{salt,nil} × 头部 0~8 字节 trim，全负 |
| `assets/custom1.json` / `v2ray_config.json` / `v2inject.json` | 死资产 | 全项目 `getAssets()` 无引用点 |
| SSH 隧道层 payload | 未还原 | 各家域名已注销，无法再抓 |

---

## 7. 必避坑清单

1. **不传 AAD** → `InvalidTag`，会被误判为密码错。
2. **用一把密码试到底** → Bee 有 12 B / 32 B 两把，字段级必须是 12 B 那把。
3. **把 `remote 127.0.0.1 8888` 当成服务器地址** → 会连本地。
4. **以为字段是明文** → `ServerIPHost` 也是加密的，直接读会得到一长串 base64。
5. **base64 补齐** → 用 `s + "=" * (-len(s) % 4)`，不要无脑 `+= "=="`（会产生多余字节）。
6. **`;` 分隔的备用 host** → 只取第一条会漏掉存活节点，需全量展开。
7. **`V2rayUUID` 非标准 UUID** → `9282027871777-9282027871777` 合法（VLESS 允许任意字符串），不要用 UUID 正则校验。
8. **`ServerType` 与 `Flag` 不可信** → `Flag=ma` 但出口在欧洲是常态（Cloud Run 承载）。
