# Bee VPN（co.strongteam.beevpn）逆向 · 节点池还原

对 `Bee VPN_Build_64.apk`（47 MB，arm64-v8a）的配置下发链路、加密方案与节点池做完整逆向，
并给出**真实可用性实测结论**。

> 本项目为协议与数据格式研究。不含绕过上游风控、不驱动任何生产接入。

## 状态表

| 模块 | 状态 | 证据 |
|---|---|---|
| App 架构识别 | ✅ | v2rayNG + SocksHttp/UltraSSH + ics-openvpn + Xray/Hysteria2 native |
| 配置服务器定位 | ✅ | `https://strongteam.co/api/bee/bee1/bee{1,2,3}.txt`（Native CU 硬编码） |
| 加密方案还原 | ✅ | base64 → salt(16)\|nonce(12)\|ct → Argon2id(3,8192,1,32) → AES-256-GCM **AAD=salt** |
| 密码提取 | ✅ | `BinkeVPNTeam`(12B, DO) / `1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+`(32B, decrypt) |
| 节点池提取 | ✅ | 67 节点 / 121 唯一主机 / 5 协议 / 402 加密字段 100% 解密 |
| TCP 层实测 | ✅ | 121 端点 ×5 次：32 存活（≥80%），P50 246 ms |
| 协议层实测 | ❌ **0 可用** | VLESS 404/403；Hysteria2 UDP 全超时；OpenVPN 0/78 握手；SSH 认证全失败 |
| Demo + 压测 | ✅ | `demo_server.py`（:8951）+ `demo.html` + `bench.py` |

## 关键结论

**这批节点不是"直连代理"，而是 Juanscript 式双跳结构** —— 配置原文即证据：

```
remote 127.0.0.1 8888      # OVPN 配置里指向本地 SOCKS，不是公网服务器
```

实际链路：

```
App → [SSH / SNI 注入隧道 @ host:110 或 :53]  →  本地 SOCKS 127.0.0.1:8888
                                              →  OpenVPN / Xray VLESS / Hysteria2
```

三重原因导致不可用：

1. 二级协议从来不对公网开放，必须先有 SSH 隧道层；
2. SSH 入口域名大面积注销（`guruzfreenet.online` / `guruzgh.shop` / `jezvpn.xyz` / `bshield.dns.army` 等 DoH 双源确认无记录），存活域名上凭证全部 `AuthenticationException`；
3. 端口 **110 / 53** 是运营商免流白名单端口，普通网络下 refused/timeout。

→ **不具备长期稳定代理池价值，不建议接入生产池。**

## 快速开始

```bash
pip install argon2-cffi cryptography pyyaml PySocks

# 1) 拉配置（需境外出口；直连 strongteam.co 会被 RST）
curl -A "Bee VPN" -o bee2.txt https://strongteam.co/api/bee/bee1/bee2.txt

# 2) 解密
python tools/decrypt.py bee2.txt            # -> bee2.plain (623,367 B)

# 3) 收割节点（逐字段解密）
python tools/harvest.py                     # -> data/nodes_full.json

# 4) 三层压测
python tools/bench.py                       # -> data/bench_result.json
python tools/probe_ws.py                    # WS 升级探测（VLESS 路由）
wsl bash ovpn/batch.sh                      # OpenVPN 握手（需 apt install openvpn）

# 5) Demo
python demo_server.py                       # http://127.0.0.1:8951/
```

## 目录

```
docs/PROTOCOL.md           ★ 实现手册：常量 / 信封 / 字段表 / 最小实现 / 必避坑
docs/NEWAPI_INTEGRATION.md ★ 对接指南：new-api 接入机制 + 前置条件 + 三条路径 + 交接指令
docs/REVERSE_REPORT.md     完整逆向报告（架构 / 加密 / 节点 / 实测 / 合规）

tools/decrypt.py           加密方案最小实现 + CLI
tools/harvest.py           节点字段全量解密 -> nodes_full.json
tools/bench.py             TCP/TLS 三层压测
tools/probe_ws.py          VLESS WS 路由探测
tools/socks_layer.py       隧道 -> SOCKS5 转换层（Linux netns 版，new-api 直连消费）

data/nodes_redacted.json   67 节点（凭证已脱敏，host 保留）
data/bench_result.json     121 端点 × 5 次 TCP 采样原始数据
data/ovpn_batch.log        78 份 OpenVPN 配置握手结果（0 ALIVE）
data/probe_fp.log          证书导出复测（TLS object read error 证据）

demo_server.py             本地 Demo 服务（:8951，凭证自动脱敏）
demo.html                  单页前端（节点表 + 一键测活）
```

> `data/nodes_full.json`（明文凭证）已被 `.gitignore` 排除。需要完整数据请自行
> `python tools/harvest.py` 从 `bee2.txt` 生成。

## 加密方案速查

```python
key = argon2.IDKey(b"BinkeVPNTeam", salt, 3, 8192, 1, 32)     # argon2id
pt  = AESGCM(key).decrypt(nonce, ct, salt)                     # ★ AAD = salt
# payload = base64(salt[0:16] || nonce[16:28] || ct[28:])
```

## 合规

- 节点来源混合：个人/运营商 VPS + 白嫖云（Cloud Run / CF Worker / CloudFront）+ 免流端口。
- 凭证经实测全部失效，不存在可用的他人基础设施盗用路径。
- 生产接入风险：稳定性≈0、上游随时清理、运营商政策风险。**不建议**。

## new-api 对接（30 秒版）

**new-api 侧零改代码**，只需环境变量：

```bash
TRYINGOPEN_PROXY_FILE=/opt/proxy-layer/proxies.txt        # 多文件用逗号分隔
```

清单每行 `socks5://host:port`，`#` 注释跳过；每个文件在面板上是独立卡片（`origin`=文件名）。

⚠️ 两个必须知道的点（详见 `docs/NEWAPI_INTEGRATION.md`）：

1. **住宅源不做真实出口拨测** —— `TraceProbes()` 里 `if e.source != "free" { continue }`，
   所以出口 IP 正确性必须由转换层自己校验；
2. 容器内 `127.0.0.1` 是容器自己的 loopback，需改 `host.docker.internal` 或 `network_mode: host`。

**但 Bee 当前 0/67 可用，不建议接入**。前置条件见对接文档 §5，替代路径见 §6（推荐横向扫同框架 App）。

## 证据索引

| 主张 | 证据文件 |
|---|---|
| 加密方案 | `docs/PROTOCOL.md` §2 + `tools/decrypt.py` 实跑 `[+] pw12 OK 623367 bytes` |
| 67 节点 / 402 字段 | `data/nodes_redacted.json`、`tools/harvest.py` |
| TCP 32/121 存活 P50 246ms | `data/bench_result.json` |
| OpenVPN 0/78 | `data/ovpn_batch.log` |
| 非 OVPN TLS | `data/probe_fp.log`（`TLS object -> incoming plaintext read error`） |

---

*分析日期 2026-10-29 · 仅供协议与格式研究，产物不含绕过上游风控的实现*
