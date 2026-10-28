# NEWAPI_INTEGRATION.md — new-api 代理池对接指南

> 面向执行对接的会话。本文档自包含，不需要回看其他上下文。

---

## 0. 一句话结论（先读这段，能省你半天）

**Bee VPN 这批节点当前 0/67 可用，不要直接接入生产池。**

原因不是抓取失败，而是架构性的：这批节点是 **Juanscript 双跳结构**（SSH/SNI 注入隧道 → 本地 SOCKS → 二级协议），
配置里的 `remote 127.0.0.1 8888` 就是证据。二级协议从不对公网开放，
且大量入口域名已注销、`110/53` 是运营商免流端口。

所以本文档分两部分：

- **第一部分（§1–§4）**：new-api 侧的真实接入机制 —— 这部分与 Bee 无关，是通用做法，**对接会话必须掌握**。
- **第二部分（§5–§8）**：Bee 具体落地的前置条件、路径选择与验证标准 —— 用于判断"什么时候才轮到动手"。

---

## 1. new-api 侧接入机制（源码级，已核实）

### 1.1 唯一的住宅清单入口

`relay/channel/tryingopen/proxy_pool.go` → `LoadProxies()`：

```go
// 支持逗号分隔的多个文件：住宅清单 + 本地协议转换层天然是两份来源
if files := strings.TrimSpace(os.Getenv("TRYINGOPEN_PROXY_FILE")); files != "" {
    for _, file := range strings.Split(files, ",") {
        ...
        addSource(lines, "residential", filepath.Base(file), 1.0)
    }
}
```

| 项 | 规则 |
|---|---|
| 环境变量 | `TRYINGOPEN_PROXY_FILE`，**逗号分隔多文件** |
| 每行格式 | `socks5://host:port` 或 `http://user:pass@host:port` |
| 注释 | `#` 开头整行跳过；空行跳过 |
| 去重 | 按整行字符串去重（`seen[raw]`） |
| 入池属性 | `source="residential"`、`healthScore=1.0`（池内最高权重档） |
| 分池观测 | `origin` = **文件名**（`filepath.Base`），每个文件在面板上是独立卡片 |
| 兜底 | `TRYINGOPEN_PROXIES`（逗号分隔的内联清单） |

**所以转换层输出到文件即可，new-api 一行业务代码都不用改。**

### 1.2 相关管理接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/twoapi_panel/proxy_pool` | 代理池观测（管理员），含 total/available/cooling/residential/free |
| POST | `/api/twoapi_panel/proxy_pool/reload` | 手动重载住宅源 + 触发一轮免费源抓取 |
| POST | `/api/twoapi_panel/proxy_pool/config` | 设置免费源抓取周期（写 option 表，热更新） |

源码：`controller/twoapi_panel.go:218/293/320`，路由 `router/api-router.go:412`。

### 1.3 调度与风控参数（决定你的池子要多大）

| 机制 | 默认值 | 配置项 |
|---|---|---|
| 429 冷却 | 阶梯 `0,30,90,300,900` 秒（按 24h 窗口内使用次数递增） | `TRYINGOPEN_USE_COOLDOWN_MAP` |
| 其它失败冷却 | 固定 30 s | — |
| 全局熔断 | 同一代理连续失败 **5** 次 → 全池熔断 **10 分钟** | 常量 `globalFailThreshold` / `globalFailCooldown` |
| 健康分 | 成功 `0.7*old+0.3*1.0`；失败 `0.7*old+0.3*0.0` | — |
| 每日限额 | 默认不限 | `TRYINGOPEN_PROXY_MAX_USE_PER_DAY` |
| 分配策略 | ①成功节点缓存优先 ②权重自适应加权随机 ③新 IP/冷却到期兜底 | — |

### 1.4 ★ 最容易被忽略的一条：住宅源不做真实出口拨测

```go
// proxy_pool.go:1179  TraceProbes()
for _, e := range proxyPool {
    if e.source != "free" {      // ← 住宅清单直接跳过
        continue
    }
```

**含义**：通过 `TRYINGOPEN_PROXY_FILE` 注入的条目，new-api 不会验证它是否真能出网。
一个完全连不通的 `socks5://1.2.3.4:1080` 也会安静躺在池子里，被调度到才失败。

**因此：出口 IP 正确性必须由转换层自己校验（`check_exit_ip()`），不能指望 new-api 兜底。**

### 1.5 容器内 `127.0.0.1` 的坑

如果 new-api 跑在 Docker 里，清单里的 `127.0.0.1:PORT` 指的是**容器自己的 loopback**，不是宿主机。
三选一：

1. `extra_hosts: - "host.docker.internal:host-gateway"`，清单写 `host.docker.internal:PORT`，转换层监听 `0.0.0.0`；
2. new-api 用 `network_mode: host`；
3. 转换层进同一个 compose 网络，清单写服务名。

---

## 2. 对接标准链路（VPN → SOCKS5 → new-api）

```
节点凭证 ──► 隧道进程（OpenVPN / WireGuard / Xray / Hysteria2）
         ──► 隧道内 SOCKS5（microsocks / 3proxy）
         ──► 宿主/容器可达端口
         ──► proxies.txt（每行 socks5://host:port）
         ──► TRYINGOPEN_PROXY_FILE
         ──► new-api 代理池
```

### 2.1 每节点一个 network namespace（Linux，唯一可靠做法）

同宿主多 tun 有两个死穴：tun IP 会漂移、多个 tun 常拿到同一个 `10.8.0.0/24` 互相打架。

```
宿主机 0.0.0.0:44000+i --TCP relay--> 10.200.{i}.2:34000+i
                                        └─ netns vpn{i}: veth 10.200.{i}.2/30
                                           + openvpn(tun0, 自带 redirect-gateway)
                                           + microsocks(bind 0.0.0.0)
```

**必做三细节**：

1. **netns 内 DNS**：`/etc/resolv.conf` 仍指向宿主 DNS，经隧道不可达 →
   `ip netns exec vpnN unshare -m --propagation private sh -c 'mount --bind <走隧道resolv.conf> /etc/resolv.conf && exec microsocks -i 0.0.0.0 -p 3400N'`
2. **fail-closed 顺序（反了会全灭）**：
   ```bash
   ip route replace <server_ip>/32 via <veth_gw>   # 先补服务器主机路由
   ip route del default via <veth_gw>              # 再删默认路由
   ```
   只删默认路由 → openvpn 自己发不出包；不删 → 隧道断后流量回落成宿主真实 IP（**泄漏**）。
3. **判活**：流式读 `Initialization Sequence Completed`；
   出口校验用 **IP 直连** `http://208.95.112.1/json/`（别用域名，会踩 DNS 污染）。

规模上限：单机 **20–50 条隧道**（每条 ≈ 1 tun + 1 veth + 1 microsocks + 1 openvpn 进程）。

### 2.2 输出清单

```bash
# /opt/proxy-layer/proxies.txt
# 由转换层每轮健康检查后重写
socks5://127.0.0.1:44000
socks5://127.0.0.1:44001
```

```bash
# new-api 环境变量（多文件用逗号）
TRYINGOPEN_PROXY_FILE=/opt/proxy-layer/proxies.txt,/opt/proxy-layer/proxies-backup.txt
```

### 2.3 三层验证（缺一层都不算打通）

| 层 | 命令 | 通过标准 |
|---|---|---|
| 隧道层 | `ip netns exec vpn0 curl -s http://208.95.112.1/json/` | 出口 IP ≠ 宿主 IP，且落在目标国家 |
| 池层 | `GET /api/twoapi_panel/proxy_pool` | 能看到条目，`origin` 是你给的文件名 |
| **业务层** | 发一次真实 relay 请求，核对上游侧看到的来源 IP | 上游日志里的来源 IP = 隧道出口 IP |

**只看池快照有条目 ≠ 流量真走了它。**

---

## 3. 转换层参考实现

`tools/socks_layer.py`（本仓库）：读 `ovpn/` 目录 → 逐节点起 netns + openvpn + microsocks →
写 `proxies.txt` → 自带出口 IP 校验与失败摘除。部署在 Linux 服务器执行，Windows 仅用于生成配置。

---

## 4. Bee 专属对接参数（若将来真的可用）

| 项 | 值 |
|---|---|
| 节点清单 | `data/nodes_full.json`（含明文凭证，**未入库**，需自行用 `tools/harvest.py` 生成） |
| 全局凭证 | `sandoki/sandoki`；Hysteria `sandoki:sandoki`，obfs 密码 `sandoki` |
| OVPN 配置 | `CustomCertificate` 字段内联完整 `.ovpn`；无该字段的用 `DefaultOVPNCert` 模板 |
| OVPN 端口 | `OpenVPNTCPPort=110` / `OpenVPNUdpPort=53`（免流端口，公网多不可达） |
| VLESS | `443` + WS + TLS，`path`=`V2rayPath`，`Host`/`SNI`=`ServerIPHost`，`uuid`=`V2rayUUID` |
| Hysteria2 | `443/udp`，`password`=`UDP_user`，`obfs=salamander` + `obfs-password=UDP_obfs` |
| 出口国家 | 以 `ServerType` 承载地为准（Cloud Run 多在 `europe-west1`，`Flag` 不可信） |

---

## 5. 接入前置条件（Bee 目前**全部不满足**）

打勾才允许动手，任一为空就不要开工：

- [ ] 隧道层可复现：能对至少 1 个节点建立 SSH/SNI 隧道，或二级协议可直连（当前：0/67）
- [ ] 凭证有效：`sandoki/sandoki` 或节点自属凭证能通过认证（当前：全 `AuthenticationException`）
- [ ] 端口可达：`110/53` 或 `443` 在部署网络下不被拒（当前：48 timeout / 13 refused）
- [ ] 出口校验：能拿到真实出口 IP 且国家符合预期（当前：协议层都到不了）
- [ ] 合规确认：节点归属与使用授权清晰（当前：来源混合，含免流端口，政策风险高）

---

## 6. 三条路径（按性价比排序）

### 路径 B（推荐）：横向扫同框架仍在运营的 App

Bee 用的 `v2rayNG + SocksHttp/UltraSSH` 缝合怪在免流圈是模板化产物。
**加密方案已完整破解，换同框架 App 只需换 API 域名与密码常量**，成本远低于在死池子上继续挖。

识别特征：
- `assets/` 有 `custom1.json` / `v2inject.json` 模板
- dex 同时含 `com.v2ray.ang.*` 与 `com.vpn.sandok.ultrasshservice` / `com.sandok.tunnel`
- 配置走 `https://<品牌域>/api/<x>/beeN.txt` 形态

### 路径 A（成本高）：复现 SSH 隧道层

需要动态分析（Frida hook `libgojni.so` 的隧道初始化 + 抓注入 payload），
且入口域名已注销，**多数情况下无节点可连，不建议投入**。

### 路径 C：直接弃用

当前事实支持这条：稳定性≈0，不值得占用生产池。

---

## 7. 交接清单（给对接会话的最短指令）

若将来前置条件满足，把下面这段直接发给对接会话：

```
任务：把 <转换层输出目录>/proxies.txt 接入 new-api 代理池。
1. new-api 侧禁止改业务代码，只配环境变量：
   TRYINGOPEN_PROXY_FILE=/path/proxies.txt[,/path/proxies2.txt]
2. 转换层必须保证：清单里每一行都经过真实出口 IP 校验（new-api 的 TraceProbes 只验 source=="free"，住宅源不验）。
3. 容器内 127.0.0.1 需改 host.docker.internal 或 network_mode: host（见 docs/NEWAPI_INTEGRATION.md §1.5）。
4. 验收三层：隧道层出口 IP / /api/twoapi_panel/proxy_pool 有条目 / 真实 relay 请求核对上游来源 IP。
5. 池子规模 20–50 条隧道；429 冷却 0/30/90/300/900s；连续 5 次失败会全池熔断 10 分钟，排障先看这个。
```

---

## 8. 验收记录模板

| 项 | 值 |
|---|---|
| 隧道数量 | N 条（成功 M 条） |
| 唯一出口 IP | N 个（出口国家分布：…） |
| 延迟 P50 / P95 | … |
| 吞吐 P50 | … Mbps |
| 并发 8 路成功率 | … |
| `/api/twoapi_panel/proxy_pool` | total / available / cooling |
| 业务层核对 | 上游看到的来源 IP = … |
| 未通过项与原因 | … |
