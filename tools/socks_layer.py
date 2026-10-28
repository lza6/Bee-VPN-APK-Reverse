#!/usr/bin/env python3
"""socks_layer.py — 节点隧道 → SOCKS5 端口清单（Linux 专用）

把一批 OpenVPN 配置变成 new-api 可直接消费的 socks5 清单：
  每节点一个 network namespace（避免 tun IP 漂移 / 路由打架）
    netns vpn{i}: veth + openvpn(tun0) + microsocks:34000+i
    宿主 0.0.0.0:44000+i  TCP relay -> 10.200.{i}.2:34000+i
  健康检查（真实出口 IP）通过的才写进 proxies.txt

用法:
  sudo python3 tools/socks_layer.py --ovpn-dir ovpn --out /opt/proxy-layer/proxies.txt
  sudo python3 tools/socks_layer.py --down            # 全部拆除

依赖: openvpn, microsocks, iproute2
环境: MIHOMO 强相关项目里本文件不涉及内核；只处理 OVPN
"""
from __future__ import annotations
import argparse, os, socket, subprocess, sys, time, json, threading, glob

BASE_IDX = int(os.environ.get("SL_BASE_IDX", "0"))
MAX_NODES = int(os.environ.get("SL_MAX_NODES", "50"))
PORT_RANGE = int(os.environ.get("SL_PORT_RANGE", "1000"))
EXIT_PROBE = "http://208.95.112.1/json/"   # IP 直连，别用域名（DNS 污染）
RESOLV = os.environ.get("SL_RESOLV", "/etc/resolv.conf")

def sh(cmd: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)

def ns_name(i: int) -> str: return f"vpn{BASE_IDX+i}"

def node_files(ovpn_dir: str) -> list[str]:
    files = sorted(glob.glob(os.path.join(ovpn_dir, "*.ovpn")))
    return [f for f in files if ".fp." not in f and not f.endswith(".nv.ovpn")][:MAX_NODES]

def parse_remote(path: str) -> tuple[str, str]:
    for line in open(path, encoding="utf8", errors="ignore"):
        p = line.split()
        if len(p) >= 3 and p[0] == "remote" and p[1] not in ("127.0.0.1", "0.0.0.0"):
            return p[1], p[2]
    return "", ""

def cred_file(path: str) -> str:
    return os.path.splitext(path)[0] + ".cred"

def setup_node(i: int, ovpn: str, ext_ip: str) -> bool:
    """建立 netns + veth + openvpn + microsocks，宿主端口转发。"""
    ns = ns_name(i)
    host, _port = parse_remote(ovpn)
    if not host:
        return False
    try:
        ext_ip = socket.gethostbyname(host)
    except Exception:
        return False
    sockport = 34000 + i
    hostport = 44000 + i
    gw = f"10.200.{i}.1"
    nsip = f"10.200.{i}.2"
    sh(f"ip netns del {ns} 2>/dev/null")
    sh(f"ip netns add {ns}")
    sh(f"ip link add veth{i} type veth peer name veth{i}b")
    sh(f"ip link set veth{i}b netns {ns}")
    sh(f"ip addr add {gw}/30 dev veth{i}"); sh(f"ip link set veth{i} up")
    sh(f"ip netns exec {ns} ip addr add {nsip}/30 dev veth{i}b")
    sh(f"ip netns exec {ns} ip link set veth{i}b up")
    sh(f"ip netns exec {ns} ip link set lo up")
    sh(f"ip netns exec {ns} ip route add default via {gw}")
    # 宿主侧 NAT（仅覆盖该 ns 出向）
    sh(f"iptables -t nat -C POSTROUTING -s {nsip}/32 -j MASQUERADE 2>/dev/null || "
       f"iptables -t nat -A POSTROUTING -s {nsip}/32 -j MASQUERADE")
    sh("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    cred = cred_file(ovpn)
    auth = f"--auth-user-pass {cred}" if os.path.exists(cred) else ""
    sh(f"ip netns exec {ns} nohup openvpn --config {ovpn} {auth} --daemon bee{i} "
       f"--log /tmp/openvpn-{ns}.log --connect-retry-max 3", check=False)
    # 等隧道建立
    ok = False
    for _ in range(30):
        time.sleep(1)
        if "Initialization Sequence Completed" in sh(f"tail -20 /tmp/openvpn-{ns}.log").stdout:
            ok = True
            break
    if not ok:
        sh(f"ip netns del {ns} 2>/dev/null")
        return False
    # fail-closed：先补 VPN 服务器主机路由，再删默认路由（顺序反了隧道自灭）
    sh(f"ip netns exec {ns} ip route replace {ext_ip}/32 via {gw}")
    sh(f"ip netns exec {ns} ip route del default via {gw} 2>/dev/null")
    # microsocks（resolv.conf 走隧道内 DNS）
    sh(f"ip netns exec {ns} unshare -m --propagation private sh -c "
       f"'mount --bind {RESOLV} /etc/resolv.conf && exec microsocks -i 0.0.0.0 -p {sockport}' >/dev/null 2>&1 &")
    time.sleep(1)
    # 宿主 TCP relay
    relay = (f"nohup socat TCP-LISTEN:{hostport},fork,reuseaddr "
             f"TCP:10.200.{i}.2:{sockport} >/dev/null 2>&1 &")
    sh(relay)
    time.sleep(1)
    return True

def check_exit(hostport: int, timeout: int = 12) -> str | None:
    """真实出口 IP 校验（IP 直连，避免 DNS 污染）"""
    try:
        s = socket.create_connection(("127.0.0.1", hostport), timeout=timeout)
        s.sendall(f"CONNECT 208.95.112.1:80 HTTP/1.1\r\nHost: 208.95.112.1\r\n\r\n".encode())
        if b"200" not in s.recv(200):
            s.close(); return None
        s.sendall(b"GET /json/ HTTP/1.1\r\nHost: 208.95.112.1\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 4000:
            c = s.recv(2048)
            if not c: break
            buf += c
        s.close()
        body = buf.split(b"\r\n\r\n", 1)[-1]
        return json.loads(body.decode("utf8", "ignore")).get("query")
    except Exception:
        return None

def down():
    for i in range(MAX_NODES):
        sh(f"pkill -f 'socat TCP-LISTEN:{44000+i}' 2>/dev/null")
        sh(f"ip netns del {ns_name(i)} 2>/dev/null")
    print("[down] 已拆除全部 netns 与 relay")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ovpn-dir", default="ovpn")
    ap.add_argument("--out", default="proxies.txt")
    ap.add_argument("--down", action="store_true")
    a = ap.parse_args()
    if a.down:
        down(); return
    files = node_files(a.ovpn_dir)
    if not files:
        print(f"[!] {a.ovpn_dir} 下没有 .ovpn"); return
    print(f"[*] 节点 {len(files)} 个，开始建立隧道（上限 {MAX_NODES}）")
    alive = []
    for i, f in enumerate(files):
        if setup_node(i, f, ""):
            ip = check_exit(44000 + i)
            if ip:
                alive.append((44000 + i, ip))
                print(f"[+] {os.path.basename(f):42s} port={44000+i} exit={ip}")
            else:
                print(f"[x] {os.path.basename(f):42s} 隧道起但出口校验失败")
    with open(a.out, "w") as fh:
        fh.write(f"# generated by socks_layer.py  {time.strftime('%F %T')}\n")
        for port, ip in alive:
            fh.write(f"socks5://127.0.0.1:{port}   # exit={ip}\n")
    print(f"[=] 存活 {len(alive)} / {len(files)} -> {a.out}")
    print("[!] 提示：容器内 new-api 需改用 host.docker.internal 或 network_mode: host")

if __name__ == "__main__":
    main()
