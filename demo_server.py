#!/usr/bin/env python3
"""Bee VPN (co.strongteam.beevpn) 节点池本地 Demo 服务

数据来源: assets/configfile.json / 远端 https://strongteam.co/api/bee/bee1/bee2.txt
解密: base64 -> salt(16)|nonce(12)|ct, Argon2id(pwd, salt, t=3, m=8192, p=1, klen=32) -> AES-256-GCM(AAD=salt)

启动: python demo_server.py        (默认 127.0.0.1:8931)
"""
import json, os, socket, ssl, time, base64, statistics, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
# 完整数据（含明文凭证，gitignore）优先；新克隆的仓库只有脱敏版，自动回落
for _cand in (os.path.join(ROOT, "data", "nodes_full.json"),
              os.path.join(ROOT, "nodes_full.json"),
              os.path.join(ROOT, "data", "nodes_redacted.json")):
    if os.path.exists(_cand):
        DATA = _cand
        break
else:
    raise SystemExit("找不到节点数据：先跑 python tools/harvest.py 生成 data/nodes_full.json")
DATA_SOURCE = os.path.basename(DATA)
PORT = int(os.environ.get("PORT", 8951))

with open(DATA, encoding="utf8") as f:
    POOL = json.load(f)

def mask(v, keep=3):
    if not isinstance(v, str) or not v:
        return ""
    if len(v) <= keep * 2:
        return "*" * len(v)
    return v[:keep] + "*" * (len(v) - keep * 2) + v[-keep:]

def public_node(n, idx):
    hosts = [h.strip() for h in str(n.get("ServerIPHost", "")).split(";") if h.strip()]
    return {
        "id": idx,
        "name": n.get("Name", ""),
        "flag": n.get("Flag", ""),
        "type": n.get("ServerType", ""),
        "protocol": n.get("ServerProtocol", ""),
        "hosts": hosts,
        "ssl_port": n.get("SSLPort"),
        "tcp_port": n.get("TCP"),
        "udp_port": n.get("UDP"),
        "ssh_port": n.get("SSH_Port"),
        "has_ovpn_cert": bool(n.get("CustomCertificate")),
        "cred_preview": mask(str(n.get("OVPNUser") or n.get("UDP_user") or "")) if (n.get("OVPNUser") or n.get("UDP_user")) else "",
        "v2ray": {
            "proto": n.get("V2rayProtocol"),
            "uuid": mask(str(n.get("V2rayUUID") or ""), 4),
            "path": n.get("V2rayPath"),
        } if n.get("ServerProtocol") == "V2ray" else None,
        "hy2": {
            "auth": mask(str(n.get("UDP_user") or ""), 2),
            "obfs": n.get("UDP_obfs"),
        } if n.get("ServerProtocol") == "UDP Hysteria" else None,
    }

NODES = [public_node(n, i) for i, n in enumerate(POOL["servers"])]

def tcp_probe(host, port, timeout=6.0):
    t0 = time.time()
    try:
        ip = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return {"ok": False, "stage": "dns", "ms": None, "ip": None}
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        ms = round((time.time() - t0) * 1000)
        s.close()
    except Exception as e:
        return {"ok": False, "stage": "tcp", "ms": round((time.time() - t0) * 1000), "ip": ip, "err": type(e).__name__}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        r = socket.create_connection((ip, int(port)), timeout=timeout)
        ss = ctx.wrap_socket(r, server_hostname=host)
        ss.close()
        tls = "ok"
    except Exception as e:
        tls = type(e).__name__
    return {"ok": True, "stage": "tcp", "ms": ms, "ip": ip, "tls": tls}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path in ("/", "/index.html"):
            html = open(os.path.join(ROOT, "demo.html"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if p.path == "/api/stats":
            from collections import Counter
            self._json({
                "meta": POOL["meta"],
                "data_source": DATA_SOURCE,
                "total": len(NODES),
                "by_protocol": Counter(n["protocol"] for n in NODES),
                "by_type": Counter(n["type"] for n in NODES),
                "unique_hosts": len({h for n in NODES for h in n["hosts"]}),
            })
            return
        if p.path == "/api/nodes":
            q = parse_qs(p.query)
            proto = (q.get("protocol") or [None])[0]
            data = [n for n in NODES if not proto or n["protocol"] == proto]
            self._json({"count": len(data), "nodes": data})
            return
        if p.path == "/api/probe":
            q = parse_qs(p.query)
            host = (q.get("host") or [""])[0]
            port = (q.get("port") or ["443"])[0]
            if not host:
                self._json({"error": "host required"}, 400)
                return
            self._json({"host": host, "port": int(port), **tcp_probe(host, port)})
            return
        self._json({"error": "not found"}, 404)

def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[demo] Bee VPN node pool demo  ->  http://127.0.0.1:{PORT}/")
    print(f"[demo] data={DATA_SOURCE} nodes={len(NODES)}  protocols={sorted({n['protocol'] for n in NODES})}")
    srv.serve_forever()

if __name__ == "__main__":
    main()
