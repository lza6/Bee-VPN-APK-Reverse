#!/usr/bin/env python3
"""fetch_configs.py — 一键拉取并体检 Bee VPN 三份配置

用法:
  python tools/fetch_configs.py                 # 用系统代理 127.0.0.1:10808
  python tools/fetch_configs.py --no-proxy      # 直连（大概率被 RST）
  python tools/fetch_configs.py --outdir data/raw

输出每份文件的: 大小 / len%4 / 是否合法 base64 / 解码长度 / 能否用已知密码解开
"""
import argparse, base64, hashlib, os, sys, urllib.request, ssl

BASE = "https://strongteam.co/api/bee/bee1/"
FILES = ["bee1.txt", "bee2.txt", "bee3.txt"]
UA = "Bee VPN"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from decrypt import b64d, decrypt_bytes, PW, PW2
    HAVE_DEC = True
except Exception:
    HAVE_DEC = False


def fetch(name, use_proxy=True, outdir="."):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if use_proxy:
        handlers.append(urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:10808",
            "https": "http://127.0.0.1:10808",
        }))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    op = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(BASE + name, headers={"User-Agent": UA})
    return op.open(req, timeout=90).read()


def inspect(name, raw):
    n = len(raw)
    mod = n % 4
    ok_b64 = mod == 0
    body = raw.rstrip()
    decoded = None
    if len(body) % 4 != 1:
        try:
            decoded = base64.b64decode(body + b"=" * (-len(body) % 4))
        except Exception:
            decoded = None
    status = "-"
    if HAVE_DEC and decoded:
        for tag, pw in (("pw12", PW), ("pw32", PW2)):
            try:
                pt = decrypt_bytes(decoded, pw)
                status = f"DECRYPTED {tag} -> {len(pt)} B"
                break
            except Exception:
                continue
        else:
            status = "LOCKED (密码不匹配)"
    print(f"  {name:10s} size={n:>9d} len%4={mod} legal_b64={'yes' if ok_b64 else 'NO'} "
          f"decoded={len(decoded) if decoded else '-':>9} sha1={hashlib.sha1(raw).hexdigest()[:10]} -> {status}")
    return decoded, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--outdir", default=".")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    print(f"[*] 拉取 {BASE}  (proxy={'off' if a.no_proxy else '127.0.0.1:10808'})")
    results = {}
    for name in FILES:
        try:
            raw = fetch(name, use_proxy=not a.no_proxy)
        except Exception as e:
            print(f"  {name:10s} FETCH FAIL: {type(e).__name__} {str(e)[:60]}")
            continue
        open(os.path.join(a.outdir, name), "wb").write(raw)
        results[name] = inspect(name, raw)
    print("\n[提示] bee2 可解 = 方案正确；bee1/bee3 LOCKED 属预期，见 docs/UNSOLVED-BEE1-BEE3.md")


if __name__ == "__main__":
    main()
