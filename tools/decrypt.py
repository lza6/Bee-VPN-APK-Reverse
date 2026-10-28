#!/usr/bin/env python3
"""Bee VPN 配置解密器（最小实现 + CLI）

用法:
  python tools/decrypt.py <base64文件>          # 整体解密 -> <file>.plain
  python tools/decrypt.py --field "<base64串>"   # 解单个字段

方案: base64_std(salt(16)|nonce(12)|ct) -> Argon2id(pwd,salt,t=3,m=8192,p=1,len=32) -> AES-256-GCM, AAD=salt
"""
import base64, sys, os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PW = b"BinkeVPNTeam"          # AndroidLibXrayLite.DO     @ .rodata 0x391a99 (len 12)
PW2 = b"1v0Ri+hhvQrh/tQ0fZmKDQaATClldrT+"  # AndroidLibXrayLite.decrypt @ .rodata 0x3b3739 (len 32)

def b64d(s: bytes) -> bytes:
    s = s.strip()
    return base64.b64decode(s + b"=" * (-len(s) % 4))

def decrypt_bytes(b: bytes, pw: bytes = PW) -> bytes:
    salt, nonce, ct = b[:16], b[16:28], b[28:]
    key = hash_secret_raw(pw, salt, 3, 8192, 1, 32, Type.ID)
    return AESGCM(key).decrypt(nonce, ct, salt)   # AAD = salt

def decrypt_field(s: str, pw: bytes = PW) -> str:
    return decrypt_bytes(b64d(s.encode()), pw).decode()

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    if sys.argv[1] == "--field":
        print(decrypt_field(sys.argv[2])); return
    src = sys.argv[1]
    raw = open(src, "rb").read()
    for pw_name, pw in (("pw12", PW), ("pw32", PW2)):
        try:
            pt = decrypt_bytes(b64d(raw), pw)
        except Exception:
            continue
        out = os.path.splitext(src)[0] + ".plain"
        open(out, "wb").write(pt)
        print(f"[+] {pw_name} OK  {len(pt)} bytes -> {out}")
        return
    print("[-] 解密失败（密码/结构不匹配）")

if __name__ == "__main__":
    main()
