import socket, ssl, json, base64, os, struct, concurrent.futures, time
def ws_probe(host, port, path, hosthdr=None, timeout=8):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        raw=socket.create_connection((host,port),timeout=timeout)
        s=ctx.wrap_socket(raw, server_hostname=host)
    except Exception as e:
        return ('CONNFAIL', type(e).__name__, None)
    key=base64.b64encode(os.urandom(16)).decode()
    hh = hosthdr or host
    req=(f'GET {path} HTTP/1.1\r\nHost: {hh}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
         f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
         f'User-Agent: Mozilla/5.0\r\n\r\n')
    try:
        s.sendall(req.encode())
        s.settimeout(timeout)
        data=s.recv(400)
        s.close()
        first=data.split(b'\r\n')[0].decode('latin1')
        return ('OK', first, data[:120])
    except Exception as e:
        return ('READFAIL', type(e).__name__, None)
tests=[
 ('atnet3-507168703375.europe-southwest1.run.app', 443, '/ws-kobe'),
 ('atnet3-507168703375.europe-southwest1.run.app', 443, '/'),
 ('atnet3-507168703375.europe-southwest1.run.app', 443, '/ws-kobe?ed=2048'),
 ('atnet3-507168703375.europe-southwest1.run.app', 110, '/ws-kobe'),
 ('server2.bshield.dns.army', 443, '/binke'),
 ('server2.bshield.dns.army', 443, '/'),
 ('server2.bshield.dns.army', 8443, '/binke'),
 ('shegeftihaaa.net', 443, '/rsedgws'),
 ('shegeftihaaa.net', 8443, '/rsedgws'),
 ('sidiv2.beevpn.shop', 443, '/xhttp'),
 ('sidiv2.beevpn.shop', 443, '/'),
 ('mludp.mludpdnsvip.top', 443, '/?ed'),
 ('vps.groupjgm.es', 443, '/vless'),
 ('vps.groupjgm.es', 443, '/'),
 ('ssh.groupjgm.es', 443, '/vless'),
]
with concurrent.futures.ThreadPoolExecutor(10) as ex:
    for t,r in zip(tests, ex.map(lambda t: ws_probe(*t), tests)):
        print(f'{t[0][:44]:46s}:{t[1]:5d} {t[2]:14s} -> {r[0]} {r[1]}')
