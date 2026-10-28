import os as _os
WORK = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
"""Bee VPN 节点池压测：TCP 握手 + TLS + WS 升级三层测量"""
import json, os, socket, ssl, time, statistics, concurrent.futures, base64, os, sys
NODES=json.load(open(os.path.join(WORK,'data','nodes_full.json'),encoding='utf8'))['servers']
def uniq():
    out=[]; seen=set()
    for s in NODES:
        for h in [x.strip() for x in str(s.get('ServerIPHost','')).split(';') if x.strip()]:
            k=(h,s['ServerProtocol'])
            if k in seen: continue
            seen.add(k)
            out.append({'host':h,'proto':s['ServerProtocol'],'type':s['ServerType'],'flag':s['Flag'],'ssl':s.get('SSLPort') or '443'})
    return out
def tcp_once(host,port,timeout=6):
    t=time.time()
    try:
        ip=socket.getaddrinfo(host,int(port),socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
    except Exception as e:
        return None,None,'DNSFAIL'
    try:
        s=socket.create_connection((ip,int(port)),timeout=timeout); s.close()
        return (time.time()-t)*1000, ip, 'OK'
    except Exception as e:
        return (time.time()-t)*1000, ip, type(e).__name__
def tls_once(host,port,timeout=8):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    t=time.time()
    try:
        r=socket.create_connection((host,int(port)),timeout=timeout)
        s=ctx.wrap_socket(r,server_hostname=host)
        cert=s.getpeercert(binary_form=True)
        ver=s.version(); s.close()
        return (time.time()-t)*1000, ver, len(cert or b''), 'OK'
    except Exception as e:
        return (time.time()-t)*1000, '', 0, type(e).__name__
def ws_once(host,port,path,timeout=8):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        r=socket.create_connection((host,int(port)),timeout=timeout)
        s=ctx.wrap_socket(r,server_hostname=host)
        key=base64.b64encode(os.urandom(16)).decode()
        s.sendall((f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0\r\n\r\n').encode())
        s.settimeout(timeout); d=s.recv(200); s.close()
        return d.split(b'\r\n')[0].decode('latin1')[:30]
    except Exception as e:
        return 'ERR:'+type(e).__name__
def bench_one(n):
    host=n['host']; port=int(n['ssl'])
    lat=[]
    for _ in range(5):
        ms,ip,st=tcp_once(host,port)
        if st=='OK' and ms: lat.append(ms)
    n['ip']=ip
    n['tcp_ok']=len(lat); n['tcp_rate']=len(lat)/5
    if lat:
        n['p50']=round(statistics.median(lat)); n['p95']=round(sorted(lat)[int(len(lat)*0.95)-1] if len(lat)>1 else lat[0])
        n['min']=round(min(lat))
    else:
        n['p50']=n['p95']=n['min']=None
    if n['tcp_ok']:
        ms,ver,cl,st=tls_once(host,port)
        n['tls']=st; n['tls_ms']=round(ms)
    else:
        n['tls']='SKIP'; n['tls_ms']=None
    return n
def main():
    targets=uniq()
    print(f'benchmarking {len(targets)} unique endpoints ...')
    out=[]
    with concurrent.futures.ThreadPoolExecutor(24) as ex:
        for r in ex.map(bench_one, targets): out.append(r)
    out.sort(key=lambda x: (x['tcp_rate']==0, x['p50'] or 9e9))
    json.dump(out, open(os.path.join(WORK,'data','bench_result.json'),'w',encoding='utf8'), ensure_ascii=False, indent=1)
    print(f"{'proto':14s}{'host':46s}{'ok':>3s}{'p50':>7s}{'p95':>7s}{'tls':>16s}  ip")
    for n in out:
        print(f"{n['proto']:14s}{n['host'][:44]:46s}{n['tcp_ok']:3d}{(n['p50'] or 0):7d}{(n['p95'] or 0):7d}{n['tls']:>16s}  {n.get('ip') or ''}")
    alive=[n for n in out if n['tcp_rate']>=0.8]
    print(f"\nSUMMARY: endpoints={len(out)} tcp_alive(>=80%)={len(alive)}")
    if alive:
        p50=[n['p50'] for n in alive]
        print(f'P50 across alive: median={statistics.median(p50):.0f}ms min={min(p50)}ms max={max(p50)}ms')
main()
