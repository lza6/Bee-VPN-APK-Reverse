import os
WORK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import base64, json, collections
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
PW=b'BinkeVPNTeam'
def dec(s):
    if not isinstance(s,str) or len(s)<20: return s
    try: b=base64.b64decode(s+'='*(-len(s)%4))
    except Exception: return s
    if len(b)<29: return s
    salt,nonce,ct=b[:16],b[16:28],b[28:]
    try:
        key=hash_secret_raw(PW,salt,3,8192,1,32,Type.ID)
        return AESGCM(key).decrypt(nonce,ct,salt).decode('utf8')
    except Exception:
        return s
FIELDS=['ServerIPHost','OVPNUser','OVPNPass','UDP_obfs','UDP_user','CustomCertificate',
        'V2rayUUID','V2rayPath','V2rayProto','H2pass','SlowDNSHost','SlowDNSKey']
d=json.load(open(os.path.join(WORK,'data','plain_bee2.txt'),encoding='utf8'))
out={'meta':{k:dec(d[k]) for k in ['Version','DefOVPNUser','DefOVPNPass','HysteriaUser','HysteriaOBFS','Telegram','Facebook']},'servers':[]}
for s in d['Servers']:
    o={'Name':s.get('Name','').strip(),'Flag':s.get('Flag'),'ServerType':s.get('ServerType'),
       'ServerProtocol':s.get('ServerProtocol'),'TCP':s.get('OpenVPNTCPPort'),'UDP':s.get('OpenVPNUdpPort'),
       'SSH_Port':s.get('SSH_Port'),'SSLPort':s.get('SSLPort'),'isdefUser':s.get('isdefUser')}
    for f in FIELDS:
        if f in s: o[f]=dec(s[f])
    out['servers'].append(o)
json.dump(out,open(os.path.join(WORK,'data','nodes_full.json'),'w',encoding='utf8'),ensure_ascii=False,indent=1)
print('nodes',len(out['servers']))
print('meta',json.dumps(out['meta'],ensure_ascii=False))
# 展示 hy2 与 vless 全量
for s in out['servers']:
    if s['ServerProtocol']=='UDP Hysteria':
        print('HY2',s['ServerIPHost'],'|',s.get('UDP_user'),'|obfs',s.get('UDP_obfs'),'|flag',s['Flag'])
