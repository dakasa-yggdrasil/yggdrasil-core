"""LAB-only read-only probe; identical netlink schema without controller imports."""
import base64,json,socket,struct

def check(ok,reason):
 if not ok:raise RuntimeError(reason)
def packets(raw):
 out=[];at=0
 while at<len(raw):
  n,t,f,q,p=struct.unpack_from('<IHHII',raw,at);check(n>=16 and at+n<=len(raw),'NL_PACKET_BOUNDS');out.append((t,q,raw[at+16:at+n]));at+=(n+3)&~3
 check(at==len(raw),'NL_PACKET_LENGTH');return out
def attrs(raw):
 out=[];at=0
 while at<len(raw):
  n,k=struct.unpack_from('<HH',raw,at);check(n>=4 and at+n<=len(raw),'NL_ATTR_BOUNDS');out.append((k,raw[at+4:at+n]));at+=(n+3)&~3
 check(at==len(raw),'NL_ATTR_LENGTH');return out
def msg(t,flags,seq,payload):
 b=struct.pack('<IHHII',16+len(payload),t,flags,seq,0)+payload;return b+bytes((-len(b))%4)
def genid(nl):
 nl.send(msg((10<<8)|16,1,10,struct.pack('>BBH',0,0,0)));r=packets(nl.recv(8192));check(len(r)==1 and r[0][0]==((10<<8)|15) and r[0][1]==10,'GENID_RESPONSE')
 x=[v for k,v in attrs(r[0][2][4:]) if k&0x3fff==1];check(len(x)==1 and len(x[0])==4,'GENID_ATTR');return struct.unpack('>I',x[0])[0]
def rules(nl):
 nl.send(msg((10<<8)|7,1|0x300,80,struct.pack('>BBH',1,0,0)));out=[];done=False
 while not done:
  for typ,seq,data in packets(nl.recv(65536)):
   check(seq==80,'RULE_DUMP_SEQUENCE')
   if typ==3:done=True;continue
   check(typ==((10<<8)|6),'RULE_DUMP_TYPE');fields=attrs(data[4:]);v={k&0x3fff:x for k,x in fields}
   if v.get(1)==b'dakasa_capacity_network\0' and v.get(2)==b'admit_deadline\0':out.append(data)
 return out
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);s.bind((0,0));s.settimeout(5)
try:
 first=genid(s);rows=rules(s);last=genid(s);check(first==last,'GENID_CHANGED_IN_PROBE')
 print(json.dumps({'genid':first,'rules':[base64.b64encode(raw).decode() for raw in rows]}),flush=True)
finally:s.close()
