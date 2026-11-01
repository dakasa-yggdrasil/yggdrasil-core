"""LAB-only read-only probe; identical netlink schema without controller imports."""
import base64,fcntl,json,os,socket,stat,struct,sys
from pathlib import Path

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
check(len(sys.argv)==3 and sys.argv[1]=='probe' and sys.argv[2].isdigit(),'EXACT_INHERITED_WRITER_FD_REQUIRED')
writer_fd=int(sys.argv[2]);opened=os.fstat(writer_fd)
lock=Path(__file__).resolve().parent.parent/'drain-coordinator'/'writer.lock';named=os.lstat(lock)
check(stat.S_ISREG(opened.st_mode) and opened.st_uid==0 and stat.S_IMODE(opened.st_mode)==0o600
      and opened.st_nlink==1 and (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino),
      'SAME_INHERITED_WRITER_INODE_REQUIRED')
fcntl.flock(writer_fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);s.bind((0,0));s.settimeout(5)
try:
 first=genid(s);rows=rules(s);last=genid(s);check(first==last,'GENID_CHANGED_IN_PROBE')
 print(json.dumps({'genid':first,'rules':[base64.b64encode(raw).decode() for raw in rows]}),flush=True)
finally:s.close()
