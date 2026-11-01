"""LAB candidate only: direct immutable BPF/netfilter primitives.

Not connected to an operational controller or Guardian; not production authority.
Kernel and tuple contracts are those of the reviewed laboratory fixture.
"""
import ctypes, hashlib, json, os, platform, socket, stat, struct, subprocess
from pathlib import Path
if platform.machine() != 'x86_64':
    raise RuntimeError('LAB_X86_64_BPF_SYSCALL_REQUIRED')

LIB=ctypes.CDLL(None,use_errno=True);LIB.syscall.restype=ctypes.c_long

def check(ok,reason):
    if not ok:raise RuntimeError(reason)
def bpf(op,raw):
    b=ctypes.create_string_buffer(raw+bytes(max(0,144-len(raw))));r=LIB.syscall(321,op,ctypes.byref(b),ctypes.sizeof(b))
    if r<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return r
def cmd(*argv,inp=None,writer_lease=None):
    pass_fds=()
    if writer_lease is not None:
        import writer_lease_v3_DRAFT as lease_module
        check(type(writer_lease) is lease_module.WriterLease,'EXACT_PROBE_WRITER_LEASE_REQUIRED')
        pass_fds=(writer_lease.validate(),)
    p=subprocess.run(argv,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,pass_fds=pass_fds)
    if p.returncode:raise RuntimeError('COMMAND_FAILED:'+argv[0]+':'+p.stderr.decode(errors='replace')[:400])
    return p.stdout
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
def attr(k,v):
    b=struct.pack('<HH',4+len(v),k)+v;return b+bytes((-len(b))%4)
def msg(t,flags,seq,payload):
    b=struct.pack('<IHHII',16+len(payload),t,flags,seq,0)+payload;return b+bytes((-len(b))%4)
def ins(op,d=0,s=0,off=0,imm=0):return struct.pack('<BBhi',op,d|(s<<4),off,imm)
def program(fd):
    ops=[];fix=[]
    def emit(op,d=0,s=0,off=0,imm=0):ops.append([op,d,s,off,imm])
    def guard(op,d=0,s=0,imm=0):fix.append(len(ops));emit(op,d,s,0,imm)
    emit(0xbf,9,1);emit(0xb7,2,0,0,0);emit(0xbf,3,10);emit(0x07,3,0,0,-32);emit(0xb7,4,0,0,24);emit(0x85,0,0,0,26);guard(0x55,0,0,0)
    emit(0x71,0,10,-32);guard(0x55,0,0,0x45);emit(0x71,0,10,-23);guard(0x55,0,0,6)
    emit(0x69,0,10,-26);emit(0x57,0,0,0,0xff3f);guard(0x55,0,0,0)
    emit(0x61,6,10,-20);emit(0x63,10,6,-48);emit(0x61,6,10,-16);emit(0x63,10,6,-44);emit(0x69,6,10,-10);emit(0x63,10,6,-40)
    emit(0x18,1,1,0,fd);emit(0);emit(0xbf,2,10);emit(0x07,2,0,0,-48);emit(0x85,0,0,0,1);guard(0x15,0,0,0)
    emit(0x79,7,0);emit(0x85,0,0,0,5);guard(0x3d,0,7);emit(0xb7,0,0,0,-1);emit(0x95)
    end=len(ops);emit(0xb7,0,0,0,0);emit(0x95)
    for i in fix:ops[i][3]=end-i-1
    return b''.join(ins(*row) for row in ops)
class ProgInfo(ctypes.Structure):
    _fields_=[('type',ctypes.c_uint32),('id',ctypes.c_uint32),('tag',ctypes.c_ubyte*8),('jited_len',ctypes.c_uint32),('xlated_len',ctypes.c_uint32),('jited_insns',ctypes.c_uint64),('xlated_insns',ctypes.c_uint64),('load_time',ctypes.c_uint64),('created_by_uid',ctypes.c_uint32),('nr_map_ids',ctypes.c_uint32),('map_ids',ctypes.c_uint64)]
class MapInfo(ctypes.Structure):
    _fields_=[('type',ctypes.c_uint32),('id',ctypes.c_uint32),('key_size',ctypes.c_uint32),('value_size',ctypes.c_uint32),('max_entries',ctypes.c_uint32),('map_flags',ctypes.c_uint32)]
def info(fd,obj):bpf(15,struct.pack('<IIQ',fd,ctypes.sizeof(obj),ctypes.addressof(obj)));return obj
def make_program(rows):
    check(0 < len(rows) <= 256, 'NONEMPTY_BOUNDED_MAP')
    keys = [bytes.fromhex(hx) for hx, deadline in rows]
    check(all(len(key)==12 for key in keys) and len(set(keys))==len(keys), 'EXACT_UNIQUE_MAP_KEYS')
    check(all(type(deadline) is int and 0 < deadline < (1 << 64) for hx, deadline in rows), 'EXACT_POSITIVE_DEADLINES')
    m=bpf(0,struct.pack('<IIIII',1,12,8,256,128));p=None
    try:
        for hx,deadline in rows:
            key=ctypes.create_string_buffer(bytes.fromhex(hx));val=ctypes.c_uint64(deadline)
            bpf(2,struct.pack('<IIQQQ',m,0,ctypes.addressof(key),ctypes.addressof(val),0))
        bpf(22,struct.pack('<I',m));code=program(m);a=ctypes.create_string_buffer(code);lic=ctypes.create_string_buffer(b'GPL');log=ctypes.create_string_buffer(65536)
        try:p=bpf(5,struct.pack('<IIQQIIQ',1,len(code)//8,ctypes.addressof(a),ctypes.addressof(lic),1,len(log),ctypes.addressof(log)))
        except OSError:raise RuntimeError('BPF_VERIFIER:'+log.value.decode(errors='replace')[-600:])
        ids=(ctypes.c_uint32*8)();pi=ProgInfo();pi.nr_map_ids=8;pi.map_ids=ctypes.addressof(ids);info(p,pi);mi=info(m,MapInfo())
        check(pi.type==1 and pi.nr_map_ids==1 and ids[0]==mi.id and mi.map_flags&128,'ACTUAL_PROGRAM_MAP_BINDING')
        return {'program_fd':p,'program_id':pi.id,'program_tag':bytes(pi.tag).hex(),'map_fd':m,'map_id':mi.id}
    except BaseException:
        if p is not None:os.close(p)
        os.close(m);raise

def genid(nl):
    nl.send(msg((10<<8)|16,1,10,struct.pack('>BBH',0,0,0)));r=packets(nl.recv(8192));check(len(r)==1 and r[0][0]==((10<<8)|15) and r[0][1]==10,'GENID_RESPONSE')
    x=[v for k,v in attrs(r[0][2][4:]) if k&0x3fff==1];check(len(x)==1 and len(x[0])==4,'GENID_ATTR');return struct.unpack('>I',x[0])[0]
def rules(nl,chain):
    nl.send(msg((10<<8)|7,1|0x300,80,struct.pack('>BBH',1,0,0)));out=[];done=False
    while not done:
        for typ,seq,data in packets(nl.recv(65536)):
            check(seq==80,'RULE_DUMP_SEQUENCE')
            if typ==3:done=True;continue
            check(typ==((10<<8)|6),'RULE_DUMP_TYPE');fields=attrs(data[4:]);v={k&0x3fff:x for k,x in fields}
            if v.get(1)==b'dakasa_capacity_network\0' and v.get(2)==chain.encode()+b'\0':out.append((fields,data))
    return out
def rewrite(raw,old,new):
    out=b'';count=0
    for k,v in attrs(raw):
        if v==old:v=new;count+=1
        elif old in v:v,n=rewrite(v,old,new);count+=n
        out+=attr(k,v)
    return out,count
def replace_jump(fields,seq):
    out=struct.pack('>BBH',1,0,0);seen=0
    for k,v in fields:
        if k&0x3fff==6:continue
        if k&0x3fff==4:v,n=rewrite(v,b'admit_new\0',b'admit_deadline\0');seen+=n
        out+=attr(k,v)
    check(seen==1,'ONE_LEGACY_JUMP');return msg((10<<8)|6,1|4|0x100,seq,out)
def xtjump(fd,seq):
    xt=struct.pack('<HHi',2,0,fd)+bytes(512)+bytes(8)
    match=attr(1,b'match\0')+attr(2|0x8000,attr(1,b'bpf\0')+attr(2,struct.pack('>I',1))+attr(3,xt))
    verdict=attr(1,struct.pack('>i',-3))+attr(2,b'admit_new\0')
    immediate=attr(1,b'immediate\0')+attr(2|0x8000,attr(1,struct.pack('>I',0))+attr(2|0x8000,attr(2|0x8000,verdict)))
    body=struct.pack('>BBH',1,0,0)+attr(1,b'dakasa_capacity_network\0')+attr(2,b'admit_deadline\0')+attr(4|0x8000,attr(1|0x8000,match)+attr(1|0x8000,immediate))
    return msg((10<<8)|6,1|4|0x400|0x800,seq,body)
def flush(name,seq):return msg((10<<8)|14,1|4,seq,struct.pack('>BBH',1,0,0)+attr(1,b'dakasa_capacity_network\0')+attr(2,name.encode()+b'\0'))
def element(key,timeout,value=None):
    e=attr(1|0x8000,attr(1,key))+attr(4,struct.pack('>Q',timeout))
    if value is not None:e+=attr(2|0x8000,attr(1,value))
    return attr(1|0x8000,e)
def add(name,entries,seq):
    body=struct.pack('>BBH',1,0,0)+attr(1,b'dakasa_capacity_network\0')+attr(2,name.encode()+b'\0')+attr(3|0x8000,b''.join(entries))
    return msg((10<<8)|12,1|4|0x400|0x200,seq,body)
def begin(g,s):return msg(0x10,1,s,struct.pack('>BBH',0,0,10)+attr(1,struct.pack('>I',g)))
def end(s):return msg(0x11,1,s,struct.pack('>BBH',0,0,10))
def fdinfo(pid,fd):
    return dict(line.split(':',1) for line in Path('/proc/%d/fdinfo/%d'%(pid,fd)).read_text().splitlines() if ':' in line)
def map_rows(id):
    fd=bpf(14,struct.pack('<I',id));rows=[];prev=None
    try:
        mi=info(fd,MapInfo());check(mi.id==id and mi.type==1 and mi.key_size==12 and mi.value_size==8 and mi.map_flags&128,'FROZEN_MAP_SHAPE')
        while True:
            key=ctypes.create_string_buffer(12)
            try:bpf(4,struct.pack('<IIQQ',fd,0,0 if prev is None else ctypes.addressof(prev),ctypes.addressof(key)))
            except OSError as e:
                if e.errno==2:break
                raise
            val=ctypes.c_uint64();bpf(1,struct.pack('<IIQQQ',fd,0,ctypes.addressof(key),ctypes.addressof(val),0));rows.append((key.raw,val.value));prev=key
            check(len(rows)<=256,'BOUNDED_MAP_ROWS')
        return rows
    finally:os.close(fd)

def startticks(pid):
    raw=Path('/proc/%d/stat'%pid).read_bytes();return int(raw[raw.rfind(b')')+1:].split()[19])
def durable(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def canon(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
def private_read(path,cap=8*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);check(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and not stat.S_IMODE(a.st_mode)&0o077,'PRIVATE_ORIGINAL_RECEIPT')
        with os.fdopen(fd,'rb',closefd=False) as f:data=f.read(cap+1)
        b=os.fstat(fd);check(len(data)<=cap and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'STABLE_ORIGINAL_RECEIPT');return data
    finally:os.close(fd)
