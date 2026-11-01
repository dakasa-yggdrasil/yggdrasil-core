"""CI-only same-custodian one-use deny capability. NEVER production authority.

This assumes trusted fixture sources, exclusive writer inventory and receipt
provenance; Python-private tokens do not provide production source sealing.
"""
import fcntl,hashlib,json,os,re,socket,stat,struct,time
from pathlib import Path
import guarded_nl as nl
import guarded_unit_identity as identity
import guarded_sources as sources
import drain_marker_v3_DRAFT as marker_v3
import recovery_read_DRAFT as recovery
import recovery_terminality_DRAFT as terminal

_CAP=object()
class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def custodian_identity():
    unit=os.environ.get('CI_CUSTODIAN_UNIT','');invocation=os.environ.get('INVOCATION_ID','')
    need(re.fullmatch(r'[a-zA-Z0-9_.@:-]+\.service',unit) is not None
         and re.fullmatch(r'[0-9a-f]{32}',invocation) is not None,'SYSTEMD_CUSTODIAN_REQUIRED')
    props=identity._properties(unit);pid=os.getpid()
    need(props['MainPID']==str(pid) and props['ActiveState']=='active'
         and props['InvocationID']==invocation
         and Path('/proc/self/cgroup').read_text().splitlines()==['0::'+props['ControlGroup']],
         'SAME_ACTIVE_SYSTEMD_CUSTODIAN_REQUIRED')
    return (unit,invocation,pid,identity._startticks(pid),props['ControlGroup'],
            os.readlink('/proc/self/ns/net'),Path('/proc/sys/kernel/random/boot_id').read_text().strip())

def check_fence(anchor,fd):
    need(type(anchor) is terminal.MarkerAnchor and anchor.pid==os.getpid(),'SAME_CUSTODIAN_MARKER_REQUIRED')
    coord=anchor.coordinator;named=os.lstat(coord.writer_lock);opened=os.fstat(fd)
    need(stat.S_ISREG(opened.st_mode) and opened.st_uid==0 and opened.st_nlink==1
         and stat.S_IMODE(opened.st_mode)==0o600
         and (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino), 'EXACT_WRITER_FENCE_REQUIRED')
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    mark=marker_v3._marker_identity(coord)
    need(mark[:3]==anchor.key and mark[3].get('writer_lock_identity')==[opened.st_dev,opened.st_ino],
         'SAME_MARKER_AND_WRITER_FENCE_REQUIRED')
    terminal.prove_terminal_for_marker(anchor)
    return mark

def deny_wire(net,genid,records,reference):
    rows=recovery._pins(records,reference)
    need(all(deadline==1 for values in rows.values() for _,deadline in values),'ONLY_EXPIRED_DENY_MAPS')
    current=nl.rules(net,'admit_deadline');need(len(current)==2,'EXACT_TWO_OLD_GATES')
    seq=201;parts=[]
    for fields,_ in current:
        h=dict((k&0x3fff,v) for k,v in fields)[3]
        parts.append(nl.msg((10<<8)|8,1|4,seq,struct.pack('>BBH',1,0,0)+nl.attr(1,b'dakasa_capacity_network\0')+nl.attr(2,b'admit_deadline\0')+nl.attr(3,h)));seq+=1
    for rec in records:parts.append(nl.xtjump(rec['program_fd'],seq));seq+=1
    for name in ('core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'):
        parts.append(nl.flush(name,seq));seq+=1
    return nl.begin(genid,200)+b''.join(parts)+nl.end(seq),seq

class _Permit:
    def __init__(self,*,anchor,fence,identity0,net,genid,wire_hash,source_generation,source_epoch,
                 old_digest,records,reference,cache,deny_dir,deny_intent_digest,cap):
        need(cap is _CAP,'PRIVATE_CI_PERMIT_REQUIRED')
        self.anchor,self.fence,self.identity0,self.net=anchor,fence,identity0,net
        self.genid,self.wire_hash,self.source_generation,self.source_epoch=genid,wire_hash,source_generation,source_epoch
        self.old_digest,self.records,self.reference,self.cache=old_digest,records,reference,cache
        self.deny_dir,self.deny_intent_digest=deny_dir,deny_intent_digest
        self.deadline_ns=time.monotonic_ns()+250_000_000
        self.used=False;self.cap=cap

def mint(*,anchor,fence,net,genid,wire,deny_records,reference,cache,old_directory,sender_records,
         old_records,original_pin,receipt,coverage,deny_dir):
    identity0=custodian_identity();mark=check_fence(anchor,fence.fileno())
    old=recovery.inspect_unknown(anchor,old_directory,counter=1,sender_records=sender_records)
    sample=recovery.sample_attached(anchor.coordinator,net,expected_marker=anchor.key,expected_genid=genid,
        records=old_records,reference=reference,cache=cache,original_pin=original_pin,receipt=receipt,coverage=coverage)
    need(not sample['effect_or_recovery_authority'] and sample['four_nft_collections_joined'],
         'READ_ONLY_ORIGINAL_SNAPSHOT_REQUIRED')
    expected,_=deny_wire(net,genid,deny_records,reference)
    need(wire==expected and hashlib.sha256(wire).hexdigest()!=old['wire_sha256'],
         'ONLY_DISTINCT_DENY_WIRE_REQUIRED')
    directory=Path(deny_dir);st=directory.lstat()
    need(stat.S_ISDIR(st.st_mode) and not directory.is_symlink() and st.st_uid==0
         and not stat.S_IMODE(st.st_mode)&0o077,'PRIVATE_DENY_INTENT_DIRECTORY_REQUIRED')
    raw=nl.private_read(directory/'DENY-INTENT.json');saved=json.loads(raw)
    need(nl.private_read(directory/'DENY-WIRE.bin')==wire
         and saved.get('schema')=='ci_distinct_deny_after_unknown_v1'
         and saved.get('genid')==genid and saved.get('marker_sha256')==anchor.key[2]
         and saved.get('old_unknown_wire_sha256')==old['wire_sha256']
         and saved.get('wire_sha256')==hashlib.sha256(wire).hexdigest()
         and saved.get('programs')==deny_records and saved.get('no_retry') is True,
         'SAME_DURABLE_DISTINCT_DENY_INTENT_REQUIRED')
    source=sources.build_expected(cache);recovery._marker_reader_join(mark[3],cache,source)
    need(nl.genid(net)==genid and custodian_identity()==identity0,'SAME_CUSTODIAN_SOURCE_AND_GENID_REQUIRED')
    return _Permit(anchor=anchor,fence=fence,identity0=identity0,net=net,genid=genid,
        wire_hash=hashlib.sha256(wire).hexdigest(),source_generation=source['source_generation'],
        source_epoch=source['invalidation_epoch'],old_digest=old['wire_sha256'],records=tuple(deny_records),
        reference=reference,cache=cache,deny_dir=directory,
        deny_intent_digest=hashlib.sha256(raw).hexdigest(),cap=_CAP)

def consume(permit,wire,*,old_directory,sender_records):
    need(type(permit) is _Permit and permit.cap is _CAP and not permit.used
         and time.monotonic_ns()<permit.deadline_ns,'LIVE_UNUSED_CI_DENY_PERMIT_REQUIRED')
    need(custodian_identity()==permit.identity0,'SAME_SYSTEMD_CUSTODIAN_REQUIRED')
    mark=check_fence(permit.anchor,permit.fence.fileno())
    old=recovery.inspect_unknown(permit.anchor,old_directory,counter=1,sender_records=sender_records)
    source=sources.build_expected(permit.cache);recovery._marker_reader_join(mark[3],permit.cache,source)
    need(old['wire_sha256']==permit.old_digest and source['source_generation']==permit.source_generation
         and source['invalidation_epoch']==permit.source_epoch,'SAME_UNKNOWN_AND_READER_REQUIRED')
    intent_raw=nl.private_read(permit.deny_dir/'DENY-INTENT.json')
    need(hashlib.sha256(intent_raw).hexdigest()==permit.deny_intent_digest
         and nl.private_read(permit.deny_dir/'DENY-WIRE.bin')==wire,'SAME_DURABLE_DENY_BYTES_REQUIRED')
    need(nl.genid(permit.net)==permit.genid,'CI_DENY_GENID_CHANGED')
    expected,_=deny_wire(permit.net,permit.genid,list(permit.records),permit.reference)
    need(wire==expected and hashlib.sha256(wire).hexdigest()==permit.wire_hash,'SAME_ONLY_DENY_WIRE_REQUIRED')
    need(time.monotonic_ns()<permit.deadline_ns,'CI_DENY_PERMIT_EXPIRED')
    permit.used=True
