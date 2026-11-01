"""Bounded negative checks for CI holder renew; real-kernel test follows."""
import gc,os,socket,sys,threading,time,types,weakref
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'runtime'))
import guarded_effect_lease_two_peers_DRAFT as effect
import guarded_refresh_registry_DRAFT as registry
import guarded_lease_ipc_DRAFT as ipc

class Verified:pass
class Chain:pass
cap=object();cache=object();token='t'*64

def fixture():
    now=time.monotonic_ns();a=effect.EffectLeaseAuthority.__new__(effect.EffectLeaseAuthority)
    a.pid=os.getpid();a.lock=threading.Lock();a.cache=cache;a.pending=None
    a.verifier=types.SimpleNamespace(_VerifiedGeneration=Verified,_VERIFIED_CAPABILITY=cap)
    a.current15=types.SimpleNamespace(CoverageChain=Chain)
    a.lease={'token':token,'until':now+1_000_000_000,'epoch':7,'receipt_sha256':'r',
             'invalidation_epoch':3,'maps':{'inbound':{b'a':now+10_000_000_000},'reverse':{b'b':now+10_000_000_000}},
             'sender_pidfd':0,'revoked':False}
    a._source_live=lambda lease:{role:dict(rows) for role,rows in lease['maps'].items()}
    v=Verified();v.capability=cap;v.guardian_pid=a.pid;v.reader_cache=cache;v.sender_pidfd=0
    v.actual={'inbound':[(b'a',now+10_000_000_000)],'reverse':[(b'b',now+10_000_000_000)]}
    c=Chain();c.cache=cache;c.pid=a.pid;c.verifier=a.verifier;c.last_verified=v
    c.genid=7;c.epoch=3;c.deadline_ns=now+9_000_000_000
    c.last_observation=(True,now-16_000_000_000,now-1_000_000,c.deadline_ns,3,7,'r')
    live={'invalidation_epoch':3,'observation':{'genid':7,'receipt_sha256':'r','kernel_min_deadline_ns':now+8_000_000_000}}
    return a,v,c,live,now

def held(fn):
    try:fn()
    except effect.Held:return
    raise AssertionError('invalid renewal accepted')

a,v,c,live,now=fixture();previous=a.lease
result=a.renew(token,v,c,now+2_000_000_000,live)
assert result['expires_monotonic_ns']>previous['until'] and a.lease is not previous and not result['external_effect_authorized']
for mutate in ('token','genid','epoch','source','deadline','expired'):
    a,v,c,live,now=fixture();until=now+2_000_000_000;supplied=token
    if mutate=='token':supplied='wrong'
    elif mutate=='genid':live['observation']['genid']=8
    elif mutate=='epoch':live['invalidation_epoch']=4
    elif mutate=='source':a._source_live=lambda lease:{'inbound':{b'a':now+1_100_000_000},'reverse':{b'b':now+10_000_000_000}}
    elif mutate=='deadline':until=now+6_000_000_000
    else:a.lease['until']=now-1
    held(lambda:a.renew(supplied,v,c,until,live))

r=registry.GuardianRefreshRegistry.__new__(registry.GuardianRefreshRegistry)
r.lock=threading.Lock();r.state='HOLDER';r.holder=object();r.current_verified=object();r.pending=object();r._preparer_live=lambda:None
called=[]
try:r.observe_holder(r.holder,lambda _:called.append(True))
except effect.BusyBeforeRenew:pass
else:raise AssertionError('pending sender did not reject renewal')
assert not called

# 500 replacements with one reader retaining an old snapshot. Its FD stays
# valid until that reader ends; all other retired generations are reclaimed.
a,v,c,live,now=fixture();a._owned_sender_pidfds=weakref.WeakSet()
read_fd,write_fd=os.pipe()
with a.lock:owner=a._duplicate_sender_locked(read_fd)
lease={'sender_pidfd':owner};del owner
reader_ready=threading.Event();reader_finish=threading.Event();reader_done=threading.Event()
reader_fd=lease['sender_pidfd'].fd
def retain(snapshot):
    reader_ready.set();assert reader_finish.wait(3)
    os.fstat(snapshot['sender_pidfd'].fd);reader_done.set()
reader=threading.Thread(target=retain,args=(lease,));reader.start();assert reader_ready.wait(3)
for _ in range(500):
    with a.lock:owner=a._duplicate_sender_locked(read_fd)
    lease={'sender_pidfd':owner};del owner
    os.fstat(reader_fd)
    assert len(a._owned_sender_pidfds)<=2
reader_finish.set();reader.join(3);assert reader_done.is_set() and not reader.is_alive()
del reader;gc.collect()
try:os.fstat(reader_fd)
except OSError:pass
else:raise AssertionError('retired reader descriptor leaked')
assert len(a._owned_sender_pidfds)==1
del lease;gc.collect()
assert len(a._owned_sender_pidfds)==0
owners=[]
for _ in range(a.MAX_OWNED_SENDER_PIDFDS):
    with a.lock:owners.append(a._duplicate_sender_locked(read_fd))
with a.lock:held(lambda:a._duplicate_sender_locked(read_fd))
assert len(a._owned_sender_pidfds)==a.MAX_OWNED_SENDER_PIDFDS
owners.clear();gc.collect();assert len(a._owned_sender_pidfds)==0
with a.lock:owner=a._duplicate_sender_locked(read_fd)
snapshot={'sender_pidfd':owner,'revoked':False};a.lease=snapshot;del owner
a.peer_pidfd=os.dup(read_fd);a.preparer_pidfd=os.dup(read_fd)
snapshot_fd=snapshot['sender_pidfd'].fd;a.close();os.fstat(snapshot_fd)
del snapshot;gc.collect()
try:os.fstat(snapshot_fd)
except OSError:pass
else:raise AssertionError('snapshot FD retained after last reader')
os.close(read_fd);os.close(write_fd)

# A timed-out join cannot close any authority FD, including when only the
# monitor remains alive. Once both terminate, normal close is permitted.
class CloseProbe:
    def __init__(self):self.closed=False
    def close(self):self.closed=True
for stuck_monitor in (False,True):
    stop=threading.Event();thread=threading.Thread(target=stop.wait);thread.start()
    probe=CloseProbe();session=types.SimpleNamespace(monitor=thread if stuck_monitor else None)
    try:ipc.close_after_workers(None if stuck_monitor else thread,session,probe,timeout=.01)
    except RuntimeError:pass
    else:raise AssertionError('live reader allowed authority close')
    assert not probe.closed
    stop.set();ipc.close_after_workers(None if stuck_monitor else thread,session,probe,timeout=3)
    assert probe.closed

class Expiring:
    def __init__(self):self.lock=threading.Lock();self.lease={'until':time.monotonic_ns()+100_000_000,'revoked':False}
    def _source_live(self,lease):
        if time.monotonic_ns()>=lease['until']:raise effect.Held('expired')
    def revoke(self):
        with self.lock:self.lease['revoked']=True
left,right=socket.socketpair();authority=Expiring();authority.channel=left;lost=threading.Event()
def on_lost():authority.revoke();lost.set()
session=ipc.HolderSession(left,authority,lambda _:None,lambda:None,on_lost=on_lost)
worker=threading.Thread(target=session.serve);worker.start();right.settimeout(3)
assert b'REVOKED' in right.recv(4096) and lost.wait(3)
worker.join(3);assert not worker.is_alive() and authority.lease['revoked']
left.close();right.close()
print('PASS renewal bounds, epoch/token/source failures, pending exclusion and expiry revocation',flush=True)
