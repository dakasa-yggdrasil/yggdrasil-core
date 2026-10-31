"""Disposable Linux CI: actual service-shaped identity and real nft genid drift.

The maps, reader witness and systemd identity verifier are fixtures. This is
not an integrated Guardian or a production qualification.
"""
import hashlib,json,os,socket,subprocess,sys,time,types,unittest
from pathlib import Path
import authority
import guarded_nl

class Registry:
    pass
class Verified:
    pass
CAP=object()
class Identity:
    def __init__(self, wrong=False):self.wrong=wrong;self.calls=[]
    def _current_ids(self,*args):pass
    def _secure_source(self,path,digest):
        assert path == Path(sys.argv[0]) and len(digest)==64
    def authenticate(self,channel,**kwargs):
        self.calls.append(kwargs)
        return {'pid':os.getpid(),'start_ticks':guarded_nl.startticks(os.getpid()),
                'control_group':'wrong' if self.wrong else '/test.scope',
                'pidfd':os.pidfd_open(os.getpid(),0)}
class FakeNL:
    canon=staticmethod(lambda x:(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode())
    startticks=staticmethod(guarded_nl.startticks)
    def fdinfo(self,pid,fd):
        return {'prog_id':str(fd+100)} if fd in (10,20) else {'map_id':str(fd+200),'frozen':'1'}
    def map_rows(self,mid):return [(bytes([mid%256])*12,time.monotonic_ns()+20_000_000_000)]
class Reference:
    def verify(self,prog,mid):pass

class IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.sock,self.peer=socket.socketpair()
        self.nl=FakeNL();self.nlsock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);self.nlsock.bind((0,0));self.nlsock.settimeout(5)
        self.reg=Registry();self.reg.pid=os.getpid();self.reg.cache=object()
        self.reg.prep={'pid':os.getpid(),'start_ticks':guarded_nl.startticks(os.getpid()),'unit':'test.service','invocation_id':'test','control_group':'/test.scope'}
        self.reg._preparer_live=lambda:None;self.reg.reference=Reference()
        self.v=Verified();self.v.capability=CAP;self.v.guardian_pid=os.getpid();self.v.reader_cache=self.reg.cache;self.v.sender_pidfd=os.pidfd_open(os.getpid(),0)
        self.v.anchor={'pid':os.getpid(),'start_ticks':self.reg.prep['start_ticks'],'netns':os.readlink('/proc/self/ns/net')}
        self.identity=Identity()
        self.identity_argv=Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
        self.assertEqual(self.identity_argv[:2],['/usr/bin/python3','-B'])
        self.verifier=types.SimpleNamespace(_VerifiedGeneration=Verified,_VERIFIED_CAPABILITY=CAP)
        self.registry_module=types.SimpleNamespace(GuardianRefreshRegistry=Registry)
        self.authority=None
    def tearDown(self):
        if self.authority is not None:self.authority.close()
        else:self.sock.close()
        self.peer.close();self.nlsock.close();os.close(self.v.sender_pidfd)
    def create(self, identity=None):
        self.authority=authority.SenderRegistryAuthority(self.sock,registry=self.reg,registry_module=self.registry_module,
            verified=self.v,verifier=self.verifier,identity=identity or self.identity,nl=self.nl,
            sender_argv=self.identity_argv,sender_sha256='a'*64,validate_kernel=lambda _:None)
        return self.authority
    def test_authenticate_same_service_exactly(self):
        obj=self.create();self.assertEqual(len(self.identity.calls),1)
        call=self.identity.calls[0];self.assertEqual(call['expected_argv'],self.identity_argv)
        self.assertEqual(call['unit'],'test.service');self.assertEqual(obj.sender,os.getpid())
    def test_identity_mismatch_rejected(self):
        with self.assertRaisesRegex(authority.Held,'SAME_ORIGINAL_CONTROLLER_IDENTITY'):self.create(Identity(wrong=True))
    def attest(self, drift):
        obj=self.create();generation=guarded_nl.genid(self.nlsock)
        rows={'inbound':[(b'a'*12,time.monotonic_ns()+20_000_000_000)],'reverse':[(b'b'*12,time.monotonic_ns()+20_000_000_000)]}
        records=[{'program_fd':10,'program_id':110,'map_fd':11,'map_id':211}, {'program_fd':20,'program_id':120,'map_fd':21,'map_id':221}]
        self.nl.map_rows=lambda mid:rows['inbound' if mid==211 else 'reverse']
        self.v.actual=rows;self.v.result={'after':generation,'programs':records}
        receipt_hash=hashlib.sha256(self.nl.canon(self.v.result)).hexdigest()
        maps={role:[[key.hex(),val] for key,val in sorted(items)] for role,items in rows.items()}
        request={'schema':'lab_positive_generation_attest_request_v1','nonce':'a'*64,'sender_pid':os.getpid(),
          'sender_start_ticks':self.reg.prep['start_ticks'],'genid':generation,'receipt_sha256':receipt_hash,
          'ids':[[110,211],[120,221]],'map_digest':hashlib.sha256(self.nl.canon(maps)).hexdigest(),
          'until_ns':time.monotonic_ns()+10_000_000_000}
        seen=[]
        def snapshot(_):
            if drift and seen:subprocess.run(['/usr/sbin/nft','add','table','ip','ci_drift'],check=True)
            current=guarded_nl.genid(self.nlsock);seen.append(current)
            return {'observation':{'genid':current,'receipt_sha256':receipt_hash,'kernel_min_deadline_ns':time.monotonic_ns()+15_000_000_000},'invalidation_epoch':4}
        obj.validate_kernel=snapshot;sent=[];obj._send=sent.append
        if drift:
            with self.assertRaisesRegex(authority.Held,'STABLE_POSITIVE_KERNEL_AND_SOURCE'):obj.attest_current(request)
            self.assertNotEqual(seen[0],seen[1]);self.assertEqual(sent,[])
        else:
            obj.attest_current(request);self.assertEqual(seen,[generation,generation]);self.assertEqual(len(sent),1)
            self.assertFalse(sent[0]['external_effect_authorized'])
    def test_positive_attestation(self):self.attest(False)
    def test_real_nft_genid_drift_rejected(self):self.attest(True)
if __name__=='__main__':unittest.main(verbosity=2)
