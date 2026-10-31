"""Actual legacy cached_cycle and Guardian kernel read, disposable nft netns.

The cache, owner and deployment-specific compiled AST pin are fixtures. This
exercises real controller/native process and Guardian methods, not BPF service
integration or production authority.
"""
import hashlib,importlib.util,json,os,subprocess,sys,tempfile,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'runtime'))
import controller,native_io,native_structure,nft_owner as nft
spec=importlib.util.spec_from_file_location('test_guardian',HERE/'network_guardian.py');guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('test_coverage',HERE/'coverage.py');coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)
def cmd(*args,inp=None):return subprocess.run(args,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10).stdout

def endpoints(suffix):
    now=time.monotonic()
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+20,'synthetic') for k,a in
       [('core','10.244.1.'+str(suffix)),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    prom=nft.PrometheusSource('10.244.1.9',now,now+20,'synthetic')
    return entries,[entries[0]],[prom]
class Cache:
    def __init__(self):self.rows=endpoints(1);self.key='initial'
    def commit_snapshot(self):return ((*self.rows,{},1),self.key,1)
class Ownership:
    def permit_original_send(self,lease,started):
        assert not lease.dispatched
        lease.dispatched=True

def cycle(cache,previous):
    original=nft.owned_table_snapshot();token=nft.revalidate_owned_ruleset(original)
    lease=types.SimpleNamespace(token=token,dispatched=False)
    result,key=controller.cached_cycle(types.SimpleNamespace(cache=cache),lease,Ownership(),apply=lambda:True,previous_key=previous)
    return result,key,lease

def main():
    assert os.geteuid()==0
    native_io.ROOT=HERE/'custody';native_io.ROOT.mkdir(mode=0o700)
    native_io.configure();native_io.end_initialization()
    cmd('/usr/sbin/nft','-f','-',inp=nft.render((),now=time.monotonic(),table_exists=False).encode())
    raw=cmd('/usr/sbin/nft','-a','-j','list','ruleset');owned,_=native_structure._objects(raw)
    expected=hashlib.sha256(native_structure._structure(owned,keep_handles=False)).hexdigest()
    assert len(owned)==47
    guardian.RUNTIME=HERE/'runtime';guardian.RUNTIME_HASHES['nft_owner.py']=hashlib.sha256((guardian.RUNTIME/'nft_owner.py').read_bytes()).hexdigest()
    observer=guardian.Owner.__new__(guardian.Owner)
    observer.C=types.SimpleNamespace(_objects=native_structure._objects,_structure=native_structure._structure,AST47=expected)
    observer.coverage=coverage
    observer.call=lambda name,args:cmd(*args)
    cache=Cache();one,key,lease=cycle(cache,None)
    assert one['applied'] and lease.dispatched and key=='initial'
    snapshot,_=observer.kernel();assert snapshot['all_four_backends_and_reverse_sources_positive']
    same,key,silent=cycle(cache,key);assert same is None and not silent.dispatched
    old_native=native_io.process.native;calls=[]
    def ambiguous(*args,**kwargs):
        value=old_native(*args,**kwargs)
        if args[0]==['/usr/sbin/nft','-f','-']:
            calls.append(1)
            raise native_io.process.Held('CI_INJECT_AFTER_NATIVE_COMPLETED')
        return value
    native_io.process.native=ambiguous
    cache.rows=endpoints(2);cache.key='uncertain'
    try:
        try:cycle(cache,key);raise AssertionError('unknown effect reported success')
        except nft.Held as e:assert str(e)=='CI_INJECT_AFTER_NATIVE_COMPLETED'
    finally:native_io.process.native=old_native
    assert len(calls)==1
    uncertain=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network');assert b'10.244.1.2' in uncertain
    # External genid advance and a NEW observation produce a distinct transaction.
    # CI owns this entire namespace and no other mutator. This does not establish
    # those prerequisites or any receipt/attachment truth in production.
    cmd('/usr/sbin/nft','add','table','ip','ci_unrelated')
    cache.rows=endpoints(3);cache.key='new-observation'
    new,newkey,newlease=cycle(cache,key);assert new['applied'] and newlease.dispatched and newkey=='new-observation'
    fresh=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
    assert b'10.244.1.3' in fresh and b'10.244.1.2' not in fresh
    snapshot,_=observer.kernel();assert snapshot['all_four_backends_and_reverse_sources_positive']
    print('PASS actual cached_cycle/native nft, Guardian.kernel, unknown effect no replay, fresh distinct reconciliation',flush=True)
    print('BOUNDARY: private CI namespace; cache, owner and compiled AST pin are fixtures; legacy relative TTL',flush=True)
    # Experiment with the actual LAB 47->50 sender, fixed to this CI namespace.
    # The CI fixture supplies observation/lease authority and is not a service.
    import guarded_nl as nl, guarded_generation as generation, transition_structure_DRAFT as trans
    native_structure.COMPILED_NATIVE_AST_SHA256=expected
    raw=cmd('/usr/sbin/nft','-a','-j','list','ruleset')
    original=trans.OriginalPin(raw)
    records=[];first=None;recovery=None
    try:
        now=time.monotonic_ns();expiry=now+15_000_000_000
        maps={'inbound':[('01'*12,expiry)],'reverse':[('02'*12,expiry)]}
        for role in ('inbound','reverse'):records.append(nl.make_program(maps[role]))
        rows,cores,prom=cache.rows
        def encode(row):return {'kind':getattr(row,'kind','prom'),'address':row.address,'port':getattr(row,'port',0),'deadline':int(row.expires*1e9)}
        plan={'maps':maps,'backends':[encode(x) for x in rows],'cores':[encode(x) for x in cores],'prom':[encode(x) for x in prom]}
        receipts=HERE/'receipts';receipts.mkdir(mode=0o700)
        first=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts,host_netns=os.environ['CI_HOST_NETNS'])
        transferred=records;records=[]
        emitted=first.submit(plan,transferred)
        assert emitted['ok'] and first.state=='AWAITING_FIXTURE_VERIFICATION'
        try:first.submit(plan,[]);raise AssertionError('unverified generation allowed another send')
        except RuntimeError as e:assert str(e)=='ONLY_READY_SAME_OWNER'
        # Independently changed foreign nft object: never infer that the old
        # receipt proves the present generation. The diagnostic recovery sender
        # is distinct and submits a deny-only batch using fresh expired maps.
        cmd('/usr/sbin/nft','add','table','ip','ci_foreign_after_50')
        recovery=generation.GenerationEmitter(initial_raw=raw,transition=trans,receipt_dir=receipts,
                                               host_netns=os.environ['CI_HOST_NETNS'],recover_fixture=True)
        deny_maps={'inbound':[('03'*12,1)],'reverse':[('04'*12,1)]}
        for role in ('inbound','reverse'):records.append(nl.make_program(deny_maps[role]))
        transferred=records;records=[]
        denied=recovery.submit({'maps':deny_maps,'backends':[],'cores':[],'prom':[]},transferred)
        assert denied['ok'] and denied['genid']!=emitted['after'] and denied['wire_sha256']!=emitted['wire_sha256']
        text=cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
        observed=coverage.kernel_text(text)
        assert all(not values for values in observed['dynamic_collections'].values())
        print('PASS actual BPF-backed 47-to-50 sender, unverified hold, foreign genid and distinct deny-only fenced transaction',flush=True)
        print('BOUNDARY: fake authority and AST; deny-only recovery, not live Guardian or positive recovery',flush=True)
    finally:
        for rec in records:
            os.close(rec['program_fd']);os.close(rec['map_fd'])
        if recovery is not None:recovery.close_private_fixture()
        if first is not None:first.close_private_fixture()
if __name__=='__main__':main()
