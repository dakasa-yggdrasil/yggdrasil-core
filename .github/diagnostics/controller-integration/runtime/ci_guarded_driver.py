"""CI-only driver connecting serve_hot to an independent Guardian service.

A bounded test fixture, not installed service configuration or production
authority. Any exception aborts the loop; no uncertain send is retried.
"""
import os,time
import guarded_preparation,guarded_sources,native_structure

class GuardedDriver:
    def __init__(self,*,watch,sender,emitter,positive_session,ceiling_cache,endpoints,max_commits):
        if os.environ.get('CI_GUARDED_FIXTURE')!='1' or type(max_commits) is not int or not 1<=max_commits<=(4 if os.environ.get('CI_HOLDER_TEST')=='1' else 3):
            raise RuntimeError('ONLY_BOUNDED_PRIVATE_CI_DRIVER')
        self.watch,self.sender,self.emitter,self.positive_session=watch,sender,emitter,positive_session
        self.ceiling_cache,self.endpoints,self.max_commits=ceiling_cache,endpoints,max_commits
        self.results=[];self.pause_started=None
    def prepare(self,cache):
        rows,_,_,_,_=cache.snapshot()
        core=next(x for x in rows if x.kind=='core')
        witness=self.watch.admission_witness(core.native_identity.split('/',1)[0],core.address)
        if witness.get('event')!='ADMISSION_HOLD' or witness.get('guard')!='GUARDED_INTENT_PENDING':
            raise RuntimeError('PENDING_INTENT_MUST_BLOCK_ADMISSION:'+str(witness))
        expected=guarded_sources.build_expected(self.ceiling_cache)
        prepared=guarded_preparation.PreparedGeneration(cache,
                    deadline_ceilings={role:expected[role] for role in ('inbound','reverse')})
        try:
            descriptors=prepared.fixture_descriptors(cache)
            self.watch.prepare(descriptors)
            permit=self.sender.prepare(list(descriptors),until_ns=time.monotonic_ns()+3_000_000_000)
            return prepared,permit
        except BaseException:
            prepared.close();raise
    def begin_handoff(self):
        self.pause_started=time.monotonic();self.watch.pause()
    def confirm(self,handoff,owner,lease,pin,started):
        result=handoff['native_result']
        confirmed=self.watch.confirm(result,handoff['submitted_plan'])
        if confirmed.get('same_guardian_successor_verified') is not True:raise RuntimeError('GUARDIAN_CONFIRMATION_REQUIRED')
        attestation=self.sender.attest_current(self.emitter.receipt,until_ns=time.monotonic_ns()+8_000_000_000)
        new_pin=native_structure.accept_lab_positive_guarded(self.positive_session,self.emitter,attestation,previous_pin=pin)
        self.emitter.activate_lab_guarded_pin(new_pin)
        owner.adopt_lab_guarded_pin(pin,new_pin,lease)
        lease_age=(result['send_started_ns']-int(lease.token.returned*1e9))/1e6
        dispatch=(result['send_started_ns']-started)/1e6
        if not (0<=lease_age<750 and 0<=dispatch<250):raise RuntimeError('ORIGINAL_GUARDED_BUDGETS')
        self.results.append({'native_result':result,'lease_age_ms':lease_age,'dispatch_ms':dispatch})
        return new_pin
    def finish(self,reader):
        self.watch.resume()
        self.results[-1]['watch_pause_ms']=(time.monotonic()-self.pause_started)*1000
        if len(self.results)>=self.max_commits:
            reader.stop.set();return
        # Holder qualification uses the original 15-second chain, never a fake clock.
        if os.environ.get('CI_HOLDER_TEST')=='1':time.sleep(5.2)
        # One synthetic new topology observation wakes the real cache loop.
        entries,cores,prom=self.endpoints(4)
        reader.cache.publish_topology(([x for x in entries if x.kind in ('core','broker')],cores,prom,{},frozenset(),time.monotonic()+(65 if os.environ.get('CI_HOLDER_TEST')=='1' else 25)))
