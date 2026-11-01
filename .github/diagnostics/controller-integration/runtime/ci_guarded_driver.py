"""CI-only driver connecting serve_hot to an independent Guardian service.

A bounded test fixture, not installed service configuration or production
authority. Any exception aborts the loop; no uncertain send is retried.
"""
import os,time,threading
import guarded_preparation,guarded_sources,native_structure

def bounded_guardian_ceilings(watch,cache):
    expected=guarded_sources.build_expected(cache)
    remote=watch.source_ceilings()
    if remote.get('production_authority') is not False:raise RuntimeError('CI_CEILING_ONLY')
    for role in ('inbound','reverse'):
        rows=remote['maps'][role];ceilings={bytes.fromhex(k):v for k,v in rows}
        if len(rows)!=len(ceilings) or set(ceilings)!=set(expected[role]) or any(type(v) is not int for v in ceilings.values()):
            raise RuntimeError('EXACT_INDEPENDENT_GUARDIAN_CEILINGS_REQUIRED')
        expected[role]={k:min(v,ceilings[k]) for k,v in expected[role].items()}
    return expected

class GuardedDriver:
    def __init__(self,*,watch,sender,emitter,positive_session,ceiling_cache,endpoints,max_commits,stop_signal=None):
        continuous=os.environ.get('CI_CONTINUOUS_TEST')=='1'
        limit=12 if continuous else (4 if os.environ.get('CI_HOLDER_TEST')=='1' else 3)
        if (os.environ.get('CI_GUARDED_FIXTURE')!='1' or type(max_commits) is not int or not 1<=max_commits<=limit
                or (continuous and (os.environ.get('CI_HOLDER_TEST')!='1' or type(stop_signal) is not type(threading.Event())))
                or (not continuous and stop_signal is not None)):
            raise RuntimeError('ONLY_BOUNDED_PRIVATE_CI_DRIVER')
        self.watch,self.sender,self.emitter,self.positive_session=watch,sender,emitter,positive_session
        self.ceiling_cache,self.endpoints,self.max_commits=ceiling_cache,endpoints,max_commits
        self.results=[];self.pause_started=None;self.stop_signal=stop_signal;self.previous_expiry_ns=None;self.pre_intent_waits=0
    def prepare(self,cache):
        rows,_,_,_,_=cache.snapshot()
        core=next(x for x in rows if x.kind=='core')
        witness=self.watch.admission_witness(core.native_identity.split('/',1)[0],core.address)
        if witness.get('event')!='ADMISSION_HOLD' or witness.get('guard')!='GUARDED_INTENT_PENDING':
            raise RuntimeError('PENDING_INTENT_MUST_BLOCK_ADMISSION:'+str(witness))
        expected=(bounded_guardian_ceilings(self.watch,self.ceiling_cache) if self.stop_signal is not None
                  else guarded_sources.build_expected(self.ceiling_cache))
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
        completed_ns=time.monotonic_ns()
        if self.previous_expiry_ns is not None and completed_ns>=self.previous_expiry_ns:
            raise RuntimeError('PREVIOUS_KERNEL_WINDOW_EXPIRED_BEFORE_CONFIRMED_REFRESH')
        deadlines=[value for rows in handoff['submitted_plan']['maps'].values() for _,value in rows]
        if not deadlines or min(deadlines)<=completed_ns:raise RuntimeError('NEW_KERNEL_WINDOW_ALREADY_EXPIRED')
        self.previous_expiry_ns=min(deadlines)
        self.results.append({'native_result':result,'lease_age_ms':lease_age,'dispatch_ms':dispatch,
                             'confirmed_ns':completed_ns,'minimum_deadline_ns':self.previous_expiry_ns})
        return new_pin
    def finish(self,reader):
        self.watch.resume()
        self.results[-1]['watch_pause_ms']=(time.monotonic()-self.pause_started)*1000
        if self.stop_signal is not None:
            if self.stop_signal.wait(5.2):reader.stop.set();return
            if len(self.results)>=self.max_commits:raise RuntimeError('CI_CONTINUOUS_BOUND_REACHED_WITHOUT_STOP')
            return
        if len(self.results)>=self.max_commits:
            reader.stop.set();return
        # Holder qualification uses the original 15-second chain, never a fake clock.
        if os.environ.get('CI_HOLDER_TEST')=='1':time.sleep(5.2)
        # One synthetic new topology observation wakes the real cache loop.
        entries,cores,prom=self.endpoints(4)
        reader.cache.publish_topology(([x for x in entries if x.kind in ('core','broker')],cores,prom,{},frozenset(),time.monotonic()+(35 if os.environ.get('CI_HOLDER_TEST')=='1' else 25)))
