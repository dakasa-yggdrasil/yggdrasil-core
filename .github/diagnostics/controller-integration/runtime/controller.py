"""Brain-only fixed WireGuard backend owner. No action occurs on import.

Default --check-once performs original GETs and native nft -c only. --run is an
explicit Root deployment action requiring a sealed root-private configuration.
No Guest or remote caller can submit endpoints, rules, authority or refreshes.
"""

# LAB-only execution on dedicated disposable host.
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

import dns_native
import kube_native
import nft_owner as nft
import observations
import native_structure
import native_io
import transition_adoption as transition
import whole_witness as whole
import drain_marker_v3_DRAFT as drain_v3

# CI-only injection. No default path or production authority.
CI_DRAIN_COORDINATION = None

def _ci_drain():
    nft.require(os.environ.get('CI_GUARDED_FIXTURE')=='1'
                and type(CI_DRAIN_COORDINATION) is drain_v3.CoordinatorV3,
                'ONLY_BOUND_CI_DRAIN_COORDINATOR')
    return CI_DRAIN_COORDINATION

PREFIX = Path('/opt/dakasa/capacity-network')
STATE = Path('/run/dakasa-capacity-network')
CONNTRACK = Path('/var/tmp/dakasa-two-cluster-b5c117ab7f94221f3de4/brain-data/data/d76b59b2203578bb4cb3438338ccad2f0d3e194bef799a8957f21430b7d5f1e3/bin/conntrack')
CONNTRACK_SHA256 = '30c657ecd884277883ef04b09a9d69e66f1c3beaf3927babe8c949cddc320055'
FIELDS = {'schema', 'execute', 'source_files_sha256', 'eks_endpoint', 'eks_public_ca_base64', 'core_service_uid', 'core_container_images', 'lab_only', 'production_authority'}


def private(path, directory=False):
    s = path.lstat()
    nft.require(s.st_uid == 0 and not stat.S_IMODE(s.st_mode) & 0o077 and not path.is_symlink(), 'ROOT_PRIVATE_SOURCE')
    nft.require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'ROOT_SOURCE_TYPE')


def load_config(path, *, execute):
    private(path)
    raw = path.read_bytes()
    nft.require(len(raw) <= 32768, 'ROOT_CONFIG_BOUND')
    config = json.loads(raw)
    nft.require(set(config) == FIELDS and config['schema'] == 'lab_fixed_capacity_network_controller_v1' and type(config['execute']) is bool, 'CLOSED_ROOT_CONTROLLER_CONFIG_V5_EXACT_CORE_IMAGE_PAIRS')
    nft.require(not execute or config['execute'] is True, 'ROOT_EXECUTE_SEAL_REQUIRED')
    nft.require(config['lab_only'] is True and config['production_authority'] is False, 'ONLY_LOCAL_LAB_NO_PRODUCTION_AUTHORITY')
    names = {'controller.py', 'nft_owner.py', 'dns_native.py', 'kube_native.py', 'install_owned_once.py', 'brain_https.py', 'observations.py', 'native_structure.py', 'native_io.py', 'original_process.py', 'eks_https.py', 'whole_witness.py', 'transition_adoption.py'}
    nft.require(set(config['source_files_sha256']) == names, 'EXACT_SOURCE_PACKAGE')
    for name, expected in config['source_files_sha256'].items():
        source = Path(__file__).parent / name
        nft.require(not source.is_symlink() and hashlib.sha256(source.read_bytes()).hexdigest() == expected, 'ROOT_REVIEWED_SOURCE_HASH')
    uid = config['core_service_uid']
    nft.require(isinstance(uid, str) and re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', uid), 'CORE_SERVICE_UID')
    kube_native.approved_core_images(config)
    return config, hashlib.sha256(raw).hexdigest()


def ct_mark_preflight(table_exists):
    result = nft.command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_mark')
    nft.require(result.returncode == 0, 'NATIVE_MARK_RULE_READ')
    rules = json.loads(result.stdout)['nftables']
    nft.ruleset_mark_preflight(rules)
    if table_exists:
        return
    # On first ownership, no historical connection may already carry the new
    # reserved value. Raw connection tuples are neither printed nor persisted.
    source = Path('/proc/net/nf_conntrack')
    if source.exists():
        with source.open('rb') as f:
            raw = f.read(8 * 1024**2 + 1)
        nft.require(len(raw) <= 8 * 1024**2, 'NATIVE_CT_CENSUS_BOUND')
    else:
        native = CONNTRACK.lstat()
        nft.require(stat.S_ISREG(native.st_mode) and native.st_uid == 0 and not stat.S_IMODE(native.st_mode) & 0o022 and not CONNTRACK.is_symlink() and native.st_size == 195952, 'EXACT_EXISTING_K3S_CONNTRACK_FILE')
        nft.require(hashlib.sha256(CONNTRACK.read_bytes()).hexdigest() == CONNTRACK_SHA256, 'EXACT_EXISTING_K3S_CONNTRACK_SHA')
        reply = nft.command([str(CONNTRACK), '-L', '-o', 'extended'], timeout=3, role='ct_census')
        nft.require(reply.returncode == 0, 'NATIVE_CT_MARK_CENSUS_UNAVAILABLE')
        raw = reply.stdout
    target = int(nft.MARK, 16)
    nft.require(all(int(v) != target for v in re.findall(rb'\bmark=(\d+)\b', raw)), 'RESERVED_CT_MARK_ALREADY_PRESENT')


def route(item, previous=None):
    if type(item) is whole.OriginalZeroTTL:
        item.validate()
        nft.require(type(previous) is whole.CompleteWitness, 'ZERO_ROUTE_REQUIRES_PREVIOUS_WHOLE_POSITIVE')
        previous.validate()
        result = nft.command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', item.addresses[0]], role='route_' + item.kind)
        facts = native_io.last_facts()
        nft.require(result.returncode == 0, 'NATIVE_BACKEND_ROUTE')
        return whole.route_after_zero(previous, item, result.stdout, facts)
    if type(item) is whole.OriginalDNS:
        item.validate()
        result = nft.command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', item.addresses[0]], role='route_' + item.kind)
        facts = native_io.last_facts()  # SAME reader thread, before any other native call.
        nft.require(result.returncode == 0, 'NATIVE_BACKEND_ROUTE')
        return whole.route_from_original(item, result.stdout, facts)
    item.validate()
    result = nft.command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', item.address], role='route_' + item.kind)
    nft.require(result.returncode == 0, 'NATIVE_BACKEND_ROUTE')
    rows = json.loads(result.stdout)
    nft.require(len(rows) == 1 and rows[0].get('type', 'unicast') == 'unicast', 'NATIVE_UNICAST_ROUTE')
    if item.kind == 'core':
        nft.require(rows[0]['dev'] == 'cni0', 'CORE_MUST_REMAIN_LOCAL_POD_ROUTE')
    else:
        nft.require(rows[0]['dev'] == 'br-2980a83da24e' and rows[0].get('prefsrc') == '172.18.0.1', 'EXACT_BRAIN_VPC_ROUTE')


def collect_topology(config, eks):
    entries, sources, prometheus_sources, errors = [], (), (), {}
    collisions, expires = kube_native.collision_snapshot()
    try:
        item, sources = kube_native.core(config, collisions, expires)
        for source in sources:
            route(source)
        entries.append(item)
    except Exception as error:
        errors['core'], sources = type(error).__name__, ()
    try:
        prometheus_sources = kube_native.prometheus(collisions, expires)
        for source in prometheus_sources:
            source.validate()
            result = nft.command(['/usr/sbin/ip', '-j', '-4', 'route', 'get', source.address], role='route_prometheus')
            nft.require(result.returncode == 0, 'NATIVE_PROMETHEUS_POD_ROUTE')
            rows = json.loads(result.stdout)
            nft.require(len(rows) == 1 and rows[0].get('type','unicast') == 'unicast' and rows[0]['dev'] == 'cni0', 'PROMETHEUS_MUST_REMAIN_LOCAL_CNI_POD_ROUTE')
    except Exception as error:
        errors['prometheus'], prometheus_sources = type(error).__name__, ()
    try:
        item = eks.broker(collisions, expires)
        route(item)
        entries.append(item)
    except Exception as error:
        errors['broker'] = type(error).__name__
    return entries, sources, prometheus_sources, errors, frozenset(collisions), expires


def collect(config, eks):
    # Historical single-cycle check helper only. Production R11 uses the
    # independent original readers below; neither path renews an expiry.
    entries, sources, prometheus_sources, errors, collisions, expires = collect_topology(config, eks)
    # Read short-lived RDS/Redis DNS LAST. Kubernetes/auth/route reads consume
    # their own original evidence windows rather than the fresh DNS TTL5/15.
    # The actually observed shorter RDS TTL5 is read after Redis TTL15.
    for kind in ('redis', 'rds'):
        try:
            answer = dns_native.resolve(kind, collisions)
            original_route = route(answer)
            witness = whole.complete(answer, original_route, collisions, expires)
            entries.append(dns_native.backend(witness, collisions, expires))
        except Exception as error:
            errors[kind] = type(error).__name__
    return entries, sources, prometheus_sources, errors


def original_cycle(config, eks, *, apply):
    # The slow TEXT comment/handle bracket belongs before short DNS reads.
    # Same process, same controller lock; neither token is a wire/config input.
    snapshot = nft.owned_table_snapshot()
    if not snapshot.exists:
        ct_mark_preflight(False)
    collect_started = time.monotonic()
    try:
        entries, sources, prometheus_sources, errors = collect(config, eks)
    except Exception as error:
        entries, sources, prometheus_sources, errors = [], (), (), {'collision_census': type(error).__name__}
    collect_returned = time.monotonic()
    # One native full-ruleset read rechecks the SAME header/handle and all
    # external ct-mark owners after collection, before the unchanged batch.
    ownership = nft.revalidate_owned_ruleset(snapshot)
    result = nft.native_batch(entries, core_sources=sources, prometheus_sources=prometheus_sources,
                              apply=apply(), _ownership=ownership)
    result['held_native_read_classes'] = errors
    result['original_collect_elapsed_seconds'] = collect_returned - collect_started
    return result


class _RefreshSchedule:
    """Scheduling only; kernel authority remains the original applied batch.

    A skipped publication never advances the committed identity/key or the
    last actually installed conservative end. A completed full read with no
    new selected payload can be remembered only to avoid rereading the same
    scheduling facts; it never renews that end or an ownership token.
    """
    LEAD = 1.250

    def __init__(self):
        self.key = self.identity = self.installed_end = self.checked = None
        self.core_pending = False

    @staticmethod
    def stamp(view):
        return view[1], view[3], view[4], view[5]

    def due(self, view, now):
        if self.core_pending:
            return True
        if self.key is None or view[3] != self.identity:
            return True
        if (view[1] == self.key and self.checked is not None
                and self.checked[:2] == (view[1], view[3]) and view[4] >= self.checked[2]):
            return False
        if self.installed_end is None:
            return False  # no installed positive authority to refresh
        return now >= min(self.installed_end, view[4]) - self.LEAD

    def no_change(self, view):
        self.checked = self.stamp(view)

    def applied(self, view, result):
        if result['applied'] is not True:
            return
        if result.get('core_pending') is True:
            self.core_pending = True
            return
        self.core_pending = False
        start, end = result['render_started'], result['native_apply_returned']
        nft.require(type(start) in (int, float) and type(end) in (int, float)
                    and start <= end < start + .250,
                    'ORIGINAL_APPLIED_REFRESH_CLOCKS_FOR_SCHEDULING_ONLY')
        rows = (*result['backend_freshness'].values(),
                *result['core_source_freshness'], *result['prometheus_source_freshness'])
        timeouts = [x['kernel_timeout_ms'] for x in rows if x['kernel_timeout_ms'] > 0]
        nft.require(all(type(x) is int for x in timeouts), 'ORIGINAL_INTEGER_KERNEL_TIMEOUTS_FOR_SCHEDULING')
        self.key, self.identity = view[1], view[3]
        # The kernel can install after render. Starting its lower bound at
        # render is conservative; native_apply_returned + TTL would renew it.
        self.installed_end = None if not timeouts else start + min(timeouts) / 1000
        self.checked = None


def cached_cycle(reader, lease, ownership, *, apply, previous_key, schedule=None, transition_context=None):
    # An ORIGINAL full native validation ran in the same PID/lock before this
    # newest snapshot. Its exact one-use object and returned clock survive
    # the handoff; no caller/disk pin or reminted token exists.
    view = None if schedule is None else reader.cache.scheduling_snapshot()
    (entries,sources,prometheus_sources,errors,generation),key,revision = reader.cache.commit_snapshot() if view is None else view[:3]
    if key == previous_key and (schedule is None or (not schedule.core_pending and view[3] == schedule.identity)):
        if schedule is not None:
            schedule.no_change(view)
        return None,key  # no native call, token consumption, log or rewrite
    attempt_started=time.monotonic()
    if not transition.first_send_eligible(transition_context,entries,sources,prometheus_sources,errors,attempt_started):
        raise nft.NoSend('R37_WAIT_GENUINE_FULL_FRESH_SNAPSHOT_BEFORE_FIRST_SEND',attempt_started,time.monotonic())
    def original_apply():
        ownership.permit_original_send(lease,attempt_started)
        return apply()
    result = nft.native_refresh(entries, core_sources=sources, prometheus_sources=prometheus_sources,
                                apply=original_apply, _ownership=lease.token)
    result['held_native_read_classes'] = errors
    result['same_process_topology_generation'] = generation
    result['same_process_semantic_cache_revision'] = revision
    if schedule is not None:
        schedule.applied(view, result)
    return result,(previous_key if result.get('core_pending') is True else key)


def cached_guarded_cycle(reader, lease, ownership, *, emitter, prepared, apply,
                         previous_key, transition_origin=None, guardian_session=None,
                         guarded_pin=None, sender_session=None, sender_permit=None, drain_intent=None):
    """CI/LAB candidate: hand one stable cache generation to the BPF emitter.

    This method is not wired into serve_hot. Its returned key is *pending*:
    the caller must not commit it until an independent Guardian verifies and
    acknowledges the original receipt. Errors after a possible send escape;
    this function never retries an uncertain transaction.
    """
    import guarded_nl
    cache=reader.cache
    snapshot,key,revision=cache.commit_snapshot()
    if key == previous_key:
        return None,key
    entries,cores,prom,errors,generation=snapshot
    nft.require(not errors and len(entries)==4 and len(cores)>0 and len(prom)==1,
                'ONLY_FULL_GUARDED_CACHE_SNAPSHOT')
    if emitter.has_gates:
        nft.require(guarded_pin is not None and sender_session is not None and sender_permit is not None
                    and transition_origin is None and guardian_session is None,
                    'ORIGINAL_GUARDED_LEASE_PIN_AND_GUARDIAN_PERMIT_REQUIRED')
    else:
        nft.require(transition_origin is not None and guarded_pin is None
                    and sender_session is None and sender_permit is None
                    and guardian_session is not None,
                    'ORIGINAL_47_ORIGIN_AND_GUARDIAN_REQUIRED')
    descriptors=prepared.fixture_descriptors(cache)
    maps={role:[(item.hex(),deadline) for item,deadline in sorted(guarded_nl.map_rows(record['map_id']))]
          for role,record in zip(('inbound','reverse'),descriptors)}
    def encode(item):
        return {'kind':getattr(item,'kind','prom'),'address':item.address,
                'port':getattr(item,'port',0),'deadline':int(item.expires*1e9)}
    plan={'maps':maps,'backends':[encode(x) for x in entries],
          'cores':[encode(x) for x in cores],'prom':[encode(x) for x in prom]}
    newest,newest_key,newest_revision=cache.commit_snapshot()
    nft.require(newest_key==key and newest_revision==revision and newest==snapshot,
                'SAME_CACHE_SNAPSHOT_BEFORE_GUARDED_HANDOFF')
    core=[item for item in entries if item.kind=='core']
    nft.require(len(core)==1,'CI_ONE_CORE_FOR_DRAIN_BARRIER')
    # A durable exclusive intent blocks participating admission and writers
    # while Guardian prepare/send/ACK execute without holding flock.
    drain_permit=_ci_drain().barrier(drain_intent,core[0],cores)
    nft.require(apply() is True,'ORIGINAL_GUARDED_APPLY_REQUIRED')
    records=prepared.take_same_process_for_emitter(cache)
    if emitter.has_gates:
        result=emitter.submit(plan,records,guarded_lease=lease,guarded_owner=ownership,
                              guarded_pin=guarded_pin,sender_session=sender_session,sender_permit=sender_permit,
                              drain_permit=drain_permit)
    else:
        result=emitter.submit(plan,records,original_lease=lease,original_owner=ownership,
                              transition_origin=transition_origin,guardian_session=guardian_session,
                              drain_permit=drain_permit)
    # Keep the exact emitter return intact: its receipt bytes are validated
    # independently and must not acquire controller-only metadata.
    return {'native_result':result,'submitted_plan':plan,'same_process_topology_generation':generation,
            'same_process_semantic_cache_revision':revision,
            'guardian_receipt_acceptance_pending':True},key


def _retained_unused_cycle(reader, lease, ownership, *, apply, previous_key, schedule, transition_context=None):
    """Borrow ONE original token without renewing it while no payload changed.

    A cache-only no-op never consumed or dispatched this token. The exclusive
    lane remains borrowed until a real changed payload uses it, stop is seen,
    or its ORIGINAL quiet250 deadline expires. A later wake gets a fresh whole
    cache snapshot; neither clocks nor no-op reads move that deadline.
    """
    quiet_deadline = lease.token.returned + .250
    while not reader.stop.is_set():
        reader.cache.wake.clear()
        now = time.monotonic()
        # Match the quiet eligibility of take immediately BEFORE attempting
        # another cached cycle. The unchanged permit still fences hard750.
        if not 0 <= now - lease.token.returned < .250:
            return None, previous_key
        nft.require(not lease.dispatched and not lease.token.consumed,
                    'ONLY_UNUSED_ORIGINAL_OWNERSHIP_LEASE_MAY_WAIT')
        view = reader.cache.scheduling_snapshot()
        if schedule.due(view, now):
            # Cache-lock/scheduling work may itself outlast the quiet slot.
            if not 0 <= time.monotonic() - lease.token.returned < .250:
                return None, previous_key
            result, key = cached_cycle(reader, lease, ownership, apply=apply,
                                       previous_key=previous_key, schedule=schedule, transition_context=transition_context)
            if result is not None:
                return result, key
        remaining = quiet_deadline - time.monotonic()
        if remaining <= 0:
            return None, previous_key
        reader.cache.wake.wait(min(.050, remaining))
    return None, previous_key


def serve_hot(reader, pin, *, apply, initial_sequence=1, transition_context=None, guarded_driver=None):
    if guarded_driver is not None:
        return _serve_guarded_hot(reader,pin,apply=apply,driver=guarded_driver,initial_sequence=initial_sequence)
    # Only the original main thread commits. One independent full-ruleset
    # reader feeds original one-use tokens. It never writes a kernel batch.
    ownership=native_structure._OwnershipReader(pin,reader.stop,reader.cache.wake)
    ownership.start()
    sequence,discarded_total,last_discard_log=initial_sequence,0,None
    last_key,last_owner_error_log=None,None
    schedule = _RefreshSchedule()
    try:
        while not reader.stop.is_set():
            transition.require_transition_live(transition_context)
            reader.cache.wake.clear()
            view=reader.cache.scheduling_snapshot()
            if not schedule.due(view,time.monotonic()):
                # Only clocks changed while the last actual kernel window
                # has room. Its original end never moves on this skip.
                reader.cache.wake.wait(.050)
                continue
            handed,error=ownership.take()
            if handed is None:
                now=time.monotonic()
                if error is not None and (last_owner_error_log is None or now-last_owner_error_log>=1):
                    observations.emit_json({'schema':'capacity_original_ownership_reader_held_v1',**error,
                        'native_apply_started':False,'Core_or_VM_authority':False})
                    last_owner_error_log=now
                reader.cache.wake.wait(.050)
                continue
            lease,provenance=handed
            try:
                try:
                    result,committed_key=_retained_unused_cycle(reader,lease,ownership,apply=apply,previous_key=last_key,schedule=schedule,transition_context=transition_context)
                except nft.NoSend as error:
                    discarded_total += 1
                    nft.require(discarded_total <= (1 << 63)-1,'BOUNDED_PRE_SEND_DISCARD_COUNT')
                    now=time.monotonic()
                    if last_discard_log is None or now-last_discard_log>=1:
                        observations.emit_json({'schema':'capacity_owned_nft_refresh_discarded_before_send_v1',
                            'closed_guard':error.guard,'render_started':error.started,
                            'discarded_monotonic':error.discarded,'discarded_total':discarded_total,
                            'native_apply_started':False,'commit_sequence_unchanged':sequence,
                            'next_iteration_requires_new_ownership_and_original_cache_snapshot':True,
                            'Core_or_VM_authority':False})
                        last_discard_log=now
                    reader.stop.wait(.050)
                    continue
            finally:
                ownership.release(lease)
            if result is None:
                continue
            # No generic Held/native error is caught. Unknown apply remains
            # fatal and is never retried. A pure discard never bumps sequence.
            sequence += 1
            nft.require(sequence <= (1 << 63)-1,'BOUNDED_ORIGINAL_COMMIT_SEQUENCE')
            result['commit_sequence']=sequence
            result['pre_send_discarded_total']=discarded_total
            result['original_ownership_handoff']=provenance
            result['sampled_DNS_diagnostic_reference']=reader.cache.dns_diagnostic_reference()
            if result['applied'] is True:
                last_key=committed_key
            observations.emit_json(result)
            if result.get('core_pending') is True:
                reader.stop.wait(.250)
                continue
            closure=transition.close_after_first_fresh_commit(transition_context,result)
            if closure is not None:observations.emit_json(closure)
    finally:
        # Shared original stop deadline; the caller subsequently joins the
        # three observation readers with the SAME clock, never a new window.
        reader.stop.set();reader.cache.wake.set()
        ownership.close_join(reader.shutdown_deadline())


def _serve_guarded_hot(reader, pin, *, apply, driver, initial_sequence=1):
    """CI/LAB continuous caller: failures propagate and are never replayed.

    Guardian/driver custody is required throughout. The caller must perform
    distinct reconciliation after an unknown send. This path is not wired
    into the production entrypoint and grants no remote-effect authority.
    """
    import ci_guarded_driver
    nft.require(type(driver) is ci_guarded_driver.GuardedDriver and os.environ.get('CI_GUARDED_FIXTURE')=='1',
                'ONLY_BOUNDED_CI_GUARDED_DRIVER')
    owner=native_structure._OwnershipReader(pin,reader.stop,reader.cache.wake);owner.start()
    sequence=initial_sequence;last_key=None;installed_until=None
    try:
        while not reader.stop.is_set():
            # Stop only between handoffs. An in-flight transaction must still
            # reach confirmation or retain its uncertain marker.
            if driver.stop_signal is not None and driver.stop_signal.is_set():
                reader.stop.set();break
            _snapshot,key,_revision=reader.cache.commit_snapshot()
            now=time.monotonic()
            if key==last_key and installed_until is not None and now<installed_until-1.250:
                reader.cache.wake.wait(min(.05,max(0,installed_until-1.250-now)));reader.cache.wake.clear();continue
            prepared=None;lease=None
            # This must precede watch.prepare and SenderSession.prepare:
            # either can register an externally uncertain operation.
            current,_,_=reader.cache.commit_snapshot()
            before_entries,before_cores,_,_,_=current
            before_core=[item for item in before_entries if item.kind=='core']
            nft.require(len(before_core)==1,'CI_ONE_CORE_FOR_DRAIN_INTENT')
            intent=_ci_drain().begin(before_core[0],before_cores,writer_lease=driver.emitter.writer_lease)
            _ci_drain().barrier(intent,before_core[0],before_cores)
            try:
                prepared,permit=driver.prepare(reader.cache)
                driver.begin_handoff()
                deadline=time.monotonic()+5
                while lease is None and not reader.stop.is_set() and time.monotonic()<deadline:
                    handed,error=owner.take()
                    if handed is None:reader.cache.wake.wait(.05);reader.cache.wake.clear()
                    else:lease=handed[0]
                nft.require(lease is not None,'GUARDED_OWNERSHIP_NOT_AVAILABLE_WITHIN_BUDGET')
                started=time.monotonic_ns()
                # A due refresh may use the same semantic key; it still needs
                # a fresh prepared generation and the same original deadline.
                handoff,new_key=cached_guarded_cycle(reader,lease,owner,emitter=driver.emitter,
                    prepared=prepared,apply=apply,previous_key=None,guarded_pin=pin,
                    sender_session=driver.sender,sender_permit=permit,drain_intent=intent)
                nft.require(handoff is not None,'GUARDED_REFRESH_NOT_DISPATCHED')
                pin=driver.confirm(handoff,owner,lease,pin,started)
                _ci_drain().finish(intent,pin,handoff['native_result'])
                last_key=new_key;sequence+=1
                deadlines=[value for rows in handoff['submitted_plan']['maps'].values() for _key,value in rows]
                nft.require(deadlines and all(type(x) is int for x in deadlines),'BOUNDED_GUARDED_DEADLINES')
                installed_until=min(deadlines)/1e9
                driver.finish(reader)
            finally:
                if lease is not None:owner.release(lease)
                if prepared is not None:prepared.close()
    finally:
        reader.stop.set();reader.cache.wake.set();owner.close_join(reader.shutdown_deadline())
    return {'last_key':last_key,'pin':pin,'sequence':sequence,'production_authority':False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-once', action='store_true')
    mode.add_argument('--run', action='store_true')
    a = p.parse_args()
    nft.require(os.geteuid() == 0, 'BRAIN_ROOT_OWNER_ONLY')
    config, config_sha = load_config(a.config, execute=a.run)
    fd = None
    if a.run:
        private(STATE, True)
        fd = os.open(STATE / 'controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    kube_native.initialize_brain_client()
    eks = kube_native.EKS(config)
    reader = observations.Readers(lambda: collect_topology(config, eks), dns_native.resolve, route)
    stopped_at = None
    def shutdown_deadline():
        stop()
        return stopped_at + 4
    reader.shutdown_deadline = shutdown_deadline
    def stop(*_):
        nonlocal stopped_at
        if stopped_at is None:
            stopped_at = time.monotonic()
        reader.stop.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        # Cold absent tables get a genuine empty create/echo. Existing exact
        # owned47 tables are READ-adopted, preserving handles/maps/residualTTL.
        # Explicit Root transition connectivity grants no observation credit.
        native_io.configure()
        snapshot = nft.owned_table_snapshot()
        if not snapshot.exists:
            ct_mark_preflight(False)
        ownership = nft.revalidate_owned_ruleset(snapshot)
        initialized, pin, transition_context = transition.initialize(
            apply=lambda: a.run and not reader.stop.is_set(), _ownership=ownership,
            config_sha=config_sha)
        sequence = 0 if initialized['schema']==transition.ADOPTION_SCHEMA else 1
        initialized['commit_sequence'] = sequence
        initialized['held_native_read_classes'] = {}
        initialized['same_process_topology_generation'] = 0
        observations.emit_json(initialized)
        if reader.stop.is_set():
            return
        # The hot source-controlled flush/add grammar is checked once. Empty
        # initial input is sufficient to verify all four exact names/types;
        # the typed renderer admits no caller-supplied rule/port/role text.
        nft.check_refresh_template((), core_sources=(), prometheus_sources=())
        native_io.end_initialization()
        if a.run:
            nft.require(pin is not None, 'ORIGINAL_SAME_PROCESS_STRUCTURE_PIN_REQUIRED')
        reader.start()
        warm_deadline = time.monotonic() + 30
        while not reader.stop.is_set():
            entries, cores, prom, _, _ = reader.cache.snapshot()
            now = time.monotonic()
            if len(entries) == 4 and len(cores) >= 1 and len(prom) == 1 and all(
                    nft._kernel_remaining(x.expires, now, True, reserve_seconds=.250) > 0
                    for x in (*entries, *cores, *prom)):
                break
            nft.require(now < warm_deadline, 'ORIGINAL_R11_COLD_READ_WINDOW_NOT_RENEWED')
            reader.stop.wait(.050)
        if reader.stop.is_set():
            return
        if a.check_once:
            # Original check path performs no source-controlled apply and
            # therefore cannot create a native apply echo or positive coverage.
            entries, cores, prom, errors, generation = reader.cache.snapshot()
            nft.check_refresh_template(entries, core_sources=cores, prometheus_sources=prom)
            observations.emit_json({'schema':'root_R11_static_empty_and_current_readonly_check_v1',
                'applied':False,'backends':sorted(x.kind for x in entries),
                'held_native_read_classes':errors,'same_process_topology_generation':generation,
                'core_native_identities':[x.native_identity for x in cores],
                'prometheus_sources':len(prom),'host_continuity_qualified':False})
            return
        serve_hot(reader, pin, apply=lambda: a.run and not reader.stop.is_set(), initial_sequence=sequence, transition_context=transition_context)
    finally:
        stop()
        try:
            reader.close_join(stopped_at + 4)
        finally:
            if fd is not None:
                os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if isinstance(error,(nft.Held,native_io.process.Held,transition.Held)) and re.fullmatch('[A-Z0-9_]{1,160}', str(error)) else 'ORIGINAL_R11_HELD_OR_UNCERTAIN'
        observations.emit_json({'status': 'HOLD', 'closed_guard': reason, 'error_class':type(error).__name__, 'last_original_native_facts':native_io.last_facts(), 'no_unknown_native_apply_replay': True})
        raise SystemExit(78) from None
