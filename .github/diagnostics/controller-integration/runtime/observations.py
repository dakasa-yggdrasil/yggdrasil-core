"""Same-process fixed-size original observations; copying never renews expiry.

The callbacks are compiled private controller functions, never wire/config
selectors. Only the single controller main thread can commit nft batches.
"""
import math
from collections import deque
import json
import re
import threading
import time

from nft_owner import Backend, Held, PrometheusSource, MAX_FRESH_SECONDS, ipv4, require
import dns_native
import native_io
import whole_witness as whole

TOPOLOGY_INTERVAL = 5.0
DNS_INTERVAL = .050
DNS_FAR_INTERVAL = .250
DNS_URGENT_SECONDS = 1.250
DNS_DIAGNOSTIC_BYTES = 512 * 1024
DNS_DIAGNOSTIC_LINE_BYTES = 4096
DNS_DIAGNOSTIC_INTERVAL = 2.0
MAX_SEQUENCE = (1 << 63) - 1
_OUTPUT_LOCK = threading.Lock()


def emit_json(value):
    # All same-process controller/reader lines use one output lock. Original
    # payloads, TLS bytes and raw DNS wires never enter these diagnostics.
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    with _OUTPUT_LOCK:
        print(raw, flush=True)


DNS_DIAGNOSTIC_COLUMNS = ('attempt_sequence', 'outcome', 'DNS_started',
    'DNS_returned', 'TTL_seconds', 'original_DNS_expiry', 'route_native_sequence',
    'route_original_started', 'route_original_returned', 'publication_returned',
    'selected_original_expiry', 'selected_original_DNS_started',
    'same_prior_whole_retained', 'error_class_or_guard')


def dns_error(error):
    # Only compiled Held guard codes; never repr/args/free text from sockets,
    # Unicode errors, native stderr or external response contents.
    name = type(error).__name__
    if isinstance(error, (Held, whole.Held)) and re.fullmatch('[A-Z0-9_]{1,72}', str(error)):
        return name + ':' + str(error)
    return name


class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.generation = 0
        self.guard_invalidation_epoch = 0
        self.guard_recovery_epoch = 0  # CI draft: changes when an explicit error clears
        self.collisions = frozenset()
        self.collision_expires = 0
        self.entries, self.core_sources, self.prometheus = (), (), ()
        self.dns = {'rds': None, 'redis': None}
        # Scheduling facts only. Selection/rendering still uses self.dns and
        # the exact R20 whole.select_complete rules. A fresh shorter positive
        # must be visible to the scheduler even when selection retains the
        # prior complete positive object with its original later expiry.
        self._latest_positive = {'rds': None, 'redis': None}
        self.errors = {'collision_census': 'OriginalObservationPending'}
        self.topology_returned = None
        self.wake = threading.Event()
        self.revision = 0
        self._dns_diagnostics = {kind: deque(maxlen=32) for kind in ('rds', 'redis')}
        self._dns_attempt_sequence = {'rds': 0, 'redis': 0}
        self._dns_log_sequence = 0
        self._dns_log_bytes = 0
        self._dns_log_returned = None
        self._dns_log_exhausted = False

    def dns_previous(self, kind):
        with self.lock:
            return self.dns[kind]

    def dns_poll_wait(self, kind, previous, outcome, read_started):
        """Scheduling only. No original observation, route or expiry changes.

        A completed positive read still always performs its fresh route. Far
        sampling explicitly permits up to .250s identity/failure detection
        latency. Zero/error/change/pending/expired history stays at .050s.
        The threshold is a scheduling choice, not a worst-case IO guarantee.
        """
        with self.lock:
            now = time.monotonic()
            current = self.dns[kind]
            if (outcome == 'positive' and type(previous) is whole.CompleteWitness
                    and type(current) is whole.CompleteWitness
                    and previous.original_expiry > now
                    and current.original_expiry > now + DNS_URGENT_SECONDS
                    and self.collision_expires > now + DNS_URGENT_SECONDS
                    and not self.errors.get(kind) and not self.errors.get('collision_census')
                    and previous.answer.semantic_identity == current.answer.semantic_identity
                    and previous.route.identity_json == current.route.identity_json
                    and not set(current.answer.addresses) & self.collisions):
                deadline = min(read_started + DNS_FAR_INTERVAL,
                    current.original_expiry - DNS_URGENT_SECONDS,
                    self.collision_expires - DNS_URGENT_SECONDS)
                return max(0, deadline - now)
            return max(0, read_started + DNS_INTERVAL - now)

    def dns_diagnostic_reference(self):
        with self.lock:
            return {'schema': 'capacity_sampled_DNS_diagnostic_reference_v1',
                'through_attempt_sequence': dict(self._dns_attempt_sequence),
                'sample_log_sequence': self._dns_log_sequence,
                'sampled_not_query_census': True, 'emitted_bytes': self._dns_log_bytes,
                'emission_budget_exhausted': self._dns_log_exhausted}

    def record_dns_diagnostic(self, kind, previous, answer, outcome, publication_returned,
                              attempt_started, error=None):
        # Timing facts are non-authoritative. A stale thread-local native
        # record from a previous loop must never be labelled this route read.
        facts = native_io.last_facts()
        route_sequence = route_started = route_returned = None
        if (type(facts) is dict and facts.get('role') == 'route_' + kind
                and type(facts.get('sequence')) is int
                and type(facts.get('started_monotonic')) in (int, float)
                and facts['started_monotonic'] >= attempt_started):
            route_sequence = facts['sequence']
            route_started = facts['started_monotonic']
            route_returned = facts.get('diagnostic_retention_returned_monotonic')
        with self.lock:
            require(self._dns_attempt_sequence[kind] < MAX_SEQUENCE, 'BOUNDED_DNS_DIAGNOSTIC_SEQUENCE')
            self._dns_attempt_sequence[kind] += 1
            selected = self.dns[kind]
            typed_answer = answer if type(answer) in (whole.OriginalDNS, whole.OriginalZeroTTL) else None
            row = [self._dns_attempt_sequence[kind], outcome,
                None if typed_answer is None else typed_answer.started,
                None if typed_answer is None else typed_answer.returned,
                None if typed_answer is None else typed_answer.minimum_chain_ttl,
                None if type(typed_answer) is not whole.OriginalDNS else typed_answer.expires,
                route_sequence, route_started, route_returned, publication_returned,
                None if selected is None else selected.original_expiry,
                None if selected is None else selected.answer.started,
                previous is not None and selected is previous,
                None if error is None else dns_error(error)]
            self._dns_diagnostics[kind].append(row)
            now = time.monotonic()
            if (self._dns_log_exhausted or self._dns_log_returned is not None
                    and now - self._dns_log_returned < DNS_DIAGNOSTIC_INTERVAL):
                return None
            # Latest32/kind remain in fixed RAM. Emitted samples use at most
            # four/kind, may shrink to fit4096B, and never claim a full census.
            for size in (4, 3, 2, 1):
                value = {'schema': 'capacity_original_DNS_route_publication_sample_v1',
                    'sample_log_sequence': self._dns_log_sequence + 1,
                    'columns': DNS_DIAGNOSTIC_COLUMNS,
                    'samples': {key: list(values)[-size:] for key, values in self._dns_diagnostics.items()},
                    'RAM_capacity_per_kind': 32, 'sampled_not_query_census': True,
                    'original_emitted_bytes_before_this_line': self._dns_log_bytes,
                    'Core_or_VM_authority': False}
                extent = len((json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode())
                if extent <= DNS_DIAGNOSTIC_LINE_BYTES:
                    break
            require(extent <= DNS_DIAGNOSTIC_LINE_BYTES, 'BOUNDED_DNS_DIAGNOSTIC_LINE')
            if self._dns_log_bytes + extent > DNS_DIAGNOSTIC_BYTES:
                self._dns_log_exhausted = True
                return None
            self._dns_log_sequence += 1
            self._dns_log_bytes += extent
            self._dns_log_returned = now
            return value

    def _state_key(self):
        # Original immutable evidence, not a clock or topology-generation
        # counter. Retaining the SAME positive whole witness after TTL0 does
        # not rewrite kernel elements or consume a new ownership token.
        dns = tuple((kind,None if item is None else (item.answer.semantic_identity,
            item.answer.started,item.original_expiry,item.route.identity_json,
            item.original_collision_expires,item.original_collisions)) for kind,item in sorted(self.dns.items()))
        return (self.entries,self.core_sources,self.prometheus,dns,self.collisions,
            self.collision_expires,tuple(sorted(self.errors.items())))

    def _changed(self, before):
        previous_errors = dict(before[-1])
        if any(name not in self.errors for name in previous_errors):
            require(self.guard_recovery_epoch < MAX_SEQUENCE, 'BOUNDED_GUARD_RECOVERY_EPOCH')
            self.guard_recovery_epoch += 1
        if self._state_key() != before:
            require(self.revision < MAX_SEQUENCE, 'BOUNDED_SEMANTIC_CACHE_REVISION')
            self.revision += 1
            self.wake.set()

    def _advance(self):
        require(self.generation < MAX_SEQUENCE, 'BOUNDED_SAME_PROCESS_CACHE_SEQUENCE')
        self.generation += 1

    def _guard_invalidate(self):
        """Called only under the cache lock; never coalesced like Event wake."""
        require(self.guard_invalidation_epoch < MAX_SEQUENCE, 'BOUNDED_GUARD_INVALIDATION_EPOCH')
        self.guard_invalidation_epoch += 1

    def _guard_evidence_key(self):
        def endpoint(x):
            return (getattr(x, 'kind', 'prometheus'), x.address, getattr(x, 'port', None),
                    x.native_identity)
        dns = []
        for kind, witness in sorted(self.dns.items()):
            dns.append((kind, None if witness is None else
                        (witness.answer.semantic_identity, witness.route.identity_json)))
        return (tuple(endpoint(x) for x in self.entries), tuple(endpoint(x) for x in self.core_sources),
                tuple(endpoint(x) for x in self.prometheus), tuple(dns), self.collisions,
                tuple(sorted(self.errors.items())))

    def _guard_expiries(self):
        def endpoint(x):
            return (getattr(x, 'kind', 'prometheus'), x.address, getattr(x, 'port', None))
        values = {('collision',): self.collision_expires}
        for group, items in (('entry', self.entries), ('core', self.core_sources), ('prom', self.prometheus)):
            for item in items:
                values[(group, *endpoint(item))] = item.expires
        for kind, witness in self.dns.items():
            if witness is not None:
                values[('dns', kind)] = witness.original_expiry
                values[('dns_collision', kind)] = witness.original_collision_expires
        return values

    def _guard_compare_and_invalidate(self, prior_key, prior_expiries):
        current_expiries = self._guard_expiries()
        if (self._guard_evidence_key() != prior_key or
                any(current_expiries[k] < value for k, value in prior_expiries.items() if k in current_expiries)):
            self._guard_invalidate()

    def topology_failed(self, error_class):
        with self.lock:
            before = self._state_key()
            self._guard_invalidate()
            self._advance()
            self.collisions, self.collision_expires = frozenset(), 0
            self.entries, self.core_sources, self.prometheus = (), (), ()
            self.dns = {'rds': None, 'redis': None}
            self._latest_positive = {'rds': None, 'redis': None}
            self.errors = {'collision_census': error_class}
            self.topology_returned = time.monotonic()
            self._changed(before)

    def publish_topology(self, values):
        entries, cores, prometheus, errors, collisions, expires = values
        require(type(expires) in (float, int) and math.isfinite(expires), 'ORIGINAL_COLLISION_DEADLINE')
        require(len(collisions) <= 512 and all(isinstance(x, str) and str(ipv4(x)) == x for x in collisions), 'BOUNDED_ORIGINAL_COLLISION_CENSUS')
        require(len(entries) <= 2 and len({x.kind for x in entries}) == len(entries)
                and all(type(x) is Backend and x.kind in ('core', 'broker') for x in entries), 'ONLY_ORIGINAL_TOPOLOGY_BACKENDS')
        require(len(cores) <= 8 and len({x.address for x in cores}) == len(cores)
                and all(type(x) is Backend and x.kind == 'core' for x in cores), 'BOUNDED_ORIGINAL_CORE_SOURCES')
        require(len(prometheus) <= 1 and all(type(x) is PrometheusSource for x in prometheus), 'BOUNDED_SEPARATE_PROMETHEUS_SOURCE')
        require(set(errors) <= {'core', 'broker', 'prometheus'} and all(isinstance(v, str) and len(v) <= 80 for v in errors.values()), 'FIXED_TOPOLOGY_DIAGNOSTIC_CLASSES')
        for item in (*entries, *cores, *prometheus):
            item.validate()
            require(item.expires <= expires and item.address not in collisions, 'ORIGINAL_TOPOLOGY_COLLISION_DEADLINE_JOIN')
        core = next((x for x in entries if x.kind == 'core'), None)
        require((not cores and core is None) or core is not None and core in cores, 'SAME_CORE_FORWARD_AND_REVERSE_ORIGINAL_OBSERVATION')
        require(not prometheus or all(prometheus[0].address != x.address for x in cores), 'SEPARATE_CORE_AND_PROMETHEUS_NATIVE_ROLE')
        with self.lock:
            before = self._state_key()
            guard_before, guard_expiries = self._guard_evidence_key(), self._guard_expiries()
            self._advance()
            self.entries, self.core_sources, self.prometheus = tuple(entries), tuple(cores), tuple(prometheus)
            self.collisions, self.collision_expires = frozenset(collisions), expires
            self.errors = {**{k: v for k, v in self.errors.items() if k in ('rds', 'redis')}, **errors}
            self.topology_returned = time.monotonic()
            # A new census may only shorten/invalidate retained original DNS;
            # its later deadline is NEVER copied into an older observation.
            for kind, item in self.dns.items():
                if item is not None and (set(item.answer.addresses) & self.collisions or item.original_expiry <= self.topology_returned):
                    self.dns[kind] = None
            self._guard_compare_and_invalidate(guard_before, guard_expiries)
            self._changed(before)

    def collision_context(self):
        with self.lock:
            if self.collision_expires <= time.monotonic():
                return None
            return self.collisions, self.collision_expires, self.generation

    def dns_failed(self, kind, error_class):
        require(kind in ('rds', 'redis'), 'ONLY_FIXED_DNS_KIND')
        with self.lock:
            before = self._state_key()
            self._guard_invalidate()
            self.dns[kind] = None
            self._latest_positive[kind] = None
            self.errors[kind] = error_class
            self._changed(before)

    def publish_dns(self, kind, item, original_context):
        require(kind in ('rds', 'redis') and type(item) is whole.CompleteWitness and item.answer.kind == kind, 'ORIGINAL_COMPLETE_FIXED_DNS_WITNESS')
        item.validate()
        original_collisions, original_expiry, _generation = original_context
        require(item.original_collisions == frozenset(original_collisions) and item.original_collision_expires == original_expiry,
                'SAME_ORIGINAL_DNS_COLLISION_CONTEXT')
        with self.lock:
            before = self._state_key()
            guard_before, guard_expiries = self._guard_evidence_key(), self._guard_expiries()
            previous = self.dns[kind]
            now = time.monotonic()
            self.dns[kind] = whole.select_complete(self.dns[kind], item, self.collisions, self.collision_expires, now)
            self._latest_positive[kind] = item
            # In particular, a shorter latest original may leave _state_key
            # unchanged. Wake is a request to inspect scheduling, not proof,
            # an authority substitution or a new kernel deadline.
            self.wake.set()
            if self.dns[kind] is None:
                self.errors[kind] = 'OriginalDNSOrRouteIdentityChanged'
            else:
                self.errors.pop(kind, None)
            self._guard_compare_and_invalidate(guard_before, guard_expiries)
            if previous is not None and item.original_expiry < previous.original_expiry:
                self._guard_invalidate()
            self._changed(before)

    def zero_candidate(self, kind, answer):
        require(kind in ('rds', 'redis') and type(answer) is whole.OriginalZeroTTL and answer.kind == kind,
                'ONLY_ORIGINAL_FIXED_ZERO_DNS_IDENTITY')
        with self.lock:
            previous = whole.previous_for_zero(self.dns[kind], answer, self.collisions, self.collision_expires, time.monotonic())
            require(previous is not None, 'ZERO_IDENTITY_HAS_NO_PREVIOUS_VALID_POSITIVE_AUTHORITY')
            return previous

    def publish_zero(self, kind, answer, route, previous):
        require(kind in ('rds', 'redis') and type(answer) is whole.OriginalZeroTTL and answer.kind == kind,
                'ONLY_COMPLETED_FIXED_ZERO_DNS_RECHECK')
        with self.lock:
            before = self._state_key()
            # A topology/error clear while the route was in flight cannot be
            # undone by an identity-only response. No zero object is cached.
            if self.dns[kind] is not previous:
                self._guard_invalidate()
                self.dns[kind] = None
                self.errors[kind] = 'OriginalZeroRecheckPreviousCleared'
                self._changed(before)
                return
            self.dns[kind] = whole.retain_after_zero(previous, answer, route, self.collisions, self.collision_expires, time.monotonic())
            if self.dns[kind] is None:
                self._guard_invalidate()
                self.errors[kind] = 'OriginalZeroRecheckIdentityChanged'
            else:
                self.errors.pop(kind, None)
            self._changed(before)

    def _snapshot_locked(self):
        now = time.monotonic()
        errors = dict(self.errors)
        if self.collision_expires <= now:
            errors['collision_census'] = 'OriginalObservationExpired'
            return (), (), (), errors, self.generation
        def valid(item):
            return item.observed_started <= now < min(item.expires, self.collision_expires) and item.address not in self.collisions
        entries = tuple(x for x in self.entries if valid(x))
        cores = tuple(x for x in self.core_sources if valid(x))
        prometheus = tuple(x for x in self.prometheus if valid(x))
        dns = tuple(dns_native.backend(x, self.collisions, self.collision_expires, now=now)
                    for x in self.dns.values() if x is not None and
                    x.answer.started <= now < min(x.original_expiry, self.collision_expires) and
                    not set(x.answer.addresses) & self.collisions)
        # Cached Core sources cannot outlive the matching original DNAT.
        if not any(x.kind == 'core' for x in entries):
            cores = ()
        return entries + dns, cores, prometheus, errors, self.generation

    def snapshot(self):
        with self.lock:
            return self._snapshot_locked()

    def commit_snapshot(self):
        with self.lock:
            value = self._snapshot_locked()
            entries,cores,prom,errors,generation = value
            # The kernel payload uses these complete original born/expiry
            # values and separate roles. A time-passing snapshot is a change
            # only when evidence actually expires/clears, never by now alone.
            key = (entries,cores,prom,tuple(sorted(errors.items())),
                self.collisions,self.collision_expires)
            return value,key,self.revision

    def scheduling_snapshot(self):
        """Atomic whole identity and original bounds; no authority is minted.

        Clock-only publications may be coalesced, while ALL A/CNAME/route
        identity, native process/role, collision and error changes cannot.
        The newest complete positive contributes a conservative scheduling
        bound only; _snapshot_locked remains the sole selected authority.
        """
        with self.lock:
            value = self._snapshot_locked()
            entries, cores, prom, errors, generation = value
            key = (entries, cores, prom, tuple(sorted(errors.items())),
                   self.collisions, self.collision_expires)
            def backend(item):
                return item.kind, item.address, item.port, item.native_identity
            def dns(item):
                return None if item is None else (item.answer.semantic_identity,
                    item.route.identity_json, item.original_collisions)
            identity = (tuple(backend(x) for x in entries),
                tuple(backend(x) for x in cores),
                tuple((x.address, x.native_identity) for x in prom),
                tuple((kind, dns(item)) for kind, item in sorted(self.dns.items())),
                tuple((kind, dns(item)) for kind, item in sorted(self._latest_positive.items())),
                self.collisions, tuple(sorted(errors.items())))
            bounds = [x.expires for x in (*entries, *cores, *prom)]
            bounds.append(self.collision_expires)
            bounds.extend(item.original_expiry for item in self._latest_positive.values() if item is not None)
            earliest = min(bounds)
            latest = tuple(sorted(self._latest_positive.items()))
            return value, key, self.revision, identity, earliest, latest


class Readers:
    def __init__(self, topology_read, dns_read, route):
        self.cache = Cache()
        self._topology_read, self._dns_read, self._route = topology_read, dns_read, route
        self.stop = threading.Event()
        self.threads = []

    def _topology(self):
        while not self.stop.is_set():
            try:
                value = self._topology_read()
                if self.stop.is_set():
                    return
                self.cache.publish_topology(value)
            except Exception as error:
                self.cache.topology_failed(type(error).__name__)
            self.stop.wait(TOPOLOGY_INTERVAL)

    def _dns(self, kind):
        while not self.stop.is_set():
            read_started = time.monotonic()
            context = self.cache.collision_context()
            previous = self.cache.dns_previous(kind)
            answer, outcome, publication_returned, error = None, 'pending', None, None
            if context is not None:
                try:
                    answer = self._dns_read(kind, context[0])
                    if self.stop.is_set():
                        return
                    if type(answer) is whole.OriginalZeroTTL:
                        previous = self.cache.zero_candidate(kind, answer)
                        original_route = self._route(answer, previous)
                        if self.stop.is_set():
                            return
                        self.cache.publish_zero(kind, answer, original_route, previous)
                        outcome = 'zero'
                    else:
                        original_route = self._route(answer)
                        if self.stop.is_set():
                            return
                        item = whole.complete(answer, original_route, context[0], context[1])
                        self.cache.publish_dns(kind, item, context)
                        outcome = 'positive'
                    publication_returned = time.monotonic()
                except Exception as caught:
                    error, outcome = caught, 'error'
                    self.cache.dns_failed(kind, dns_error(caught))
                    publication_returned = time.monotonic()
            diagnostic = self.cache.record_dns_diagnostic(kind, previous, answer, outcome,
                publication_returned, read_started, error)
            if diagnostic is not None:
                emit_json(diagnostic)
            # The sleep remains anchored BEFORE the original DNS and route.
            # IO/logging work never earns another full sampling interval.
            self.stop.wait(self.cache.dns_poll_wait(kind, previous, outcome, read_started))

    def start(self):
        require(not self.threads, 'ORIGINAL_READERS_START_ONCE')
        for function, args in ((self._topology, ()), (self._dns, ('rds',)), (self._dns, ('redis',))):
            thread = threading.Thread(target=function, args=args, daemon=True)
            self.threads.append(thread)
            thread.start()

    def close_join(self, original_deadline):
        self.stop.set()
        for thread in self.threads:
            thread.join(max(0, original_deadline - time.monotonic()))
        require(all(not x.is_alive() for x in self.threads), 'ALL_ORIGINAL_OBSERVATION_READERS_CLOSED_JOINED')
