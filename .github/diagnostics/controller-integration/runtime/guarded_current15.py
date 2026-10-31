"""LAB-only original-source/kernel coverage chain; this is not an effect lease.

Snapshots come from the Guardian's same-process original Readers before each
send. A non-coalescing cache invalidation epoch prevents hiding failure/recovery
between samples. Every accepted generation has an independently verified sender,
FDs, original ACK, stable kernel generation and conservative set/map deadlines.
The result is conditional on live Guardian/owner and absence of later invalidation;
it cannot authorize an external effect without a separate authenticated lease.
"""
import os
import time


_CAPABILITY = object()


class Held(Exception):
    pass


def need(value, reason):
    if not value:
        raise Held(reason)


class _BeforeSend:
    def __init__(self, cache, expected, captured_ns, capability):
        need(capability is _CAPABILITY, 'ONLY_ORIGINAL_GUARDIAN_SNAPSHOT')
        self.cache = cache
        self.expected = {role: dict(expected[role]) for role in ('inbound', 'reverse')}
        self.dnat = dict(expected['dnat'])
        self.cores = frozenset(expected['cores'])
        self.prom = frozenset(expected['prom'])
        self.source_generation = expected['source_generation']
        self.epoch = expected['invalidation_epoch']
        self.captured_ns = captured_ns
        self.pid = os.getpid()
        self.capability = capability
        self.consumed = False


class CoverageChain:
    def __init__(self, cache, sources, verifier):
        self.cache, self.sources, self.verifier = cache, sources, verifier
        self.pid = os.getpid()
        self.start_ns = self.deadline_ns = self.genid = self.epoch = None
        self.sender = None
        self.last_verified = self.last_observation = None

    def capture_before_send(self):
        need(self.pid == os.getpid(), 'SAME_GUARDIAN_PROCESS')
        expected = self.sources.build_expected(self.cache)
        need(type(expected['invalidation_epoch']) is int and expected['invalidation_epoch'] >= 0,
             'NONCOALESCING_READER_INVALIDATION_EPOCH_REQUIRED')
        return _BeforeSend(self.cache, expected, time.monotonic_ns(), _CAPABILITY)

    def record(self, before, verified, envelope):
        need(self.pid == os.getpid() and type(before) is _BeforeSend and before.capability is _CAPABILITY
             and before.pid == self.pid and before.cache is self.cache and not before.consumed,
             'ONE_ORIGINAL_BEFORE_SEND_SNAPSHOT')
        need(type(verified) is self.verifier._VerifiedGeneration
             and verified.capability is self.verifier._VERIFIED_CAPABILITY
             and verified.guardian_pid == self.pid and verified.reader_cache is self.cache
             and verified.sender_pidfd is not None, 'SAME_ORIGINAL_VERIFIED_GENERATION')
        before.consumed = True
        result, anchor = verified.result, verified.anchor
        now = time.monotonic_ns()
        obs = envelope['observation']
        current = self.sources.build_expected(self.cache)
        need(type(current['invalidation_epoch']) is int and current['invalidation_epoch'] == before.epoch
             and envelope.get('invalidation_epoch') == before.epoch,
             'READER_INVALIDATED_SINCE_BEFORE_SEND')
        need(before.captured_ns <= result['send_started_ns'] <= result['send_returned_ns']
             <= envelope['observed_ns'] <= now, 'ORIGINAL_MONOTONIC_SEND_AND_OBSERVATION')
        for role in ('inbound', 'reverse'):
            actual = dict(verified.actual[role])
            need(len(actual) == len(verified.actual[role]) and set(actual) == set(before.expected[role])
                 and set(actual) == set(current[role]), 'EXACT_BEFORE_AND_CURRENT_TUPLES')
            need(all(now < value <= before.expected[role][key] and value <= current[role][key]
                     for key, value in actual.items()), 'DEADLINES_BOUND_TO_BOTH_ORIGINAL_READS')
        until = obs['kernel_min_deadline_ns']
        need(type(until) is int and now < until, 'LIVE_CONSERVATIVE_NFT_AND_MAP_DEADLINE')
        identity = (anchor['pid'], anchor['start_ticks'], anchor['netns'])
        continuous = (self.start_ns is not None and self.sender == identity and self.epoch == before.epoch
                      and result['genid'] == self.genid and self.deadline_ns > result['send_returned_ns'])
        if not continuous:
            self.start_ns = result['send_returned_ns']
        self.sender, self.epoch, self.genid, self.deadline_ns = identity, before.epoch, result['after'], until
        qualified = envelope['observed_ns'] - self.start_ns >= 15_000_000_000
        if qualified:
            obs['current15_start_ns'] = self.start_ns
            obs['current15_observed_until_ns'] = envelope['observed_ns']
            obs['current15_guaranteed_until_ns'] = until
        self.last_verified = verified
        self.last_observation = (qualified, self.start_ns, envelope['observed_ns'], until,
                                 before.epoch, result['after'], obs['receipt_sha256'])
        envelope['current15_qualified'] = qualified
        envelope['cross_process_effect_lease'] = False
        envelope['grant_authority'] = False
        envelope['continuity_is_conditional_on_live_guardian_and_no_later_invalidation'] = True
        return envelope
