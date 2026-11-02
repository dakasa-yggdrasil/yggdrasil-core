"""Authenticated historical initializer of one exact controller lifetime.

This cache saves only recomputation of immutable original journal bytes. Every
use rereads and rehashes all consumed files and rechecks identity/authority.
It never supplies current health, a new epoch, a return or mutation authority.
"""
import copy
import math
import re
import time


IDENTITY_FIELDS = {
    'boot_id', 'pid', 'start_ticks', 'InvocationID',
    'ExecMainStartTimestampMonotonic', 'cmdline_sha256',
    'initial_R42_admitted_lifetime',
}
INITIALIZER_FIELDS = (
    'initial_structure_proof_kind', 'initial_original_echo_handles',
    'initial_original_read_handles', 'initial_original_structure_handles',
    'compiled_native_ast_sha256', 'original_read_adoption',
)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def extract(owner, g, identity):
    """Return authenticated initializer facts, or None if no original exists.

    Proof paths are derived solely from the exact physical lifetime. Stored
    measurement/health flags are never trusted. Old source/standing pairs
    retain their original meaning only through the closed standing lineage.
    """
    R = g.require
    R(type(identity) is dict and set(identity) == IDENTITY_FIELDS
      and identity['boot_id'] == owner.boot
      and type(identity['pid']) is int and identity['pid'] > 1
      and type(identity['start_ticks']) is int and identity['start_ticks'] > 0
      and re.fullmatch('[a-f0-9]{32}', identity['InvocationID']) is not None
      and type(identity['ExecMainStartTimestampMonotonic']) is str
      and identity['ExecMainStartTimestampMonotonic'].isdecimal()
      and int(identity['ExecMainStartTimestampMonotonic']) > 0
      and re.fullmatch('[a-f0-9]{64}', identity['cmdline_sha256']) is not None
      and type(identity['initial_R42_admitted_lifetime']) is bool,
      'EXACT_CURRENT_INITIALIZER_LIFETIME_IDENTITY')
    R(owner.identity() == identity, 'SAME_PHYSICAL_LIFETIME_BEFORE_INITIALIZER_READ')
    key = owner.key(identity)
    R(type(key) is str and re.fullmatch('[a-f0-9]{64}', key) is not None,
      'FIXED_INITIALIZER_LIFETIME_KEY')
    path = g.LEDGER / (key + '-QUALIFIED.PUBLIC.json')
    if not path.exists():
        return None
    raw = g.read(path, 16 << 20, 0o600)
    value = g.loads(raw)
    R(value['schema'] == 'Root_new_network_lifetime_original120_current15_return_v1'
      and value['identity'] == identity
      and type(owner.authorities) is frozenset
      and (value['source_sha256'], value['standing_config_sha256']) in owner.authorities,
      'SAME_AUTHENTICATED_ORIGINAL_LIFETIME_QUALIFICATION')
    start, end, finished, deadline = (
        value['start'], value['end'], value['finished'], value['original_work_deadline'])
    R(all(number(x) for x in (start, end, finished, deadline))
      and 0 <= start < end <= finished < deadline
      and end - start == 120 and finished <= time.monotonic(),
      'SAME_BOOT_HISTORICAL_ORIGINAL120_CLOCK_AND_BUDGET')

    refs = (value['original_prefix_ref'], value['original_suffix_ref'])
    expected_paths = (
        g.LEDGER / (key + '-ORIGINAL-PREFIX.JSONL'),
        g.LEDGER / (key + '-ORIGINAL-CLOSING.JSONL'),
    )
    bodies = []
    for ref, expected in zip(refs, expected_paths):
        R(type(ref) is dict and set(ref) == {'path', 'sha256'}
          and ref['path'] == str(expected)
          and type(ref['sha256']) is str
          and re.fullmatch('[a-f0-9]{64}', ref['sha256']) is not None,
          'FIXED_OWNED_ORIGINAL_INITIALIZER_JOURNAL_REFERENCE')
        body = g.read(expected, 64 << 20, 0o600)
        R(g.sha(body) == ref['sha256'], 'FULL_CONSUMED_ORIGINAL_INITIALIZER_BYTES')
        bodies.append(body)

    # Cache keys include every consumed byte. Rehashing is mandatory even when
    # immutable math can be reused. The caller never receives a mutable alias.
    fingerprint = (g.sha(raw), *(g.sha(body) for body in bodies))
    cached = getattr(owner, '_qualification_initializer_cache', None)
    if cached is not None and cached['fingerprint'] == fingerprint:
        R(owner.identity() == identity, 'SAME_PHYSICAL_LIFETIME_AFTER_INITIALIZER_READ')
        return copy.deepcopy(cached['result'])

    prefix, suffix = bodies
    # coverage.journal is a reusable reducer which filters other identities.
    # An owned full-prefix proof must instead account for EVERY requested row.
    seen, previous = set(), 0
    for line in prefix.splitlines():
        cursor, stamp = owner.journal_contract.journal_row(
            g.loads(line), identity['pid'], identity['InvocationID'],
            owner.boot.replace('-', ''))
        R(cursor not in seen and previous <= stamp
          and stamp / 1000000 <= finished,
          'ALL_INITIALIZER_PREFIX_ROWS_SAME_BOOT_LIFETIME_FORWARD_CLOCK')
        seen.add(cursor)
        previous = stamp
    measured = owner.coverage.journal(
        prefix, identity['pid'], identity['InvocationID'], finished,
        minimum_original_batches=1)
    anchor = owner.journal_contract.journal_anchor(
        prefix, identity['pid'], identity['InvocationID'],
        owner.boot.replace('-', ''), finished)
    measured, _ = owner.journal_contract.closing_journal(
        measured, suffix, identity['pid'], identity['InvocationID'],
        owner.boot.replace('-', ''), anchor, finished, owner.coverage)
    current = measured['current_continuous_window']
    observed = value['kernel_observed']
    R(current is not None and current['start'] <= start
      and current['observed_until'] >= end
      and measured['qualified_15_seconds'] is True
      and number(observed)
      and current['start'] <= observed <= current['observed_until']
      and finished < current['guaranteed_until']
      and value['kernel']['all_four_backends_and_reverse_sources_positive'] is True,
      'RECOMPUTED_ORIGINAL_LIFETIME120_NEVER_CURRENT_HEALTH_ALIAS')
    samples = value['periodic_transport_samples']
    R(type(samples) is list and 2 <= len(samples) <= 256
      and all(type(row) is dict and number(row['started'])
              and number(row['finished'])
              and 0 <= row['started'] <= row['finished'] <= finished
              and row['finished'] - row['started'] < 20
              and row['transport']['four_bridge_and_four_MSS_original_checks_zero'] is True
              for row in samples)
      and samples[0]['finished'] <= start
      and start - samples[0]['finished'] < 1
      and samples[-1]['finished'] >= end
      and all(0 <= b['started'] - a['finished'] <= 5.5
              for a, b in zip(samples, samples[1:])),
      'ORIGINAL_FUNCTIONAL_EIGHT_RULE_READS_SPAN_SAME120')
    R(owner.identity() == identity, 'SAME_PHYSICAL_LIFETIME_AFTER_INITIALIZER_READ')
    result = {
        'schema': 'Root_authenticated_original_lifetime_initializer47_v1',
        'identity': copy.deepcopy(identity),
        'authority': {'source_sha256': value['source_sha256'],
                      'standing_config_sha256': value['standing_config_sha256']},
        'original_qualification_ref': {'path': str(path), 'sha256': g.sha(raw)},
        'original_prefix_ref': copy.deepcopy(refs[0]),
        'original_suffix_ref': copy.deepcopy(refs[1]),
        'measurement': {name: copy.deepcopy(measured[name]) for name in INITIALIZER_FIELDS},
        'historical_original120_proof_verified': True,
        'current_health_or_new_epoch_authority': False,
    }
    owner._qualification_initializer_cache = {
        'fingerprint': fingerprint, 'result': copy.deepcopy(result)}
    return result
