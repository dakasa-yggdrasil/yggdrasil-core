"""Experimental partial hot refresh; never use as production authority.

Caller holds the same local fence lock as admission. Preserved Core elements
are not touched or refreshed; other entries change in one nft transaction.
A stale kernel read can abort the transaction, and an uncertain native send
is fatal just like the original controller.
"""
import time
import nft_owner as nft
import transition_adoption as parser


def native_partial(backends, *, core_sources, prometheus_sources, state, apply, _ownership):
    nft._consume_ownership(_ownership, .750)
    started = time.monotonic()
    def hold_unless(condition, reason):
        if not condition:
            raise nft.NoSend(reason, started, time.monotonic())
    anchor = state.get('anchor')
    hold_unless(type(anchor) is dict and set(anchor) == {'uid', 'address'}, 'DRAFT_READY_ANCHOR_REQUIRED')
    candidates = [x for x in core_sources if x.address == anchor['address']
                  and x.native_identity.split('/', 1)[0] == anchor['uid']
                  and x.observed_started <= started < x.expires]
    hold_unless(len(candidates) == 1, 'DRAFT_FRESH_READY_ANCHOR_REQUIRED')
    candidates[0].validate()
    snapshot = nft.command(['/usr/sbin/nft', '-a', 'list', 'table', 'inet', nft.TABLE],
                           timeout=.150, role='adopt_owned_text')
    nft.require(snapshot.returncode == 0, 'DRAFT_NATIVE_CORE_SNAPSHOT_FAILED')
    parsed = parser.kernel_text(snapshot.stdout)
    rows = parsed['dynamic_collections']
    core_key = ' . '.join(map(str,nft.VIP_PORTS['core']))
    target = anchor['address'] + ' . 9443'
    core = [x for x in rows['backend_dnat4'] if x['value'] == core_key and x['target'] == target and x['expires_ms'] > 0]
    reverse = [x for x in rows['core_ready4'] if x['value'] == anchor['address'] and x['expires_ms'] > 0]
    forward = [x for x in rows['backend_forward4'] if x['value'] == core_key + ' . ' + target and x['expires_ms'] > 0]
    hold_unless(len(core) == len(reverse) == len(forward) == 1, 'DRAFT_KERNEL_ANCHOR_NOT_POSITIVE')
    hold_unless(len(rows['core_ready4']) == 1
        and sum(x['value'] == core_key for x in rows['backend_dnat4']) == 1
        and sum(x['value'].startswith(core_key + ' . ') for x in rows['backend_forward4']) == 1,
        'DRAFT_KERNEL_ANCHOR_NOT_UNIQUE')
    nft.require(all(x.address not in {v['value'] for v in rows['core_ready4']} for x in prometheus_sources),
                'DRAFT_PROMETHEUS_NOT_CORE')
    noncore = [x for x in backends if x.kind != 'core']
    entries, bindings, _, prometheus = nft._eligibility(
        noncore, now=started, core_sources=(), prometheus_sources=prometheus_sources,
        _timeout_milliseconds=True, _reserve_seconds=.250)
    cmds = []
    for row in rows['backend_dnat4']:
        if row['value'] != core_key:
            cmds.append('delete element inet ' + nft.TABLE + ' backend_dnat4 { ' + row['value'] + ' }')
    for row in rows['backend_forward4']:
        if not row['value'].startswith(core_key + ' . '):
            cmds.append('delete element inet ' + nft.TABLE + ' backend_forward4 { ' + row['value'] + ' }')
    cmds.append('flush set inet ' + nft.TABLE + ' prometheus_ready4')
    if entries: cmds.append('add element inet ' + nft.TABLE + ' backend_dnat4 { ' + ', '.join(entries) + ' }')
    if bindings: cmds.append('add element inet ' + nft.TABLE + ' backend_forward4 { ' + ', '.join(bindings) + ' }')
    if prometheus: cmds.append('add element inet ' + nft.TABLE + ' prometheus_ready4 { ' + ', '.join(prometheus) + ' }')
    raw = ('\n'.join(cmds) + '\n').encode()
    # Reserve the full original hot-commit budget: neither the Ready evidence
    # nor any preserved Core tuple may expire while committing this batch.
    anchor_until = min(candidates[0].expires,
        started + min(core[0]['expires_ms'], reverse[0]['expires_ms'], forward[0]['expires_ms']) / 1000)
    hold_unless(time.monotonic() + .250 < anchor_until, 'DRAFT_ANCHOR_EXPIRY_TOO_CLOSE')
    nft._refresh_pre_send_margin(started, 'DRAFT_PARTIAL_PRE_SEND_MARGIN')
    native_returned = None
    applied = bool(apply())
    if applied:
        nft._refresh_pre_send_margin(started, 'DRAFT_PARTIAL_FINAL_PRE_SEND_FENCE')
        done = nft.command(['/usr/sbin/nft', '-f', '-'], data=raw,
                           timeout=min(.200, .250-(time.monotonic()-started)), role='hot_dynamic_apply')
        native_returned = time.monotonic()
        nft.require(done.returncode == 0 and native_returned-started < .250, 'DRAFT_PARTIAL_APPLY_UNKNOWN_NO_REPLAY')
    result=nft._hot_facts(noncore, (), prometheus_sources, started, .250, raw, applied=applied,
                          phase='draft_noncore_only', native_returned=native_returned)
    result.update({'core_pending': True, 'core_elements_untouched': True,
                   'core_continuity_proven': False, 'preserved_core_until': anchor_until,
                   'anchor_uid': anchor['uid'], 'anchor_ip': anchor['address']})
    nft.require(time.monotonic()-started < .250 and time.monotonic() < anchor_until,
                'DRAFT_PARTIAL_RESULT_EXPIRED_OR_UNKNOWN_NO_REPLAY')
    return result
