"""Private same-process pins from original native apply echo or exact read-adoption.

No pin is decoded from disk/config/wire. Unknown kernel echo shapes HOLD. Root
must qualify this exact schema with native nft1.0.2 before any deployment.
"""
import copy
import hashlib
import json
import os
import re
import threading
import time

import nft_owner as nft

DYNAMIC = {'set': {'core_ready4', 'prometheus_ready4', 'backend_forward4'}, 'map': {'backend_dnat4'}}
SETS = {'peers4', 'vips4', 'remote_vips4', 'core_ready4', 'prometheus_ready4', 'backend_forward4'}
CHAINS = {'prerouting', 'input_guard', 'admit_new', 'forward_guard', 'output_guard', 'postrouting'}
_CAPABILITY = object()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _objects(raw, *, echo=False, _with_origin=False):
    nft.require(not echo, 'NATIVE_TEXT_INPUT_HAS_TEXT_ECHO_NOT_JSON')
    value = json.loads(raw)
    nft.require(type(value) is dict and set(value) == {'nftables'} and type(value['nftables']) is list
                and 1 <= len(value['nftables']) <= 16384, 'FULL_CLOSED_NATIVE_NFT_JSON')
    rows = []
    for row in value['nftables']:
        nft.require(type(row) is dict and len(row) == 1, 'CLOSED_NATIVE_NFT_OBJECT')
        kind = next(iter(row))
        if kind == 'metainfo':
            continue
        data = row[kind]
        if type(data) is not dict:
            continue
        owned = data.get('family') == 'inet' and (data.get('name') == nft.TABLE if kind == 'table' else data.get('table') == nft.TABLE)
        if not owned:
            continue
        nft.require(kind in {'table', 'set', 'map', 'chain', 'rule'}, 'ONLY_COMPILED_OWNED_OBJECT_KINDS')
        nft.require(type(data.get('handle')) is int and data['handle'] > 0, 'ORIGINAL_NATIVE_OBJECT_HANDLE_REQUIRED')
        # Same call-local JSON tree; _handles only reads it and _structure
        # takes its OWN complete deepcopy before any counter/element edit.
        # No row/tree escapes revalidate or is shared with another reader.
        rows.append({kind: data})
    if _with_origin:
        # Standard json.loads above owns this exact tree; full native shape
        # checks have completed. Its call-local origin never authorizes a send.
        return rows, value['nftables'], nft._OriginalJSONOrigin(value['nftables'], raw, nft._JSON_ORIGIN_CAPABILITY)
    return rows, value['nftables']


def _structure(rows, *, keep_handles=True):
    tables = [x['table'] for x in rows if 'table' in x]
    nft.require(len(tables) == 1, 'EXACT_ONE_OWNED_NATIVE_TABLE')
    nft.require({x['set']['name'] for x in rows if 'set' in x} == SETS
                and sum('set' in x for x in rows) == 6
                and [x['map']['name'] for x in rows if 'map' in x] == ['backend_dnat4']
                and {x['chain']['name'] for x in rows if 'chain' in x} == CHAINS
                and sum('chain' in x for x in rows) == 6
                and sum('rule' in x for x in rows) == 33, 'COMPLETE_COMPILED_OWNED_STRUCTURE_CENSUS')
    objects, rules_by_chain, counters = [], {chain: [] for chain in CHAINS}, 0
    for row in rows:
        kind = next(iter(row))
        data = copy.deepcopy(row[kind])
        if not keep_handles:
            data.pop('handle', None)
        if kind in DYNAMIC and data.get('name') in DYNAMIC[kind]:
            # Only the exact four data-bearing collections may change. Their
            # handles/type/flags/size and every other field remain pinned.
            data.pop('elem', None)
        elif kind == 'set' and 'elem' in data:
            # Constant-set dump order is not packet-path rule order. Keep its
            # exact full values, sorted canonically; no value may be omitted.
            require_elements = data['elem']
            nft.require(type(require_elements) is list and len({_canonical(v) for v in require_elements}) == len(require_elements), 'EXACT_UNIQUE_CONSTANT_SET_VALUES')
            data['elem'] = sorted(require_elements, key=_canonical)
        if kind == 'rule':
            nft.require(type(data.get('expr')) is list and data.get('chain') in CHAINS, 'NATIVE_RULE_EXPRESSIONS_REQUIRED')
            for expression in data['expr']:
                if type(expression) is dict and 'counter' in expression:
                    counter = expression['counter']
                    nft.require(set(expression) == {'counter'} and type(counter) is dict and set(counter) == {'packets', 'bytes'}
                                and all(type(v) is int and v >= 0 for v in counter.values()), 'EXACT_COMPILED_ANONYMOUS_COUNTER')
                    expression['counter'] = {'packets': 0, 'bytes': 0}
                    counters += 1
            # The order WITHIN each chain is security-relevant and retained.
            rules_by_chain[data['chain']].append(data)
        else:
            objects.append({kind: data})
    nft.require(counters == 5, 'EXACT_FIVE_COMPILED_DROP_COUNTERS')
    return _canonical({'objects': sorted(objects, key=_canonical), 'rules_by_chain': rules_by_chain})


# Both hashes are compiled from the reviewed source-controlled R8/R10 fixed
# rule template and Root's original nft1.0.2 native grammar-only observation.
# No runtime snapshot/config/caller can select or update them.
COMPILED_STATIC_TEXT_SHA256 = '28d7e5e124c294c62e1909b48f903067c03422521fb895101591a1214643a002'
COMPILED_NATIVE_AST_SHA256 = '6f05172eb78be1fdd455055bf22c01e5b1f8ddeebf6fe5d7024e3ee28a2f6b4d'


def _text_echo(raw):
    nft.require(type(raw) is bytes and 0 < len(raw) <= 262144, 'BOUNDED_ORIGINAL_TEXT_ECHO')
    lines = raw.decode('ascii').splitlines()
    static, handles, elements, previous, ordinal, trailer, deleted = [], {}, [], {}, {}, 0, 0
    prefix = 'inet ' + nft.TABLE + ' '
    for index, line in enumerate(lines):
        line = line.strip()
        if re.fullmatch(r'# new generation [1-9][0-9]* by process [1-9][0-9]* \(nft\)', line):
            nft.require(index == len(lines)-1 and trailer == 0, 'ONLY_FINAL_ORIGINAL_GENERATION_TRAILER')
            trailer += 1
            continue
        if re.fullmatch('delete table inet '+nft.TABLE+r'(?: # handle [1-9][0-9]*)?', line):
            deleted += 1
            nft.require(deleted <= 1 and not static, 'ONLY_PRIOR_OWNED_TABLE_DELETE')
            continue
        if line.startswith('add element '+prefix):
            m = re.fullmatch('add element '+prefix+r'([a-z_0-9]+) \{ (.+) \}', line)
            nft.require(m is not None, 'CLOSED_ORIGINAL_ELEMENT_ECHO')
            if m[1] in DYNAMIC['set'] | DYNAMIC['map']:
                elements.append((m[1], m[2]))
                continue
            nft.require(m[1] in {'peers4','vips4','remote_vips4'}, 'NO_UNKNOWN_ORIGINAL_CONSTANT_SET')
            static.append(line)
            continue
        found = re.findall(r'# handle ([1-9][0-9]*)', line)
        nft.require(len(found) == 1, 'EVERY_ORIGINAL_OBJECT_HAS_ONE_NATIVE_HANDLE')
        handle = int(found[0])
        line = re.sub(r' # handle [1-9][0-9]*', '', line)
        line = ' '.join(line.split())
        m = re.fullmatch(r'add (table|set|map|chain|rule) inet '+nft.TABLE+r'(?: (.*))?', line)
        nft.require(m is not None, 'ONLY_ORIGINAL_COMPILED_TEXT_OBJECTS')
        kind, body = m[1], m[2] or ''
        if kind == 'table':
            nft.require(body == '', 'ONLY_EXACT_ORIGINAL_TABLE_ECHO');key = ('table',nft.TABLE)
        elif kind == 'rule':
            chain, separator, expression = body.partition(' ')
            nft.require(chain in CHAINS and separator, 'EXACT_ORIGINAL_RULE_CHAIN')
            position = re.match(r'handle ([1-9][0-9]*) (.+)$', expression)
            if position:
                nft.require(previous.get(chain) == int(position[1]), 'ORIGINAL_RULE_POSITION_FROM_SAME_CHAIN')
                expression = position[2]
            number = ordinal.get(chain,0);ordinal[chain] = number+1
            key = ('rule',chain,str(number));previous[chain] = handle
            line = 'add rule '+prefix+chain+' '+expression
        else:
            name = body.split(' ',1)[0]
            nft.require(name in (SETS if kind=='set' else {'backend_dnat4'} if kind=='map' else CHAINS), 'ONLY_FIXED_ORIGINAL_NAMED_OBJECT')
            key = (kind,name)
        nft.require(key not in handles, 'ONE_ORIGINAL_NATIVE_HANDLE_PER_OBJECT')
        handles[key] = handle;static.append(line)
    nft.require(trailer in (0, 1) and len(handles) == 47 and sum(k[0]=='rule'for k in handles)==33,
                'COMPLETE_ORIGINAL_ECHO_CENSUS_AND_TRAILER')
    changing = [v for k,v in handles.items() if k[0]in ('rule','set','map')]
    nft.require(len(set(changing))==len(changing), 'UNIQUE_ORIGINAL_RULE_AND_COLLECTION_HANDLES')
    return hashlib.sha256(_canonical(static)).hexdigest(), handles, elements


def _handles(rows):
    result, ordinal = {}, {}
    for row in rows:
        kind = next(iter(row));item = row[kind]
        if kind=='rule':
            chain=item['chain'];number=ordinal.get(chain,0);ordinal[chain]=number+1;key=(kind,chain,str(number))
        else:key=(kind,item['name'])
        nft.require(key not in result, 'ONE_CURRENT_NATIVE_OBJECT')
        result[key]=item['handle']
    return result


class _OriginalStructure:
    def __init__(self, handles, raw_input_sha256, capability, *, proof_kind='original_native_apply_echo', original_native_read_sha256=None):
        nft.require(capability is _CAPABILITY and proof_kind in ('original_native_apply_echo','original_owned_read_adoption'), 'ONLY_ORIGINAL_SAME_PROCESS_NATIVE_STRUCTURE_PIN')
        nft.require((proof_kind=='original_native_apply_echo' and raw_input_sha256 is not None and original_native_read_sha256 is None)or(proof_kind=='original_owned_read_adoption' and raw_input_sha256 is None and original_native_read_sha256 is not None),'HONEST_ORIGINAL_STRUCTURE_PROOF_KIND')
        self.proof_kind = proof_kind
        self.original_native_read_sha256 = original_native_read_sha256
        self.handles = dict(handles)
        self.structure_sha256 = COMPILED_NATIVE_AST_SHA256
        self.original_input_sha256 = raw_input_sha256
        self.pid = os.getpid()
        self.capability = capability


def from_original_apply_echo(raw, raw_input_sha256):
    static_hash, handles, _elements = _text_echo(raw)
    nft.require(static_hash == COMPILED_STATIC_TEXT_SHA256, 'EXACT_SOURCE_COMPILED_STATIC_ORIGINAL_TEXT_ECHO')
    # Elements are not structural authority. The same ORIGINAL source-controlled
    # checked input and whole native0 are joined by the initializer. Every later
    # native snapshot must match both original handles AND the fixed full AST.
    return _OriginalStructure(handles, raw_input_sha256, _CAPABILITY)


def revalidate(pin):
    nft.require(type(pin) is _OriginalStructure and pin.capability is _CAPABILITY
                and pin.pid == os.getpid(), 'SAME_PROCESS_ORIGINAL_STRUCTURE_NOT_DISK_OR_CALLER')
    reply = nft.command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_structure')
    nft.require(reply.returncode == 0, 'NATIVE_CURRENT_STRUCTURAL_READ')
    rows, rules, original_json = _objects(reply.stdout, _with_origin=True)
    nft.require(_handles(rows) == pin.handles, 'ALL_SAME_ORIGINAL_NATIVE_STRUCTURE_HEADER_AND_OBJECT_HANDLES')
    nft.require(hashlib.sha256(_structure(rows, keep_handles=False)).hexdigest() == COMPILED_NATIVE_AST_SHA256,
                'FULL_NATIVE_AST_EQUALS_SOURCE_COMPILED_TEMPLATE')
    nft.ruleset_mark_preflight(rules, _original_json=original_json)
    snapshot = nft._TableSnapshot(next(x['table'] for x in rows if 'table' in x), nft._OWNERSHIP_CAPABILITY)
    return nft._ValidatedOwnership(snapshot, nft._OWNERSHIP_CAPABILITY)


class _GuardedTransitionOrigin:
    """Original 47 observation retained by the same controller process only.

    This does not authorize a guarded send or accept a 50-object structure.
    """
    def __init__(self, pin, raw, capability):
        nft.require(capability is _CAPABILITY and type(pin) is _OriginalStructure
                    and pin.capability is _CAPABILITY and pin.pid == os.getpid(),
                    'ONLY_SAME_PROCESS_ORIGINAL_TRANSITION_ORIGIN')
        self._pin = pin
        self._raw = bytes(raw)
        self._raw_sha256 = hashlib.sha256(raw).hexdigest()
        self._pid = os.getpid()
        self._returned = time.monotonic()
        self._capability = capability
        self._consumed = False


def begin_guarded_transition(pin):
    """Independently reread the exact pinned 47 before any guarded mutation.

    The origin is not an ownership lease and never extends the original lease
    clock. It cannot be constructed from caller-provided or on-disk nft JSON.
    """
    nft.require(type(pin) is _OriginalStructure and pin.capability is _CAPABILITY
                and pin.pid == os.getpid(), 'SAME_PROCESS_ORIGINAL_STRUCTURE_NOT_DISK_OR_CALLER')
    reply = nft.command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_structure')
    nft.require(reply.returncode == 0, 'NATIVE_CURRENT_STRUCTURAL_READ')
    rows, rules, original_json = _objects(reply.stdout, _with_origin=True)
    nft.require(_handles(rows) == pin.handles, 'ALL_SAME_ORIGINAL_NATIVE_STRUCTURE_HEADER_AND_OBJECT_HANDLES')
    nft.require(hashlib.sha256(_structure(rows, keep_handles=False)).hexdigest() == COMPILED_NATIVE_AST_SHA256,
                'FULL_NATIVE_AST_EQUALS_SOURCE_COMPILED_TEMPLATE')
    nft.ruleset_mark_preflight(rules, _original_json=original_json)
    return _GuardedTransitionOrigin(pin, reply.stdout, _CAPABILITY)


# Disposable LAB proof only. These are explicit reviewed fixture identities,
# not runtime settings and not production authorization.
_LAB_GUARDIAN_UNIT = 'dakasa-lab-typed-guard-1030.service'
_LAB_GUARDIAN_SOURCE = '/var/tmp/dakasa-two-cluster-b5c117ab7f94221f3de4/lab_guarded_pin50_guardian_DRAFT.py'
_LAB_GUARDIAN_SHA256 = '7b25245d0fbe08334d916d824e5dfb3f04b5fddc555aa32fabdedf8a08f85a16'
_LAB_BOOT = '9930f6b8-f1e4-4542-a81b-9000e0efa4ed'


class _GuardedGuardianSession:
    def __init__(self, origin, channel, pid, ticks, invocation, pidfd, original_pin, genid, capability):
        nft.require(capability is _CAPABILITY, 'ONLY_PRIVATE_GUARDED_GUARDIAN_SESSION')
        self.origin, self.channel, self.pid, self.ticks = origin, channel, pid, ticks
        self.invocation, self.pidfd, self.original_pin, self.genid = invocation, pidfd, original_pin, genid
        self.capability = capability
        self.used = False
        self.active_receipt_sha256 = None


class _PositiveGuardianSession:
    """LAB-only, direct Guardian channel and fixture-origin 47; no production authority."""
    def __init__(self, sender, origin, original_guardian, capability):
        import guarded_sender_session_DRAFT as sp
        import transition_structure_DRAFT as transition
        nft.require(capability is _CAPABILITY and type(sender) is sp.SenderSession
                    and type(origin) is _GuardedTransitionOrigin and origin._capability is _CAPABILITY
                    and origin._pid == os.getpid() and origin._consumed and sender.pid == os.getpid()
                    and type(original_guardian) is _GuardedGuardianSession and original_guardian.origin is origin
                    and original_guardian.pid == sender.peer['pid'] and original_guardian.ticks == sender.peer['start_ticks']
                    and original_guardian.invocation == sender.peer['invocation_id'],
                    'ONLY_DIRECT_LAB_POSITIVE_GUARDIAN_SESSION')
        self.sender, self.origin, self.original_pin, self.capability = sender, origin, transition.OriginalPin(origin._raw), capability
        self.pid, self.ticks, self.pidfd = sender.peer['pid'], sender.peer['start_ticks'], sender.pidfd
        self.channel, self.used, self.active_receipt_sha256 = sender.channel, True, None
        self.attestation, self.original_guardian = None, original_guardian


def begin_lab_positive_guardian_session(sender, origin, original_guardian):
    """LAB fixture origin only; this does not attest a productive legacy cutover."""
    result = _PositiveGuardianSession(sender, origin, original_guardian, _CAPABILITY)
    _lab_guardian_alive(result)
    return result


def accept_lab_positive_guarded(session, emitter, attestation, *, previous_pin=None):
    """Mint only from this sender's direct Guardian response and held original receipt."""
    import guarded_sender_session_DRAFT as sp
    import guarded_generation as generation
    import guarded_nl as nl
    nft.require(type(session) is _PositiveGuardianSession and session.capability is _CAPABILITY
                and type(emitter) is generation.GenerationEmitter and emitter.pid == os.getpid()
                and emitter.state == 'AWAITING_FIXTURE_VERIFICATION' and type(attestation) is sp._PositiveAttestation
                and attestation.capability is sp._CAPABILITY and attestation.session is session.sender
                and attestation.pid == os.getpid(), 'ORIGINAL_DIRECT_POSITIVE_ATTESTATION_REQUIRED')
    receipt = emitter.receipt
    digest = hashlib.sha256(nl.canon(receipt)).hexdigest()
    nft.require(attestation.receipt_sha256 == digest and attestation.genid == receipt['after']
                and attestation.ids == tuple((r['program_id'],r['map_id']) for r in receipt['programs'])
                and time.monotonic_ns() < attestation.deadline_ns, 'EXACT_SENDER_RECEIPT_ATTESTATION')
    if previous_pin is None:
        nft.require(session.active_receipt_sha256 is None and receipt.get('original_47_lease_used') is True
                    and receipt.get('original_47_origin_sha256') == session.origin._raw_sha256
                    and receipt.get('genid') == session.original_guardian.genid,
                    'ONE_INITIAL_POSITIVE_PIN_WITH_ORIGINAL_47_LEASE_AND_ORIGIN')
    else:
        nft.require(type(previous_pin) is _GuardedStructure and previous_pin.session is session
                    and previous_pin.emitter is emitter and session.active_receipt_sha256 == hashlib.sha256(nl.canon(previous_pin.receipt)).hexdigest()
                    and receipt.get('guarded_lease_used') is True and receipt['genid'] == previous_pin.receipt['after']
                    and receipt.get('guarded_previous_receipt_sha256') == session.active_receipt_sha256,
                    'SAME_PREVIOUS_POSITIVE_PIN_AND_ORIGINAL_DISPATCHED_LEASE')
    _lab_guardian_alive(session)
    session.attestation, session.active_receipt_sha256 = attestation, digest
    return _GuardedStructure(session, emitter, receipt, _CAPABILITY)


class _GuardedStructure:
    def __init__(self, session, emitter, receipt, capability):
        nft.require(capability is _CAPABILITY and type(session) in (_GuardedGuardianSession, _PositiveGuardianSession)
                    and session.capability is _CAPABILITY and session.used,
                    'ONLY_ORIGINAL_AUTHENTICATED_GUARDED_PIN')
        self.session, self.emitter, self.receipt = session, emitter, copy.deepcopy(receipt)
        self.pid, self.capability = os.getpid(), capability
        self.attestation = session.attestation if type(session) is _PositiveGuardianSession else None


class _GuardedValidatedOwnership:
    def __init__(self, pin, capability):
        nft.require(capability is _CAPABILITY and type(pin) is _GuardedStructure,
                    'ONLY_SAME_PROCESS_GUARDED_OWNERSHIP')
        self.pin, self.capability = pin, capability
        self.pid, self.returned, self.consumed = os.getpid(), time.monotonic(), False


def _lab_guardian_alive(session):
    import select
    if type(session) is _PositiveGuardianSession:
        sender = session.sender
        _lab_guardian_alive(session.original_guardian)
        nft.require(not sender.closed and os.getpid() == sender.pid
                    and os.readlink('/proc/self/ns/net') == sender.netns
                    and sender.nl.startticks(sender.pid) == sender.ticks
                    and sender.nl.startticks(session.pid) == session.ticks,
                    'SAME_LIVE_POSITIVE_GUARDIAN_AND_SENDER')
        p = select.poll();p.register(session.pidfd, select.POLLIN)
        nft.require(not p.poll(0), 'POSITIVE_GUARDIAN_PIDFD_MUST_BE_LIVE')
        p = select.poll();p.register(session.channel, select.POLLIN | select.POLLHUP | select.POLLERR)
        nft.require(not p.poll(0), 'POSITIVE_GUARDIAN_CHANNEL_MUST_BE_QUIET')
        return
    p = select.poll()
    p.register(session.pidfd, select.POLLIN)
    nft.require(not p.poll(0), 'ORIGINAL_GUARDIAN_PIDFD_MUST_BE_LIVE')
    p = select.poll()
    p.register(session.channel, select.POLLHUP | select.POLLERR)
    nft.require(not p.poll(0), 'ORIGINAL_GUARDIAN_CHANNEL_MUST_BE_LIVE')


def _lab_read_line(channel):
    data = bytearray()
    while len(data) <= 65536:
        part = channel.recv(1)
        nft.require(bool(part), 'GUARDIAN_CHANNEL_EOF')
        if part == b'\n':
            return json.loads(data)
        data.extend(part)
    raise nft.Held('GUARDIAN_CHANNEL_MESSAGE_TOO_LARGE')


def begin_lab_guardian_session(origin, channel):
    """Before commit, bind exact 47 to a separately authenticated LAB unit."""
    import guarded_nl as nl
    import socket
    import struct
    import subprocess
    import transition_structure_DRAFT as transition
    nft.require(type(origin) is _GuardedTransitionOrigin and origin._capability is _CAPABILITY
                and origin._pid == os.getpid() and not origin._consumed,
                'LIVE_ORIGINAL_47_TRANSITION_ORIGIN_REQUIRED')
    nft.require(open('/proc/sys/kernel/random/boot_id').read().strip() == _LAB_BOOT,
                'ONLY_EXACT_DISPOSABLE_LAB_BOOT')
    nft.require(type(channel) is socket.socket, 'ORIGINAL_GUARDIAN_SOCKET_REQUIRED')
    pid, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    nft.require(uid == 0 and pid > 1, 'EXACT_ROOT_GUARDIAN_PEER')
    output = subprocess.run(['/usr/bin/systemctl', 'show', _LAB_GUARDIAN_UNIT,
        '--property=MainPID,InvocationID,ActiveState,SubState,ExecStart'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True).stdout.decode()
    props = dict(row.split('=', 1) for row in output.splitlines() if '=' in row)
    nft.require(props.get('MainPID') == str(pid) and props.get('ActiveState') == 'active'
                and props.get('SubState') == 'running'
                and re.fullmatch('[a-f0-9]{32}', props.get('InvocationID', '')) is not None
                and _LAB_GUARDIAN_SOURCE in props.get('ExecStart', ''), 'EXACT_LAB_GUARDIAN_UNIT')
    source = open(_LAB_GUARDIAN_SOURCE, 'rb').read()
    nft.require(hashlib.sha256(source).hexdigest() == _LAB_GUARDIAN_SHA256,
                'EXACT_LAB_GUARDIAN_SOURCE')
    cmdline = open('/proc/%d/cmdline' % pid, 'rb').read().split(b'\0')
    nft.require(_LAB_GUARDIAN_SOURCE.encode() in cmdline and b'guardian' in cmdline,
                'EXACT_LAB_GUARDIAN_PROCESS')
    ticks = nl.startticks(pid)
    pidfd = os.pidfd_open(pid, 0)
    try:
        original_pin = transition.OriginalPin(origin._raw)
        hello = _lab_read_line(channel)
        nft.require(hello.get('schema') == 'lab_guardian_47_origin_v1'
                    and hello.get('pid') == pid and hello.get('invocation_id') == props['InvocationID']
                    and hello.get('origin_digest') == original_pin.digest
                    and type(hello.get('genid')) is int and 0 < hello['genid'] < (1 << 32),
                    'INDEPENDENT_GUARDIAN_ORIGINAL_47_PIN')
        result = _GuardedGuardianSession(origin, channel, pid, ticks, props['InvocationID'],
                                         pidfd, original_pin, hello['genid'], _CAPABILITY)
        _lab_guardian_alive(result)
        return result
    except BaseException:
        os.close(pidfd)
        raise


def accept_lab_guarded_transition(session, emitter, plan, *, previous_pin=None):
    """Accept only deny-only LAB 50 after receipt from that exact Guardian socket."""
    import base64
    import guarded_generation as generation
    import guarded_nl as nl
    import secrets
    nft.require(type(session) is _GuardedGuardianSession and session.capability is _CAPABILITY
                and type(emitter) is generation.GenerationEmitter
                and emitter.pid == os.getpid() and emitter.state == 'AWAITING_FIXTURE_VERIFICATION'
                and session.origin._pid == os.getpid() and session.origin._consumed,
                'SAME_PROCESS_PENDING_EMITTER_AND_GUARDIAN_REQUIRED')
    nft.require((not session.used and previous_pin is None) or
                (session.used and type(previous_pin) is _GuardedStructure
                 and previous_pin.capability is _CAPABILITY and previous_pin.session is session
                 and previous_pin.emitter is emitter
                 and session.active_receipt_sha256 == hashlib.sha256(nl.canon(previous_pin.receipt)).hexdigest()),
                'ONLY_FIRST_OR_CURRENT_GUARDED_TRANSITION')
    _lab_guardian_alive(session)
    receipt = emitter.receipt
    if previous_pin is None:
        nft.require(receipt.get('original_47_lease_used') is True
                    and receipt.get('genid') == session.genid
                    and receipt.get('original_47_origin_sha256') == session.origin._raw_sha256
                    and receipt.get('genid') == session.original_guardian.genid,
                    'ORIGINAL_47_LEASE_AND_ORIGIN_IN_RECEIPT')
    else:
        nft.require(receipt.get('guarded_lease_used') is True
                    and receipt.get('genid') == previous_pin.receipt['after']
                    and receipt.get('guarded_previous_receipt_sha256') == session.active_receipt_sha256,
                    'ORIGINAL_GUARDED_LEASE_AND_PREVIOUS_RECEIPT')
    nft.require(type(plan) is dict and set(plan) == {'maps', 'backends', 'cores', 'prom'}
                and type(plan['maps']) is dict and set(plan['maps']) == {'inbound', 'reverse'}
                and not plan['backends'] and not plan['cores'] and not plan['prom']
                and all(plan['maps'][role] and all(deadline == 1 for _, deadline in plan['maps'][role])
                        for role in ('inbound', 'reverse')), 'DENY_ONLY_LAB_PROOF')
    result = {'ok': True, 'counter': emitter.counter, **receipt}
    anchor = {'pid': os.getpid(), 'start_ticks': nl.startticks(os.getpid()),
              'netns': os.readlink('/proc/self/ns/net'),
              'initial': base64.b64encode(session.origin._raw).decode()}
    nonce = secrets.token_hex(32)
    session.channel.sendall(nl.canon({'result': result, 'anchor': anchor, 'plan': plan, 'nonce': nonce}))
    answer = _lab_read_line(session.channel)
    nft.require(answer.get('schema') == 'lab_guardian_50_attestation_v1'
                and answer.get('guardian_pid') == session.pid
                and answer.get('invocation_id') == session.invocation
                and answer.get('origin_digest') == session.original_pin.digest
                and answer.get('nonce') == nonce and answer.get('sender_pid') == os.getpid()
                and answer.get('receipt_sha256') == hashlib.sha256(nl.canon(receipt)).hexdigest()
                and answer.get('genid') == receipt['after'] and answer.get('chain') == receipt['chain']
                and answer.get('handles') == receipt['handles'] and answer.get('deny_only') is True,
                'AUTHENTICATED_ORIGINAL_GUARDIAN_50_ATTESTATION')
    _lab_guardian_alive(session)
    session.used = True
    session.active_receipt_sha256 = hashlib.sha256(nl.canon(receipt)).hexdigest()
    return _GuardedStructure(session, emitter, receipt, _CAPABILITY)


def revalidate_lab_guarded(pin):
    """Issue a distinct guarded token; a legacy refresh cannot consume it."""
    import guarded_nl as nl
    import socket
    import transition_structure_DRAFT as transition
    nft.require(type(pin) is _GuardedStructure and pin.capability is _CAPABILITY
                and pin.pid == os.getpid() and pin.session.used, 'SAME_PROCESS_LAB_GUARDED_PIN')
    _lab_guardian_alive(pin.session)
    nft.require(((pin.emitter.state == 'AWAITING_FIXTURE_VERIFICATION' and pin.emitter.receipt == pin.receipt)
                 or (pin.emitter.state == 'READY' and pin.emitter.active_receipt == pin.receipt))
                and pin.session.active_receipt_sha256 == hashlib.sha256(nl.canon(pin.receipt)).hexdigest(),
                'SAME_LIVE_EMITTER_RECEIPT_CUSTODY')
    nft.require(nl.startticks(pin.session.pid) == pin.session.ticks, 'SAME_GUARDIAN_PROCESS')
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)
    sock.bind((0, 0));sock.settimeout(5)
    try:
        first = nl.genid(sock)
        reply = nft.command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_structure')
        nft.require(reply.returncode == 0, 'NATIVE_CURRENT_STRUCTURAL_READ')
        rows, rules, original_json = _objects(reply.stdout, _with_origin=True)
        transition.verify_guarded(pin.session.original_pin, reply.stdout,
            observed_chain_handle=pin.receipt['chain'], observed_rule_handles=tuple(pin.receipt['handles']))
        nft.ruleset_mark_preflight(rules, _original_json=original_json)
        nft.require(nl.genid(sock) == first == pin.receipt['after'], 'SAME_GUARDED_GENERATION')
    finally:
        sock.close()
    map_groups = {}
    for role, entry in zip(('inbound','reverse'), pin.receipt['programs']):
        program = nl.fdinfo(os.getpid(), entry['program_fd'])
        m = nl.fdinfo(os.getpid(), entry['map_fd'])
        nft.require(int(program['prog_id']) == entry['program_id']
                    and int(m['map_id']) == entry['map_id'] and m['frozen'].strip() == '1',
                    'LIVE_ORIGINAL_GUARDED_PROGRAM_AND_FROZEN_MAP_FDS')
        map_rows = nl.map_rows(entry['map_id'])
        nft.require(bool(map_rows), 'NONEMPTY_GUARDED_MAP')
        if type(pin.session) is _PositiveGuardianSession:
            nft.require(all(deadline > time.monotonic_ns() for key, deadline in map_rows), 'POSITIVE_MAPS_NOT_EXPIRED')
            map_groups[role] = [[key.hex(), deadline] for key,deadline in sorted(map_rows)]
        else:
            nft.require(all(deadline == 1 for key, deadline in map_rows), 'ONLY_EXPIRED_DENY_MAPS_ACCEPTED_BY_LAB_PIN')
    if type(pin.session) is _PositiveGuardianSession:
        a = pin.attestation
        nft.require(a is pin.session.attestation and a.receipt_sha256 == pin.session.active_receipt_sha256
                    and time.monotonic_ns() < a.deadline_ns
                    and hashlib.sha256(nl.canon(map_groups)).hexdigest() == a.digest,
                    'SAME_LIVE_POSITIVE_GUARDIAN_ATTESTED_MAPS_AND_DEADLINE')
    _lab_guardian_alive(pin.session)
    return _GuardedValidatedOwnership(pin, _CAPABILITY)


def consume_lab_guarded_ownership(token, pin, maximum_age):
    nft.require(type(maximum_age) in (int, float) and 0 < maximum_age <= .750,
                'GUARDED_OWNERSHIP_MAXIMUM_750MS')
    nft.require(type(token) is _GuardedValidatedOwnership and token.capability is _CAPABILITY
                and token.pid == os.getpid() and token.pin is pin and not token.consumed,
                'ONLY_ONE_USE_GUARDED_OWNERSHIP')
    token.consumed = True
    nft.require(0 <= time.monotonic() - token.returned < maximum_age,
                'GUARDED_OWNERSHIP_NOT_RENEWED')
    _lab_guardian_alive(pin.session)


class _OwnershipReader:
    """One demand-driven same-PID full native reader; one never-renewed slot.

    The initializer pin comes from this process's native echo or exact read-adoption.
    No deserialization, caller token, callback validator or public offer API.
    Only the main thread takes a token; nft.native_refresh consumes it once.
    """
    def __init__(self, pin, stop, wake):
        nft.require(type(pin) in (_OriginalStructure, _GuardedStructure)
                    and pin.capability is _CAPABILITY and pin.pid == os.getpid(),
                    'SAME_ORIGINAL_INITIALIZER_FOR_OWNERSHIP_READER')
        self._pin, self._stop, self._wake = pin, stop, wake
        self._lock = threading.Lock()
        self._slot = None
        self._error = None
        self._sequence = 0
        self._failures = 0
        self._failure_epoch = 0
        self._failed = threading.Event()
        self._thread = None
        self._committer_thread = threading.get_ident()
        self._reading = False
        self._lease = None
        self._demand = threading.Event()
        self._requested = False

    def _produce(self):
        read_started = None
        while not self._stop.is_set():
            with self._lock:
                if self._stop.is_set():
                    return
                now = time.monotonic()
                token = self._slot
                age = None if token is None else now-token.returned
                if token is not None and (token.consumed or not 0 <= age < .250):
                    self._slot = token = None
                if token is not None:
                    self._requested = False  # a ready original slot satisfies demand
                delay = 0 if read_started is None else max(0., .250-(now-read_started))
                read = self._requested and self._lease is None and delay == 0
                self._demand.clear()  # clear and inspect requests under the SAME lock
                if read:
                    self._requested = False
                    self._reading = True
                    wait = None
                else:
                    # A quiet token expires once; no periodic native replacement.
                    # With no token or demand, block until request/close wakes us.
                    wait = delay if self._requested and self._lease is None else (
                        max(0., .250-age) if token is not None else None)
            if not read:
                self._demand.wait(wait)
                continue
            read_started = time.monotonic()
            try:
                token = revalidate_lab_guarded(self._pin) if type(self._pin) is _GuardedStructure else revalidate(self._pin)
                facts = nft.native_io.last_facts()
                if self._stop.is_set():
                    return
                with self._lock:
                    nft.require(self._sequence < (1 << 63)-1, 'BOUNDED_ORIGINAL_OWNERSHIP_SEQUENCE')
                    self._sequence += 1
                    # Publish exact object/clock AND release the full read/parse
                    # lane atomically, before waking its only consuming thread.
                    self._slot = token
                    self._error = None
                    self._facts = facts
                    self._failed.clear()
                    self._reading = False
                self._wake.set()
            except Exception as error:
                with self._lock:
                    self._failed.set()
                    self._slot = None
                    self._failures += 1
                    self._failure_epoch += 1
                    nft.require(self._failures <= (1 << 63)-1, 'BOUNDED_OWNERSHIP_READ_FAILURES')
                    guard = str(error) if isinstance(error, (nft.Held,nft.native_io.process.Held)) and re.fullmatch('[A-Z0-9_]{1,160}',str(error)) else None
                    self._error = {'error_class':type(error).__name__,'closed_guard':guard,'failures':self._failures}
                    self._reading = False
                # Retry only after another explicit pending-consumer request.
                # This is a new original GET, never an uncertain apply replay.
                self._wake.set()
                self._stop.wait(.050)
            finally:
                with self._lock:
                    self._reading = False
                self._wake.set()

    def start(self):
        nft.require(self._thread is None, 'ONE_ORIGINAL_OWNERSHIP_READER_START')
        self._thread=threading.Thread(target=self._produce,daemon=True)
        self._thread.start()

    def take(self):
        nft.require(threading.get_ident()==self._committer_thread,'ONLY_ORIGINAL_MAIN_THREAD_TAKES_OWNERSHIP')
        nft.require(self._thread is None or self._thread.is_alive() or self._stop.is_set(),
                    'ORIGINAL_OWNERSHIP_READER_NOT_UNEXPECTEDLY_EXITED')
        with self._lock:
            # In-flight original full read/parse absorbs this demand; an
            # active hot lease excludes all replacement native work.
            if self._reading or self._lease is not None:
                return None, None
            token=self._slot
            if token is None:
                # The sole main caller invokes take only for a changed cache
                # key. An in-flight read/lease above absorbs concurrent demand.
                if not self._stop.is_set():
                    self._requested=True;self._demand.set()
                return None, self._error
            self._slot=None
            age = time.monotonic()-token.returned
            if token.consumed or not 0 <= age < .750 or not 0 <= age < .250:
                if not self._stop.is_set():
                    self._requested=True;self._demand.set()
                return None, {'error_class':'OriginalOwnershipExpired','closed_guard':'ORIGINAL_OWNERSHIP_REVALIDATION_NOT_RENEWED','failures':self._failures}
            # The slot is cleared BEFORE the caller can apply. This token can
            # never be re-offered even if a pure pre-send fence discards it.
            lease=_Lease(token,self,self._failure_epoch,_CAPABILITY)
            self._requested=False
            self._lease=lease
            return (lease,{'sequence':self._sequence,'original_returned':token.returned,'original_native_facts':self._facts}), None

    def permit_original_send(self, lease, attempt_started):
        """Pure pre-command linearization; never catches a sent/unknown apply.

        A failure published after take invalidates that borrowed token too.
        Once this short guarded decision completes, a later concurrent read
        is a later event; this is not a claim about future foreign mutations.
        """
        with self._lock:
            nft.require(threading.get_ident()==self._committer_thread,'ONLY_ORIGINAL_MAIN_THREAD_DECIDES_SEND')
            nft.require(type(lease) is _Lease and lease._capability is _CAPABILITY
                and lease.reader is self and self._lease is lease and not self._reading
                and not lease.dispatched,'ONE_PRIVATE_OWNERSHIP_SEND_DECISION')
            now=time.monotonic()
            if self._stop.is_set() or self._failed.is_set() or lease.failure_epoch != self._failure_epoch or not 0 <= now-lease.token.returned < .750:
                raise _NoOwnershipSend('R16_OWNERSHIP_INVALIDATED_BEFORE_NATIVE_SEND',attempt_started,now)
            lease.dispatched=True
            return True

    def adopt_lab_guarded_pin(self, old_pin, new_pin, lease):
        """Swap only while this main thread holds the dispatched guarded lease."""
        with self._lock:
            nft.require(threading.get_ident() == self._committer_thread
                        and self._pin is old_pin and type(old_pin) is _GuardedStructure
                        and type(new_pin) is _GuardedStructure and old_pin.session is new_pin.session
                        and old_pin.emitter is new_pin.emitter and self._lease is lease
                        and type(lease) is _Lease and lease.reader is self
                        and lease.dispatched and lease.token.consumed and not self._reading,
                        'ONLY_SAME_DISPATCHED_GUARDED_LEASE_SWAPS_PIN')
            _lab_guardian_alive(new_pin.session)
            self._pin = new_pin

    def release(self, lease):
        # The original main thread releases ONLY after the complete hot
        # render/call/EOF/Wait/Close path or its pre-command discard. Unknown
        # apply still propagates fatally; releasing never reoffers its token.
        with self._lock:
            nft.require(threading.get_ident()==self._committer_thread
                and type(lease) is _Lease and lease._capability is _CAPABILITY
                and lease.reader is self and self._lease is lease,
                'ONLY_ORIGINAL_MAIN_THREAD_RELEASES_HOT_LANE')
            self._lease=None
        self._wake.set();self._demand.set()

    def close_join(self, original_deadline):
        self._stop.set();self._wake.set();self._demand.set()
        if self._thread is not None:self._thread.join(max(0,original_deadline-time.monotonic()))
        nft.require(self._thread is None or not self._thread.is_alive(), 'ORIGINAL_OWNERSHIP_READER_FULLY_JOINED')


class _Lease:
    def __init__(self,token,reader,failure_epoch,capability):
        nft.require(capability is _CAPABILITY,'ONLY_PRIVATE_ORIGINAL_TOKEN_LEASE')
        self.token,self.reader,self.failure_epoch=token,reader,failure_epoch
        self._capability,self.dispatched=capability,False


class _NoOwnershipSend(nft.NoSend):
    """Only the pure callback before nft.command can emit this discard."""
