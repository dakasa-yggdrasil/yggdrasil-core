"""Pure fixed-topology nft renderer plus explicitly owned native operations.

Nothing runs or changes on import. Kernel syntax and paths require Root's real
Brain nft -c and end-to-end qualification before installation.
"""
from dataclasses import dataclass
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import math
import os
import native_io
import time

TABLE = 'dakasa_capacity_network'
COMMENT = 'dakasa-owned-capacity-overlay-v1'
WG = 'wg-capacity'
MARK = '0xda240001'
HUB = '10.201.24.1'
BRAIN = '10.250.0.50'
PEERS = tuple('10.201.24.' + str(x) for x in (*range(17, 25), *range(145, 153)))
VIP_PORTS = {'core': (HUB, 9443), 'broker': (HUB, 5671), 'rds': ('10.201.24.2', 5432), 'redis': ('10.201.24.3', 6379)}
PORTS = {'core': 9443, 'broker': 32674, 'rds': 5432, 'redis': 6379}
MAX_FRESH_SECONDS = 30
COMMIT_RESERVE_SECONDS = 3
PROPOSED_HOT_COMMIT_RESERVE_SECONDS = .750


class Held(Exception):
    pass


class NoSend(Exception):
    """Only a local pre-apply margin discard; no native child was invoked."""
    def __init__(self, guard, started, discarded):
        super().__init__(guard)
        self.guard, self.started, self.discarded = guard, started, discarded


def _refresh_pre_send_margin(started, guard):
    observed = time.monotonic()
    if observed - started >= .050:
        raise NoSend(guard, started, observed)


def require(value, reason):
    if not value:
        raise Held(reason)


def ipv4(value):
    require(isinstance(value, str), 'IP_TYPE')
    try:
        parsed = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise Held('IP_SHAPE') from None
    require(str(parsed) == value, 'CANONICAL_IP')
    return parsed


@dataclass(frozen=True)
class Backend:
    kind: str
    address: str
    port: int
    observed_started: float
    expires: float
    native_identity: str

    def validate(self):
        require(self.kind in PORTS and self.port == PORTS[self.kind], 'FIXED_DESTINATION_PORT')
        ip = ipv4(self.address)
        network = '10.244.0.0/16' if self.kind == 'core' else '172.18.0.0/16'
        require(ip in ipaddress.IPv4Network(network), 'FIXED_BACKEND_RANGE')
        require(self.address != BRAIN and self.address != '172.18.0.1' and self.address not in PEERS, 'NO_HUB_OR_PEER_BACKEND')
        require(isinstance(self.observed_started, (int, float)) and isinstance(self.expires, (int, float)) and math.isfinite(self.observed_started) and math.isfinite(self.expires) and 0 < self.expires - self.observed_started <= MAX_FRESH_SECONDS, 'NATIVE_OBSERVATION_WINDOW')
        require(isinstance(self.native_identity, str) and 0 < len(self.native_identity) <= 256 and '\n' not in self.native_identity, 'NATIVE_IDENTITY_REQUIRED')


@dataclass(frozen=True)
class PrometheusSource:
    address: str
    observed_started: float
    expires: float
    native_identity: str

    def validate(self):
        require(ipv4(self.address) in ipaddress.IPv4Network('10.244.0.0/16'), 'PROMETHEUS_POD_SOURCE_RANGE')
        require(type(self.observed_started) in (int, float) and type(self.expires) in (int, float)
                and math.isfinite(self.observed_started) and math.isfinite(self.expires)
                and 0 < self.expires - self.observed_started <= MAX_FRESH_SECONDS, 'PROMETHEUS_NATIVE_OBSERVATION_WINDOW')
        require(isinstance(self.native_identity, str) and 0 < len(self.native_identity) <= 512
                and '\n' not in self.native_identity, 'PROMETHEUS_NATIVE_LIFETIME_REQUIRED')


def _eligibility(backends, *, now, core_sources=(), prometheus_sources=(), _timeout_milliseconds=False, _reserve_seconds=None):
    require(math.isfinite(now) and len(backends) <= 4 and len({x.kind for x in backends}) == len(backends), 'CLOSED_BACKEND_CENSUS')
    entries, bindings, cores = [], [], []
    for item in sorted(backends, key=lambda x: x.kind):
        item.validate()
        require(item.observed_started <= now, 'NO_FUTURE_OBSERVATION')
        remaining = _kernel_remaining(item.expires, now, _timeout_milliseconds, reserve_seconds=_reserve_seconds)
        if remaining <= 0:
            continue
        vip, port = VIP_PORTS[item.kind]
        unit = 'ms' if _timeout_milliseconds else 's'
        entries.append(f'{vip} . {port} timeout {remaining}{unit} : {item.address} . {item.port}')
        bindings.append(f'{vip} . {port} . {item.address} . {item.port} timeout {remaining}{unit}')
    candidates = core_sources or tuple(x for x in backends if x.kind == 'core')
    require(len(candidates) <= 8 and len({x.address for x in candidates}) == len(candidates), 'CORE_SOURCE_CENSUS')
    require(not candidates or any(x.kind == 'core' and any(c.address == x.address for c in candidates) for x in backends), 'CORE_SOURCE_AND_NAT_JOIN')
    for item in sorted(candidates, key=lambda x: x.address):
        item.validate()
        require(item.kind == 'core' and item.observed_started <= now, 'CORE_SOURCE_SCOPE')
        remaining = _kernel_remaining(item.expires, now, _timeout_milliseconds, reserve_seconds=_reserve_seconds)
        if remaining > 0:
            cores.append(f'{item.address} timeout {remaining}{"ms" if _timeout_milliseconds else "s"}')
    require(len(prometheus_sources) <= 1, 'SOLE_PROMETHEUS_SOURCE_CENSUS')
    prometheus = []
    for item in prometheus_sources:
        require(isinstance(item, PrometheusSource), 'SEPARATE_PROMETHEUS_SOURCE_TYPE_NOT_CORE_BACKEND')
        item.validate()
        require(item.observed_started <= now and not any(c.address == item.address for c in candidates), 'PROMETHEUS_SOURCE_LOCAL_TIME_AND_DISTINCT_CORE_ROLE')
        remaining = _kernel_remaining(item.expires, now, _timeout_milliseconds, reserve_seconds=_reserve_seconds)
        if remaining > 0:
            prometheus.append(f'{item.address} timeout {remaining}{"ms" if _timeout_milliseconds else "s"}')
    return entries, bindings, cores, prometheus


def render(backends, *, now, table_exists, core_sources=(), prometheus_sources=(), _timeout_milliseconds=False):
    entries, bindings, cores, prometheus = _eligibility(backends, now=now, core_sources=core_sources, prometheus_sources=prometheus_sources, _timeout_milliseconds=_timeout_milliseconds)
    peers = ', '.join(PEERS)
    fixed = ', '.join(f'{ip} . {port}' for ip, port in VIP_PORTS.values())
    remote = ', '.join(f'{ip} . {port}' for kind, (ip, port) in VIP_PORTS.items() if kind != 'core')
    # nft 1.0.2 infers ct proto-dst's fixed service type from explicit TCP
    # packet context before concatenation. Related ICMP has a TCP original
    # tuple but an ICMP packet: keep it in separate scalar tuple rules so PMTU
    # and native related errors are not lost by the TCP context requirement.
    related_vips = []
    for vip, port in VIP_PORTS.values():
        related_vips.append(f'  iifname "{WG}" ip saddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct status dnat ct direction original ct original protocol tcp ct original ip saddr @peers4 ct original ip daddr {vip} ct original proto-dst {port} accept')
        related_vips.append(f'  oifname "{WG}" ip daddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct status dnat ct direction reply ct original protocol tcp ct original ip saddr @peers4 ct original ip daddr {vip} ct original proto-dst {port} accept')
    related_vip_rules = '\n'.join(related_vips)
    prefix = f'delete table inet {TABLE}\n' if table_exists else ''
    # All statements below are one native nft batch. Deleting this one owned
    # table does not clear conntrack; prior approved streams retain NAT+mark.
    return prefix + f'''table inet {TABLE} {{
 comment "{COMMENT}"
 set peers4 {{ type ipv4_addr; flags constant; elements = {{ {peers} }}; }}
 set vips4 {{ type ipv4_addr . inet_service; flags constant; elements = {{ {fixed} }}; }}
 set remote_vips4 {{ type ipv4_addr . inet_service; flags constant; elements = {{ {remote} }}; }}
 set core_ready4 {{ type ipv4_addr; flags timeout; size 8; {'elements = { ' + ', '.join(cores) + ' };' if cores else ''} }}
 set prometheus_ready4 {{ type ipv4_addr; flags timeout; size 1; {'elements = { ' + ', '.join(prometheus) + ' };' if prometheus else ''} }}
 set backend_forward4 {{ type ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; size 8; {'elements = { ' + ', '.join(bindings) + ' };' if bindings else ''} }}
 map backend_dnat4 {{ type ipv4_addr . inet_service : ipv4_addr . inet_service; flags timeout; size 8; {'elements = { ' + ', '.join(entries) + ' };' if entries else ''} }}
 chain prerouting {{
  type nat hook prerouting priority -101; policy accept;
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp dnat ip to ip daddr . tcp dport map @backend_dnat4
 }}
 chain input_guard {{
  type filter hook input priority -10; policy accept;
  iifname "{WG}" counter drop
 }}
 chain admit_new {{
  ct mark 0 ct mark set {MARK} accept
  ct mark {MARK} accept
  return
 }}
 chain forward_guard {{
  type filter hook forward priority -10; policy accept;
  iifname "{WG}" oifname "{WG}" counter drop
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct status dnat ct direction original ct original ip saddr @peers4 ct original ip daddr . ct original proto-dst @vips4 accept
  oifname "{WG}" ip daddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct status dnat ct direction reply ct original ip saddr @peers4 ct original ip daddr . ct original proto-dst @vips4 accept
{related_vip_rules}
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct direction reply ct original ip daddr @peers4 ct original proto-dst 9447 accept
  oifname "{WG}" ip daddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct direction original ct original ip daddr @peers4 ct original proto-dst 9447 accept
  iifname "{WG}" ip saddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct direction reply ct original protocol tcp ct original ip daddr @peers4 ct original proto-dst 9447 accept
  oifname "{WG}" ip daddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct direction original ct original protocol tcp ct original ip daddr @peers4 ct original proto-dst 9447 accept
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct direction reply ct original ip daddr @peers4 ct original proto-dst 9080 accept
  oifname "{WG}" ip daddr @peers4 meta l4proto tcp ct state established,related ct mark {MARK} ct direction original ct original ip daddr @peers4 ct original proto-dst 9080 accept
  iifname "{WG}" ip saddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct direction reply ct original protocol tcp ct original ip daddr @peers4 ct original proto-dst 9080 accept
  oifname "{WG}" ip daddr @peers4 meta l4proto icmp ct state related ct mark {MARK} ct direction original ct original protocol tcp ct original ip daddr @peers4 ct original proto-dst 9080 accept
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp ct state new ct status dnat ct original ip daddr . ct original proto-dst . ip daddr . tcp dport @backend_forward4 jump admit_new
  oifname "{WG}" ip saddr @core_ready4 ip daddr @peers4 meta l4proto tcp tcp dport 9447 ct state new jump admit_new
  iifname "cni0" oifname "{WG}" ip saddr @prometheus_ready4 ip daddr @peers4 meta l4proto tcp tcp dport 9080 ct state new jump admit_new
  iifname "{WG}" counter drop
  oifname "{WG}" counter drop
 }}
 chain output_guard {{
  type filter hook output priority -10; policy accept;
  oifname "{WG}" counter drop
 }}
 chain postrouting {{
  type nat hook postrouting priority 99; policy accept;
  iifname "{WG}" ip saddr @peers4 meta l4proto tcp ct mark {MARK} ct original ip daddr . ct original proto-dst @remote_vips4 snat ip to 172.18.0.1
  oifname "{WG}" ip daddr @peers4 meta l4proto tcp ct mark {MARK} ct original ip daddr @peers4 ct original proto-dst 9447 snat ip to {HUB}
  oifname "{WG}" ip daddr @peers4 meta l4proto tcp ct mark {MARK} ct original ip daddr @peers4 ct original proto-dst 9080 snat ip to {HUB}
 }}
}}
'''


def _kernel_remaining(expires, now, milliseconds=False, *, reserve_seconds=None):
    if milliseconds:
        reserve = PROPOSED_HOT_COMMIT_RESERVE_SECONDS if reserve_seconds is None else reserve_seconds
        require(reserve in (.250, .750), 'CLOSED_ORIGINAL_NATIVE_BUDGET_CONTRACT')
        return math.floor(1000 * (expires - now - reserve))
    return math.floor(expires - now - COMMIT_RESERVE_SECONDS)


def command(args, *, data=None, timeout=2, role):
    try:
        return native_io.command(args, data=data, timeout=timeout, role=role)
    except native_io.process.Held as error:
        raise Held(str(error)) from None


_OWNERSHIP_CAPABILITY = object()


class _TableSnapshot:
    """Private native-read result; never decoded from a configuration or caller."""
    def __init__(self, header, capability):
        require(capability is _OWNERSHIP_CAPABILITY, 'NATIVE_SNAPSHOT_CONSTRUCTOR_ONLY')
        self.header = None if header is None else json.dumps(header, sort_keys=True, separators=(',', ':'))
        self.pid = os.getpid()
        self.capability = capability
        self.consumed = False

    @property
    def exists(self):
        return self.header is not None


class _ValidatedOwnership:
    """One batch's original post-collect read, under the controller's same lock."""
    def __init__(self, snapshot, capability):
        require(capability is _OWNERSHIP_CAPABILITY, 'NATIVE_REVALIDATION_CONSTRUCTOR_ONLY')
        self.exists = snapshot.exists
        self.header = snapshot.header
        self.pid = os.getpid()
        self.returned = time.monotonic()
        self.capability = capability
        self.consumed = False


def _owned_table_snapshot(*, require_handle):
    result = command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', TABLE], role='owned_json')
    if result.returncode != 0:
        # A missing table must be distinguished from denied/broken native nft.
        rules = command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_mark')
        require(rules.returncode == 0, 'NATIVE_NFT_READ_FAILED')
        all_tables = [v['table'] for v in json.loads(rules.stdout)['nftables'] if 'table' in v]
        require(not any(v.get('family') == 'inet' and v.get('name') == TABLE for v in all_tables), 'OWNED_TABLE_READ_UNKNOWN')
        return _TableSnapshot(None, _OWNERSHIP_CAPABILITY)
    tables = [v['table'] for v in json.loads(result.stdout)['nftables'] if 'table' in v]
    require(len(tables) == 1 and tables[0].get('family') == 'inet' and tables[0].get('name') == TABLE, 'EXISTING_TABLE_NOT_OWNED')
    first = tables[0]
    if require_handle:
        require(type(first.get('handle')) is int and first['handle'] > 0, 'NATIVE_TABLE_HANDLE_REQUIRED')
    if 'comment' in first:
        # A present foreign/null comment must NEVER fall back to text.
        require(first['comment'] == COMMENT, 'EXISTING_TABLE_NOT_OWNED')
    else:
        # Brain's native nft1.0.2 omits table comments only in JSON. Require
        # the SAME named table's original text header/table-level comment,
        # bracketed by native JSON reads of the SAME handle. No rule/child
        # comment, differently named table, replacement or unknown is accepted.
        require(type(first.get('handle')) is int and first['handle'] > 0, 'NATIVE_TABLE_HANDLE_REQUIRED')
        text = command(['/usr/sbin/nft', 'list', 'table', 'inet', TABLE], role='owned_text')
        require(text.returncode == 0, 'NATIVE_TABLE_COMMENT_READ_FAILED')
        table_text_identity(text.stdout)
        checked = command(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', TABLE], role='owned_bracket')
        require(checked.returncode == 0, 'NATIVE_TABLE_IDENTITY_RECHECK_FAILED')
        after = [v['table'] for v in json.loads(checked.stdout)['nftables'] if 'table' in v]
        require(after == [first], 'ORIGINAL_TABLE_HANDLE_CHANGED')
    return _TableSnapshot(first, _OWNERSHIP_CAPABILITY)


def owned_table():
    # Retain the check-only callers' existing boolean contract.
    return _owned_table_snapshot(require_handle=False).exists


def owned_table_snapshot():
    # The production controller calls this BEFORE fresh backend collection.
    # On nft1.0.2 this includes TEXT comment proof and the bracketing handle
    # read. No DNS evidence has yet begun its short interval.
    return _owned_table_snapshot(require_handle=True)


_JSON_ORIGIN_CAPABILITY = object()


class _OriginalJSONOrigin:
    """Call-local origin from the immediately preceding standard JSON decode.

    This is not an ownership or send permit. Only the two compiled native
    decoders construct it, and no mutable tree escapes between decode and
    validation on those paths. Generic Python callers keep the original walk.
    """
    def __init__(self, rules, raw, capability):
        require(capability is _JSON_ORIGIN_CAPABILITY, 'ONLY_ORIGINAL_JSON_DECODER_ORIGIN')
        self.rules, self.raw, self.capability = rules, raw, capability


def ruleset_mark_preflight(rules, *, _original_json=None):
    def uses_mark(value):
        # Only dict/list nodes can satisfy or contain the original predicate.
        # Inspect each dict's ct FIRST, preserving malformed-ct errors; then
        # visit every container child in the same left-to-right order.
        absent = object()
        containers = (dict, list)
        pending = [value]
        while pending:
            current = pending.pop()
            if isinstance(current, dict):
                ct = current.get('ct', absent)
                if ct is not absent and ct.get('key') == 'mark':
                    return True
                children = reversed(current.values())
            elif isinstance(current, list):
                children = reversed(current)
            else:
                continue
            for child in children:
                if isinstance(child, containers):
                    pending.append(child)
        return False
    if (_original_json is not None and type(_original_json) is _OriginalJSONOrigin
            and _original_json.capability is _JSON_ORIGIN_CAPABILITY
            and _original_json.rules is rules and type(_original_json.raw) is bytes
            and b'\\' not in _original_json.raw and b'\x00' not in _original_json.raw):
        # The same original bytes and default-decoded builtin tree are bound
        # by a call-local origin. No escape/backslash or UTF16/32 NUL can hide
        # an ASCII ct key on this fast path. Count every literal quoted ct in
        # the whole original JSON, then count it in EXACTLY the original
        # predicate's exempt values. Standard decode/encode cannot invent such
        # a token without escapes; duplicate/discarded raw keys can only add
        # unmatched raw tokens. Equality therefore leaves none in foreign
        # objects. Values named ct may force conservative fallback.
        # Any error restarts the ORIGINAL loop, never a partial roster.
        try:
            exempt = []
            for row in rules:
                for value in row.values():
                    if isinstance(value, dict) and value.get('family') == 'inet' and value.get('table') == TABLE:
                        exempt.append(value)
            encoded = json.dumps(exempt, separators=(',', ':'), ensure_ascii=False,
                                 allow_nan=False, check_circular=False)
            if _original_json.raw.count(b'"ct"') == encoded.count('"ct"'):
                return
        except Exception:
            pass
    for row in rules:
        for value in row.values():
            if isinstance(value, dict) and value.get('family') == 'inet' and value.get('table') == TABLE:
                continue
            require(not uses_mark(value), 'OTHER_NATIVE_CT_MARK_OWNER_REQUIRES_REVIEW')


def revalidate_owned_ruleset(snapshot):
    require(type(snapshot) is _TableSnapshot and snapshot.capability is _OWNERSHIP_CAPABILITY
            and snapshot.pid == os.getpid() and not snapshot.consumed, 'ORIGINAL_SAME_PROCESS_TABLE_SNAPSHOT')
    # Consume before the original read: failed/unknown reads cannot reuse it.
    snapshot.consumed = True
    result = command(['/usr/sbin/nft', '-j', 'list', 'ruleset'], role='ruleset_mark')
    require(result.returncode == 0, 'NATIVE_MARK_RULE_READ')
    rules = json.loads(result.stdout)['nftables']
    original_json = _OriginalJSONOrigin(rules, result.stdout, _JSON_ORIGIN_CAPABILITY)
    tables = [row['table'] for row in rules if 'table' in row
              and row['table'].get('family') == 'inet' and row['table'].get('name') == TABLE]
    expected = [] if not snapshot.exists else [json.loads(snapshot.header)]
    require(tables == expected, 'ORIGINAL_TABLE_HANDLE_HEADER_CHANGED')
    # A missing JSON comment is accepted ONLY because this exact header/handle
    # is the same one whose TEXT table-level comment was already proved.
    ruleset_mark_preflight(rules, _original_json=original_json)
    return _ValidatedOwnership(snapshot, _OWNERSHIP_CAPABILITY)


def table_text_identity(raw):
    lines = raw.decode('utf-8').splitlines()
    require(len(lines) >= 3 and lines[0] == 'table inet ' + TABLE + ' {'
            and lines[1].strip() == 'comment "' + COMMENT + '"'
            and lines[-1] == '}', 'EXACT_NATIVE_TABLE_HEADER_COMMENT')


def _native_batch_impl(backends, *, apply=False, core_sources=(), prometheus_sources=(), _ownership=None):
    if _ownership is None:
        exists = owned_table()
    else:
        require(type(_ownership) is _ValidatedOwnership and _ownership.capability is _OWNERSHIP_CAPABILITY
                and _ownership.pid == os.getpid() and not _ownership.consumed, 'ORIGINAL_ONE_USE_OWNERSHIP_REVALIDATION')
        _ownership.consumed = True
        age = time.monotonic() - _ownership.returned
        require(0 <= age < COMMIT_RESERVE_SECONDS, 'ORIGINAL_OWNERSHIP_REVALIDATION_NOT_RENEWED')
        exists = _ownership.exists
    started = time.monotonic()
    raw = render(backends, now=started, table_exists=exists, core_sources=core_sources, prometheus_sources=prometheus_sources).encode()
    checked = command(['/usr/sbin/nft', '-c', '-f', '-'], data=raw, timeout=.9, role='initial_static_check')
    require(checked.returncode == 0, 'NATIVE_NFT_CHECK_REFUSED')
    require(time.monotonic() - started < 1.2, 'NATIVE_CHECK_RESERVE_EXHAUSTED')
    if apply:
        done = command(['/usr/sbin/nft', '-f', '-'], data=raw, timeout=.9, role='initial_static_apply')
        require(done.returncode == 0 and time.monotonic() - started < COMMIT_RESERVE_SECONDS, 'NATIVE_ATOMIC_BATCH_UNKNOWN')
    freshness = {v.kind: {'effective_original_window_seconds': v.expires - v.observed_started,
                         'age_seconds_at_render': started - v.observed_started,
                         'remaining_seconds_before_reserve': v.expires - started,
                         'kernel_timeout_seconds': max(0, math.floor(v.expires - started - COMMIT_RESERVE_SECONDS))}
                 for v in backends}
    return {'schema': 'capacity_owned_nft_native_batch_v1', 'nft_source_sha256': hashlib.sha256(raw).hexdigest(), 'check_return_zero': True, 'applied': apply, 'backends_admitted': sum(max(0, math.floor(v.expires - started - COMMIT_RESERVE_SECONDS)) > 0 for v in backends), 'prometheus_sources_admitted': sum(max(0, math.floor(v.expires - started - COMMIT_RESERVE_SECONDS)) > 0 for v in prometheus_sources), 'kernel_timeout_maps': True, 'Core_or_VM_authority': False,
            'backend_freshness': freshness, 'original_native_batch_elapsed_seconds': time.monotonic() - started}


def render_refresh(backends, *, now, core_sources=(), prometheus_sources=()):
    entries, bindings, cores, prometheus = _eligibility(backends, now=now, core_sources=core_sources,
                                                       prometheus_sources=prometheus_sources,
                                                       _timeout_milliseconds=True, _reserve_seconds=.250)
    # ONE atomic transaction. Only four dynamic collections change; no table,
    # chain, rule, constant set, role, ctmark or established stream is reset.
    groups = [('set', 'core_ready4', cores), ('set', 'prometheus_ready4', prometheus),
              ('set', 'backend_forward4', bindings), ('map', 'backend_dnat4', entries)]
    lines = []
    for kind, name, elements in groups:
        lines.append('flush ' + kind + ' inet ' + TABLE + ' ' + name)
        if elements:
            lines.append('add element inet ' + TABLE + ' ' + name + ' { ' + ', '.join(elements) + ' }')
    return '\n'.join(lines) + '\n'


def check_refresh_template(backends, *, core_sources=(), prometheus_sources=()):
    # Exactly this typed four-collection syntax is checked before the first
    # mutation, against the existing R8 table with the same names and types.
    raw = render_refresh(backends, now=time.monotonic(), core_sources=core_sources, prometheus_sources=prometheus_sources).encode()
    checked = command(['/usr/sbin/nft', '-c', '-f', '-'], data=raw, timeout=.200, role='refresh_template_check')
    require(checked.returncode == 0, 'ORIGINAL_TYPED_REFRESH_TEMPLATE_CHECK_ZERO')
    return hashlib.sha256(raw).hexdigest()


def _consume_ownership(ownership, maximum_age):
    require(type(ownership) is _ValidatedOwnership and ownership.capability is _OWNERSHIP_CAPABILITY
            and ownership.pid == os.getpid() and not ownership.consumed, 'ORIGINAL_ONE_USE_OWNERSHIP_REVALIDATION')
    ownership.consumed = True
    require(0 <= time.monotonic() - ownership.returned < maximum_age, 'ORIGINAL_OWNERSHIP_REVALIDATION_NOT_RENEWED')


def _hot_facts(backends, core_sources, prometheus_sources, started, reserve, raw, *, applied, phase, native_returned):
    return {'schema': 'capacity_owned_nft_native_batch_v3', 'phase': phase,
            'nft_source_sha256': hashlib.sha256(raw).hexdigest(), 'applied': applied,
            'backends_admitted': sum(_kernel_remaining(x.expires, started, True, reserve_seconds=reserve) > 0 for x in backends),
            'prometheus_sources_admitted': sum(_kernel_remaining(x.expires, started, True, reserve_seconds=reserve) > 0 for x in prometheus_sources),
            'kernel_timeout_maps': True, 'Core_or_VM_authority': False,
            'proposed_native_budget_seconds': reserve, 'Root_full_apply_and_continuous_window_qualification_separate': True,
            'backend_freshness': {x.kind: {'address': x.address, 'port': x.port, 'original_started': x.observed_started, 'original_expires': x.expires,
                                          'age_seconds_at_render': started - x.observed_started,
                                          'kernel_timeout_ms': max(0, _kernel_remaining(x.expires, started, True, reserve_seconds=reserve))}
                                  for x in backends},
            'core_source_freshness': [{'address': x.address, 'original_started': x.observed_started, 'original_expires': x.expires, 'kernel_timeout_ms': max(0, _kernel_remaining(x.expires, started, True, reserve_seconds=reserve))} for x in core_sources],
            'prometheus_source_freshness': [{'address': x.address, 'original_started': x.observed_started, 'original_expires': x.expires, 'kernel_timeout_ms': max(0, _kernel_remaining(x.expires, started, True, reserve_seconds=reserve))} for x in prometheus_sources],
            'render_started': started, 'native_apply_returned': native_returned,
            'original_native_batch_elapsed_seconds': time.monotonic() - started}


# Static initialization has no expiring dynamic evidence. These SOURCE draft
# bounds were admitted for SOURCE after Root readonly probe717270, which
# did NOT reproduce original R10 failure. Actual apply/continuous qualification
# remains separate. These new static bounds do not
# change the hot transaction's 250ms expiry reserve or 200ms native child.
STATIC_CHECK_SECONDS = 2.0
STATIC_APPLY_SECONDS = 2.0
STATIC_INIT_SECONDS = 5.0


def _native_initialize_static_impl(*, apply, _ownership):
    import native_structure
    _consume_ownership(_ownership, .750)
    require(_ownership.exists is False, 'R37_COLD_CREATE_ONLY_NO_EXISTING_TABLE_REPLACEMENT')
    started = time.monotonic()
    raw = render((), now=started, table_exists=_ownership.exists,
                 core_sources=(), prometheus_sources=(), _timeout_milliseconds=True).encode()
    checked = command(['/usr/sbin/nft', '-c', '-f', '-'], data=raw,
                      timeout=STATIC_CHECK_SECONDS, role='initial_static_check')
    require(checked.returncode == 0 and time.monotonic() - started < STATIC_INIT_SECONDS - STATIC_APPLY_SECONDS,
            'ORIGINAL_STATIC_EMPTY_CHECK_AND_REMAINING_APPLY_BUDGET')
    pin, native_returned = None, None
    applied = bool(apply())
    if applied:
        require(time.monotonic() - started < STATIC_INIT_SECONDS - STATIC_APPLY_SECONDS,
                'ORIGINAL_STATIC_EMPTY_FINAL_PRE_SEND_FENCE')
        done = command(['/usr/sbin/nft', '-a', '-e', '-f', '-'], data=raw,
                       timeout=STATIC_APPLY_SECONDS, role='initial_static_apply')
        native_returned = time.monotonic()
        require(done.returncode == 0 and native_returned - started < STATIC_INIT_SECONDS,
                'ORIGINAL_STATIC_EMPTY_ATOMIC_APPLY_ECHO_UNKNOWN')
        pin = native_structure.from_original_apply_echo(done.stdout, hashlib.sha256(raw).hexdigest())
        require(time.monotonic() - started < STATIC_INIT_SECONDS,
                'ORIGINAL_STATIC_EMPTY_ECHO_DECODE_INSIDE_SAME_BUDGET')
    result = _hot_facts((), (), (), started, STATIC_INIT_SECONDS, raw,
        applied=applied, phase='initial_static_no_dynamic', native_returned=native_returned)
    result.update(check_return_zero=True, static_dynamic_collections_empty=True,
        original_native_echo_handles=None if pin is None else [{'key':list(k),'handle':v} for k,v in sorted(pin.handles.items())],
        compiled_native_ast_sha256=native_structure.COMPILED_NATIVE_AST_SHA256,
        original_native_command_facts=native_io.last_facts())
    return result, pin


def _native_refresh_impl(backends, *, core_sources=(), prometheus_sources=(), apply, _ownership):
    _consume_ownership(_ownership, .750)
    started = time.monotonic()
    raw = render_refresh(backends, now=started, core_sources=core_sources, prometheus_sources=prometheus_sources).encode()
    _refresh_pre_send_margin(started, 'ORIGINAL_TYPED_REFRESH_PRE_SEND_MARGIN')
    native_returned = None
    applied = bool(apply())
    if applied:
        _refresh_pre_send_margin(started, 'ORIGINAL_REFRESH_FINAL_PRE_SEND_FENCE')
        done = command(['/usr/sbin/nft', '-f', '-'], data=raw, timeout=min(.200, .250 - (time.monotonic() - started)), role='hot_dynamic_apply')
        native_returned = time.monotonic()
        require(done.returncode == 0 and native_returned - started < .250, 'ORIGINAL_250MS_ATOMIC_REFRESH_UNKNOWN_NO_REPLAY')
    result = _hot_facts(backends, core_sources, prometheus_sources, started, .250, raw, applied=applied, phase='only_dynamic_elements', native_returned=native_returned)
    result['original_native_command_facts'] = native_io.last_facts() if applied else None
    require(time.monotonic() - started < .250, 'ORIGINAL_REFRESH_FACTS_WITHIN_SAME_BUDGET')
    return result


# CI-only common typed-writer gate; every caller, including non-controller
# callers, is checked before native I/O. Production binding is not provided.
CI_DRAIN_COORDINATION = None

def _ci_coordination():
    import drain_marker_v3_DRAFT as drain_v3
    require(os.environ.get('CI_GUARDED_FIXTURE')=='1'
            and type(CI_DRAIN_COORDINATION) is drain_v3.CoordinatorV3,
            'ONLY_BOUND_CI_DRAIN_COORDINATOR')
    return CI_DRAIN_COORDINATION


def _enter_writer(stack, coord, started):
    from drain_coordination_DRAFT import FenceError
    try:return stack.enter_context(coord.admission_or_other_writer())
    except FenceError as error:
        raise NoSend('DRAFT_DRAIN_COORDINATION_HOLD',started,time.monotonic()) from error

def _enter_writer_lease(stack, coord, started):
    from drain_coordination_DRAFT import FenceError
    try:return stack.enter_context(coord.writer_lease())
    except (FenceError,BlockingIOError) as error:
        raise NoSend('DRAFT_WRITER_LEASE_HOLD',started,time.monotonic()) from error

def native_batch(backends, *, apply=False, core_sources=(), prometheus_sources=(), _ownership=None):
    from drain_coordination_DRAFT import FenceError
    coord=_ci_coordination();started=time.monotonic()
    with ExitStack() as stack:
        _enter_writer_lease(stack,coord,started)
        state=_enter_writer(stack,coord,started)
        for item in (*backends,*core_sources):
            if item.kind=='core':
                try:coord.base.require_allowed(state,item.native_identity.split('/',1)[0],item.address)
                except FenceError as error:
                    raise NoSend('DRAFT_RETIRED_CORE_SOURCE',started,time.monotonic()) from error
        with coord.typed_native_send():
            return _native_batch_impl(backends,apply=apply,core_sources=core_sources,
                                      prometheus_sources=prometheus_sources,_ownership=_ownership)

def native_refresh(backends, *, core_sources=(), prometheus_sources=(), apply, _ownership):
    import partial_refresh_DRAFT as partial
    from drain_coordination_DRAFT import FenceError
    coord=_ci_coordination();started=time.monotonic()
    with ExitStack() as stack:
        _enter_writer_lease(stack,coord,started)
        state=_enter_writer(stack,coord,started)
        core=[item for item in backends if item.kind=='core']
        require(len(core)<=1,'DRAFT_ONE_CORE_BACKEND')
        retired=False;eligible=[]
        for item in core:
            try:coord.base.require_allowed(state,item.native_identity.split('/',1)[0],item.address)
            except FenceError as error:
                if str(error)!='RETIRED_BACKEND':
                    raise NoSend('DRAFT_DRAIN_COORDINATION_HOLD',started,time.monotonic()) from error
                retired=True
        for item in core_sources:
            require(item.kind=='core','DRAFT_ONLY_CORE_SOURCES')
            try:coord.base.require_allowed(state,item.native_identity.split('/',1)[0],item.address)
            except FenceError as error:
                if str(error)!='RETIRED_BACKEND':
                    raise NoSend('DRAFT_DRAIN_COORDINATION_HOLD',started,time.monotonic()) from error
                retired=True
            else:eligible.append(item)
        # No exception after entering a writer is converted to NoSend.
        with coord.typed_native_send():
            if retired:
                return partial.native_partial(backends,core_sources=eligible,
                    prometheus_sources=prometheus_sources,state=state,apply=apply,_ownership=_ownership)
            return _native_refresh_impl(backends,core_sources=core_sources,
                                        prometheus_sources=prometheus_sources,apply=apply,_ownership=_ownership)

def native_initialize_static(*, apply, _ownership):
    coord=_ci_coordination();started=time.monotonic()
    with ExitStack() as stack:
        _enter_writer_lease(stack,coord,started)
        _enter_writer(stack,coord,started)
        with coord.typed_native_send():
            return _native_initialize_static_impl(apply=apply,_ownership=_ownership)
