"""Pure SOURCE candidate. No socket/native/files/clock/config/daemon operations.

Objects are minted only from the same reader's completed original DNS wire and
the immediately following native route facts. No serialized witness API exists.
Integration into a future source epoch requires Root's separate review/owner.
"""
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import math
import struct

NAMES = {'rds': 'rds.lab.invalid', 'redis': 'redis.lab.invalid'}
PORTS = {'rds': 5432, 'redis': 6379}
_DNS, _ZERO, _ROUTE, _WHOLE = object(), object(), object(), object()


class Held(Exception):
    pass


def require(value, reason):
    if not value:
        raise Held(reason)


def number(value):
    return type(value) in (float, int) and math.isfinite(value)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def name_at(raw, start):
    # Exact bounded DNS pointer/label semantics of current dns_native.py.
    labels, position, returned, seen = [], start, None, set()
    while True:
        require(position < len(raw) and position not in seen and len(seen) <= 128, 'DNS_NAME_BOUND')
        seen.add(position); length = raw[position]
        if length & 0xc0 == 0xc0:
            require(position + 1 < len(raw), 'DNS_POINTER_TRUNCATED')
            target = (length & 0x3f) * 256 + raw[position + 1]
            require(target < position, 'DNS_POINTER_NOT_PRIOR')
            if returned is None: returned = position + 2
            position = target; continue
        require(length <= 63 and position + 1 + length <= len(raw), 'DNS_LABEL_BOUND')
        position += 1
        if length == 0:
            result = '.'.join(labels)
            require(0 < len(result) <= 253, 'DNS_NAME_LENGTH')
            return result, returned if returned is not None else position
        label = raw[position:position + length].decode('ascii').lower()
        require(all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in label), 'DNS_LABEL_CHAR')
        labels.append(label); position += length


@dataclass(frozen=True)
class OriginalDNS:
    kind: str
    question: str
    cname_chain: tuple
    addresses: tuple
    minimum_chain_ttl: int
    started: float
    returned: float
    expires: float
    original_wire_sha256: str
    original_wire: bytes = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def validate(self):
        require(self._capability is _DNS and self.kind in NAMES and self.question == NAMES[self.kind], 'SAME_PRIVATE_FIXED_QUESTION_DNS_WITNESS')
        require(type(self.original_wire) is bytes and 12 <= len(self.original_wire) <= 4096 and
                sha(self.original_wire) == self.original_wire_sha256, 'SAME_COMPLETE_ORIGINAL_DNS_WIRE_BYTES')
        require(number(self.started) and number(self.returned) and number(self.expires) and
                self.started <= self.returned < self.expires and type(self.minimum_chain_ttl) is int and
                0 < self.minimum_chain_ttl <= 86400 and self.expires == self.started + min(self.minimum_chain_ttl, 30),
                'ORIGINAL_POSITIVE_CHAIN_START_TTL_EXPIRY_NEVER_RENEWED')
        require(type(self.addresses) is tuple and 1 <= len(self.addresses) <= 8 and self.addresses == tuple(sorted(set(self.addresses))), 'COMPLETE_CANONICAL_ADDRESS_SET')
        for address in self.addresses:
            parsed = ipaddress.IPv4Address(address)
            require(str(parsed) == address and parsed in ipaddress.IPv4Network('172.18.0.0/16') and address != '10.250.0.50', 'EXACT_ORIGINAL_VPC_BACKEND_ADDRESSES')
        require(type(self.cname_chain) is tuple and len(self.cname_chain) <= 7 and
                all(type(pair) is tuple and len(pair) == 2 for pair in self.cname_chain), 'ORIGINAL_ORDERED_CNAME_CHAIN')
        return self

    @property
    def semantic_identity(self):
        return self.kind, self.question, self.cname_chain, self.addresses, PORTS[self.kind]


@dataclass(frozen=True)
class OriginalZeroTTL:
    """Completed identity-only response. Deliberately has NO expiry/authority."""
    kind: str
    question: str
    cname_chain: tuple
    addresses: tuple
    minimum_chain_ttl: int
    started: float
    returned: float
    original_wire_sha256: str
    original_wire: bytes = field(repr=False, compare=False)
    _capability: object = field(repr=False, compare=False)

    def validate(self):
        require(self._capability is _ZERO and self.kind in NAMES and self.question == NAMES[self.kind], 'PRIVATE_ZERO_TTL_IDENTITY_ONLY')
        require(type(self.original_wire) is bytes and 12 <= len(self.original_wire) <= 4096 and
                sha(self.original_wire) == self.original_wire_sha256, 'SAME_COMPLETE_ZERO_TTL_ORIGINAL_WIRE')
        require(number(self.started) and number(self.returned) and self.started <= self.returned and
                type(self.minimum_chain_ttl) is int and self.minimum_chain_ttl == 0, 'ZERO_TTL_HAS_NO_POSITIVE_VALIDITY')
        require(type(self.addresses) is tuple and 1 <= len(self.addresses) <= 8 and self.addresses == tuple(sorted(set(self.addresses))), 'COMPLETE_ZERO_TTL_ADDRESS_SET')
        for address in self.addresses:
            parsed = ipaddress.IPv4Address(address)
            require(str(parsed) == address and parsed in ipaddress.IPv4Network('172.18.0.0/16') and address != '10.250.0.50', 'EXACT_ZERO_TTL_VPC_ADDRESSES')
        require(type(self.cname_chain) is tuple and len(self.cname_chain) <= 7 and
                all(type(pair) is tuple and len(pair) == 2 for pair in self.cname_chain), 'COMPLETE_ZERO_TTL_CNAME_CHAIN')
        return self

    @property
    def semantic_identity(self):
        return self.kind, self.question, self.cname_chain, self.addresses, PORTS[self.kind]


def _decode_response(raw, request_id, kind, started, returned, allow_zero):
    """Call only AFTER the SAME original UDP handle has returned and closed.

    started belongs before send; returned belongs after read/Close. The
    future owning reader supplies these actual local facts, never cache.now.
    This pure decoder does not assert a socket or Close occurred in tests.
    """
    require(kind in NAMES and type(raw) is bytes and 12 <= len(raw) <= 4096, 'BOUNDED_FIXED_ORIGINAL_DNS_WIRE')
    identity, flags, questions, answers, authority, extra = struct.unpack('!6H', raw[:12])
    require(identity == request_id and flags & 0x8000 and flags & 0x7800 == 0 and flags & 0xf == 0 and
            not flags & 0x0200 and questions == 1 and 1 <= answers <= 32 and authority + extra <= 32, 'DNS_ORIGINAL_REPLY')
    question, position = name_at(raw, 12)
    require(question == NAMES[kind] and raw[position:position + 4] == struct.pack('!HH', 1, 1), 'DNS_ORIGINAL_QUESTION')
    position += 4; records = []
    for index in range(answers + authority + extra):
        owner, position = name_at(raw, position)
        require(position + 10 <= len(raw), 'DNS_RR_HEADER')
        typ, cls, ttl, size = struct.unpack('!HHIH', raw[position:position + 10]); position += 10
        end = position + size; require(end <= len(raw), 'DNS_RDATA_BOUND')
        if index < answers:
            require(cls == 1 and 0 <= ttl <= 86400 and (allow_zero or ttl > 0) and typ in (1, 5), 'DNS_ANSWER_SHAPE')
            if typ == 1:
                require(size == 4, 'DNS_A_SIZE'); value = str(ipaddress.IPv4Address(raw[position:end]))
            else:
                value, consumed = name_at(raw, position); require(consumed == end, 'DNS_CNAME_SIZE')
            records.append((owner, typ, ttl, value))
        position = end
    require(position == len(raw), 'DNS_TRAILING_BYTES')
    current, ttl, chain, seen = question, 86400, [], set()
    for _ in range(8):
        require(current not in seen, 'DNS_CNAME_CYCLE'); seen.add(current)
        values = [record for record in records if record[0] == current]
        require(values and len({v[1] for v in values}) == 1, 'DNS_INCOMPLETE_CHAIN')
        ttl = min(ttl, *(v[2] for v in values))
        if values[0][1] == 1:
            addresses = tuple(sorted({v[3] for v in values}))
            if ttl == 0:
                return OriginalZeroTTL(kind, question, tuple(chain), addresses, ttl, started, returned,
                                       sha(raw), raw, _ZERO).validate()
            # Preserve rejection of an unrelated zero-TTL answer. Only a
            # fully resolved zero chain has the new identity-only API.
            require(all(v[2] > 0 for v in records), 'DNS_ANSWER_SHAPE')
            return OriginalDNS(kind, question, tuple(chain), addresses, ttl, started, returned,
                               started + min(ttl, 30), sha(raw), raw, _DNS).validate()
        require(len(values) == 1, 'DNS_CNAME_AMBIGUOUS')
        target = values[0][3]; chain.append((current, target)); current = target
    raise Held('DNS_CHAIN_BOUND')


def decode_original(raw, request_id, kind, started, returned):
    """The positive-witness API NEVER accepts a zero-TTL response."""
    return _decode_response(raw, request_id, kind, started, returned, False)


def decode_response(raw, request_id, kind, started, returned):
    """Completed positive witness OR a separate non-authoritative identity."""
    return _decode_response(raw, request_id, kind, started, returned, True)


@dataclass(frozen=True)
class OriginalRoute:
    address: str
    identity_json: bytes
    original_stdout_sha256: str
    original_facts_sha256: str
    started: float
    returned: float
    _capability: object = field(repr=False, compare=False)

    def validate_for(self, answer):
        require(type(answer) is OriginalDNS, 'ONLY_POSITIVE_DNS_CAN_AUTHORIZE_ORIGINAL_ROUTE')
        answer.validate()
        require(self._capability is _ROUTE and self.address == answer.addresses[0] and
                number(self.started) and number(self.returned) and
                answer.returned <= self.started <= self.returned < answer.expires,
                'ROUTE_READ_AFTER_SAME_COMPLETED_DNS_AND_BEFORE_ORIGINAL_EXPIRY')
        return self

    def validate_after_zero(self, previous, answer):
        require(type(previous) is CompleteWitness and type(answer) is OriginalZeroTTL, 'ZERO_ROUTE_REQUIRES_PREVIOUS_COMPLETE_POSITIVE')
        previous.validate(); answer.validate()
        require(answer.semantic_identity == previous.answer.semantic_identity and
                previous.route.returned <= answer.started <= answer.returned <= self.started <= self.returned < previous.original_expiry and
                self._capability is _ROUTE and self.address == answer.addresses[0],
                'ZERO_IDENTITY_ROUTE_COMPLETES_BEFORE_PREVIOUS_ORIGINAL_EXPIRY')
        return self


def _original_route(answer, raw, facts):
    """Capture thread-local native_io.last_facts immediately after ip route get.

    No synthetic now/True parameter: original role/argv/output hash/extent and
    full native process closure must match that SAME returned read.
    """
    answer.validate()
    argv = ['/usr/sbin/ip', '-j', '-4', 'route', 'get', answer.addresses[0]]
    require(type(raw) is bytes and 0 < len(raw) <= 4096 and type(facts) is dict and
            facts['schema'] == 'root_R11_original_native_command_facts_v1' and facts['role'] == 'route_' + answer.kind and
            facts['argv'] == argv and facts['stdout_sha256'] == sha(raw) and facts['stdout_bytes'] == len(raw) and
            facts['closed_before_original_deadline_zero'] is True and facts['retention_inside_original_deadline'] is True,
            'SAME_ORIGINAL_TYPED_ROUTE_NATIVE_FACTS')
    transport = facts['original_transport']
    require(all(transport.get(key) is True for key in ('native_started', 'stdout_EOF', 'stderr_EOF', 'all_local_FDs_closed', 'local_child_joined', 'wait_zero')) and
            type(transport.get('exit_code')) is int and transport.get('exit_code') == 0 and
            transport.get('captured_output_truncated') is False,
            'ORIGINAL_ROUTE_NATIVE_FULL_EOF_CLOSE_WAIT_ZERO')
    start, end, deadline = facts['started_monotonic'], facts['diagnostic_retention_returned_monotonic'], facts['original_deadline']
    require(all(number(value) for value in (start, end, deadline, facts['returned_monotonic'])) and
            start <= facts['returned_monotonic'] <= end < deadline <= start + 2, 'ORIGINAL_ROUTE_DEADLINE_NOT_RENEWED')
    rows = json.loads(raw)
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'EXACT_SINGLE_ORIGINAL_ROUTE')
    row = rows[0]
    require(row.get('dst') == answer.addresses[0] and row.get('type', 'unicast') == 'unicast' and
            row.get('dev') == 'br-2980a83da24e' and row.get('prefsrc') == '172.18.0.1', 'EXACT_ORIGINAL_BRAIN_VPC_UNICAST_ROUTE')
    require(set(row) <= {'dst', 'gateway', 'dev', 'prefsrc', 'flags', 'uid', 'cache', 'table', 'type', 'scope', 'protocol'}, 'CLOSED_PROPOSED_ROUTE_PROJECTION_NEEDS_NATIVE_QUALIFICATION')
    if 'gateway' in row:
        require(str(ipaddress.IPv4Address(row['gateway'])) == row['gateway'], 'CANONICAL_ORIGINAL_ROUTE_GATEWAY')
    # Preserve EVERY accepted route field. No removal of cache/table/gateway/
    # flags to make different actual routes compare equal. Equality and native
    # grammar of this proposal still require an actual Root read qualification.
    return OriginalRoute(answer.addresses[0], wire(row), sha(raw), sha(wire(facts)), start, end, _ROUTE)


def route_from_original(answer, raw, facts):
    require(type(answer) is OriginalDNS, 'POSITIVE_ROUTE_FACTORY_REJECTS_ZERO_IDENTITY')
    return _original_route(answer, raw, facts).validate_for(answer)


def route_after_zero(previous, answer, raw, facts):
    require(type(answer) is OriginalZeroTTL, 'ONLY_COMPLETED_ZERO_IDENTITY_ROUTE_RECHECK')
    return _original_route(answer, raw, facts).validate_after_zero(previous, answer)


@dataclass(frozen=True)
class CompleteWitness:
    answer: OriginalDNS
    route: OriginalRoute
    original_collision_expires: float
    original_collisions: frozenset
    _capability: object = field(repr=False, compare=False)

    def validate(self):
        require(self._capability is _WHOLE and type(self.answer) is OriginalDNS, 'PRIVATE_COMPLETE_POSITIVE_ORIGINAL_WITNESS')
        self.answer.validate(); self.route.validate_for(self.answer)
        require(type(self.original_collisions) is frozenset and len(self.original_collisions) <= 512 and
                number(self.original_collision_expires) and self.route.returned < self.original_collision_expires and
                not set(self.answer.addresses) & self.original_collisions, 'ORIGINAL_FULL_ADDRESS_COLLISION_CONTEXT')
        return self

    @property
    def original_expiry(self):
        return min(self.answer.expires, self.original_collision_expires)


def complete(answer, route, original_collisions, original_collision_expires):
    return CompleteWitness(answer, route, original_collision_expires, frozenset(original_collisions), _WHOLE).validate()


def previous_for_zero(previous, answer, current_collisions, current_collision_expires, now):
    """No previous, expired, or changed identity can gain authority from zero."""
    require(type(answer) is OriginalZeroTTL, 'ONLY_PRIVATE_ZERO_IDENTITY')
    answer.validate()
    require(number(now) and number(current_collision_expires) and current_collision_expires > now and
            type(current_collisions) in (set, frozenset) and len(current_collisions) <= 512,
            'ZERO_RECHECK_CURRENT_COLLISION_CONTEXT_FRESH')
    if previous is None:
        return None
    require(type(previous) is CompleteWitness, 'ONLY_PREVIOUS_COMPLETE_POSITIVE_FOR_ZERO')
    previous.validate()
    if not (previous.answer.semantic_identity == answer.semantic_identity and
            previous.route.returned <= answer.started <= answer.returned <= now < min(previous.original_expiry, current_collision_expires) and
            not set(previous.answer.addresses) & current_collisions):
        return None
    return previous


def retain_after_zero(previous, answer, route, current_collisions, current_collision_expires, now):
    """Return the SAME positive object, never a new TTL/route/collision window."""
    selected = previous_for_zero(previous, answer, current_collisions, current_collision_expires, now)
    if selected is None:
        return None
    require(type(route) is OriginalRoute, 'SAME_CLOSED_ZERO_RECHECK_ROUTE')
    route.validate_after_zero(previous, answer)
    require(route.returned <= now, 'ZERO_RECHECK_ROUTE_ACTUALLY_RETURNED')
    return previous if route.identity_json == previous.route.identity_json else None


def select_complete(previous, current, current_collisions, current_collision_expires, now):
    """Select ONE original object; no TTL/route/collision timestamps are mixed.

    None means actual DNS/route failure and CLEAR, never old-DNS fallback.
    Identity change discards the previous and selects the CURRENT completed
    valid answer+route immediately. It never falls back across that change.
    """
    require(number(now) and number(current_collision_expires) and current_collision_expires > now,
            'CURRENT_COLLISION_CONTEXT_STILL_FRESH')
    require(type(current_collisions) in (set, frozenset) and len(current_collisions) <= 512, 'BOUNDED_CURRENT_COLLISION_CONTEXT')
    if current is None:
        return None
    require(type(current) is CompleteWitness, 'ONLY_COMPLETED_ORIGINAL_CURRENT_WITNESS')
    current.validate()
    require(current.route.returned <= now < min(current.original_expiry, current_collision_expires) and
            not set(current.answer.addresses) & current_collisions, 'CURRENT_COMPLETE_DNS_ROUTE_AND_COLLISION_REJOIN')
    if previous is None:
        return current
    require(type(previous) is CompleteWitness, 'ONLY_COMPLETE_PREVIOUS_WITNESS')
    previous.validate()
    same = (previous.answer.semantic_identity == current.answer.semantic_identity and
            previous.route.identity_json == current.route.identity_json)
    if not same:
        return current
    # The latest route belongs to the newest DNS read and was checked above;
    # equality revalidates the retained original route's identity, not its age.
    # The retained object keeps its OWN original DNS/route/collision deadlines.
    previous_expiry = min(previous.original_expiry, current_collision_expires)
    current_expiry = min(current.original_expiry, current_collision_expires)
    if previous.route.returned <= now < previous_expiry and not set(previous.answer.addresses) & current_collisions and previous_expiry > current_expiry:
        return previous
    return current
