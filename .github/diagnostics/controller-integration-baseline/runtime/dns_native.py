"""Bounded original VPC-resolver A/CNAME read with actual native DNS TTLs."""
import secrets
import socket
import struct
import time
import whole_witness as whole

from nft_owner import Backend, Held, MAX_FRESH_SECONDS, require

RESOLVER = ('127.0.0.1', 5353)
NAMES = {'rds': 'rds.lab.invalid', 'redis': 'redis.lab.invalid'}
PORTS = {'rds': 5432, 'redis': 6379}


def name_at(raw, start):
    labels, pos, returned, seen = [], start, None, set()
    while True:
        require(pos < len(raw) and pos not in seen and len(seen) <= 128, 'DNS_NAME_BOUND')
        seen.add(pos)
        length = raw[pos]
        if length & 0xc0 == 0xc0:
            require(pos + 1 < len(raw), 'DNS_POINTER_TRUNCATED')
            target = (length & 0x3f) * 256 + raw[pos + 1]
            require(target < pos, 'DNS_POINTER_NOT_PRIOR')
            if returned is None:
                returned = pos + 2
            pos = target
            continue
        require(length <= 63 and pos + 1 + length <= len(raw), 'DNS_LABEL_BOUND')
        pos += 1
        if length == 0:
            result = '.'.join(labels)
            require(0 < len(result) <= 253, 'DNS_NAME_LENGTH')
            return result, returned if returned is not None else pos
        label = raw[pos:pos + length].decode('ascii').lower()
        require(all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in label), 'DNS_LABEL_CHAR')
        labels.append(label)
        pos += length


def parse(raw, identity, fqdn):
    require(12 <= len(raw) <= 4096, 'DNS_RESPONSE_BOUND')
    native_id, flags, questions, answers, authority, extra = struct.unpack('!6H', raw[:12])
    require(native_id == identity and flags & 0x8000 and flags & 0x7800 == 0 and flags & 0x000f == 0 and not flags & 0x0200 and questions == 1 and 1 <= answers <= 32 and authority + extra <= 32, 'DNS_ORIGINAL_REPLY')
    name, pos = name_at(raw, 12)
    require(name == fqdn and raw[pos:pos + 4] == struct.pack('!HH', 1, 1), 'DNS_ORIGINAL_QUESTION')
    pos += 4
    records = []
    for index in range(answers + authority + extra):
        owner, pos = name_at(raw, pos)
        require(pos + 10 <= len(raw), 'DNS_RR_HEADER')
        typ, cls, ttl, size = struct.unpack('!HHIH', raw[pos:pos + 10])
        pos += 10
        end = pos + size
        require(end <= len(raw), 'DNS_RDATA_BOUND')
        if index < answers:
            require(cls == 1 and 0 < ttl <= 86400 and typ in (1, 5), 'DNS_ANSWER_SHAPE')
            if typ == 1:
                require(size == 4, 'DNS_A_SIZE')
                value = socket.inet_ntoa(raw[pos:end])
            else:
                value, consumed = name_at(raw, pos)
                require(consumed == end, 'DNS_CNAME_SIZE')
            records.append((owner, typ, ttl, value))
        pos = end
    require(pos == len(raw), 'DNS_TRAILING_BYTES')
    current, ttl, visited = fqdn, MAX_FRESH_SECONDS, set()
    for _ in range(8):
        require(current not in visited, 'DNS_CNAME_CYCLE')
        visited.add(current)
        values = [v for v in records if v[0] == current]
        require(values and len({v[1] for v in values}) == 1, 'DNS_INCOMPLETE_CHAIN')
        ttl = min(ttl, *(v[2] for v in values))
        if values[0][1] == 1:
            addresses = sorted({v[3] for v in values})
            require(1 <= len(addresses) <= 8, 'DNS_ADDRESS_CENSUS')
            return addresses, ttl
        require(len(values) == 1, 'DNS_CNAME_AMBIGUOUS')
        current = values[0][3]
    raise Held('DNS_CHAIN_BOUND')


def resolve(kind, collision_ips):
    require(kind in NAMES, 'FIXED_DNS_OWNER')
    fqdn = NAMES[kind]
    identity = secrets.randbits(16)
    question = b''.join(bytes([len(v)]) + v.encode('ascii') for v in fqdn.split('.')) + b'\x00' + struct.pack('!HH', 1, 1)
    query = struct.pack('!6H', identity, 0x0100, 1, 0, 0, 0) + question
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.connect(RESOLVER)
        require(s.send(query) == len(query), 'DNS_ORIGINAL_SEND')
        raw = s.recv(4097)
    # This clock belongs to the SAME completed UDP read/Close. Parsing and
    # the immediately following original route read consume its original TTL.
    try:
        answer = whole.decode_response(raw, identity, kind, started, time.monotonic())
    except whole.Held as error:
        raise Held(str(error)) from None
    require(not set(answer.addresses) & set(collision_ips), 'BACKEND_COLLIDES_BRAIN_SERVICE')
    return answer


def backend(witness, collision_ips, collision_expires, *, now=None):
    """Projection only; the complete original witness stays in the cache."""
    witness.validate()
    now = time.monotonic() if now is None else now
    require(not set(witness.answer.addresses) & set(collision_ips), 'COMPLETE_DNS_COLLISION_REJOIN')
    expires = min(witness.original_expiry, collision_expires)
    require(witness.answer.started <= now < expires, 'ORIGINAL_COMPLETE_DNS_WITNESS_STILL_VALID')
    result = Backend(witness.answer.kind, witness.answer.addresses[0], PORTS[witness.answer.kind],
                     witness.answer.started, expires, witness.answer.question)
    result.validate()
    return result
