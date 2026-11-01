"""CI-only Guardian-owned 50-object observation, NOT a DELETE grant.

The RPC caller supplies no modules, callbacks, booleans, pin, FD or receipt.
The authenticated Guardian server passes only its own internal registry and
verified generation. Production source sealing and real Kubernetes are absent.
"""
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
import time

from drain_coordination_DRAFT import FenceError

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
# Generated from this isolated package, not accepted from the RPC caller.
CI_SOURCE_SHA256 = {'ci_guardian50_session.py': 'f36bc31d2e2920ca0bcc969c77d3591bdb83b3782808aa85d7e4cfd5dfed152a',
 'ci_nl_probe.py': '92ef4d57f659f2683af06640be77e0dc04eb775d6fd5670b35fa720af3a546de',
 'coverage.py': 'c13f2d872f4b9a8351aa2999372ac8f2fd472f4db8e015810b3d6c28a596bfa6',
 'drain_marker_v3_DRAFT.py': 'f2a33a9c51ce991f22f747da2783964c1cca948935be4b1faf328c6c3ac71670',
 'guarded_live_observation.py': '10686a406a02d473e7d47b89d74c1b98dc7969bb82cb1459242739b2e9e6ce2c',
 'guarded_nl.py': '6a4fd005a7bd053ca71c424672dde85d87ca496510b01f6ebdc97a91f607b71a',
 'guarded_refresh_registry_DRAFT.py': 'e15753b01adcbe4fe23d993496066de8b47a65fd4efdf422c84ceb45f784d71f',
 'guarded_sources.py': 'e8935b8406ba4b4571d7779d65c2f280a3ed9f2aea128ce58079c2a0b9b40a66',
 'guarded_verifier.py': '66f19e364e627491fee88d61362c08fb860c29667e23654a447ab55691d74f41',
 'native_structure.py': '7da5d5ef6b543b5a8ec54bf92520e5999f06ae816c31d7b377ee51c1d2738ebf',
 'nft_owner.py': 'c3ab65330a579d25dd329267ae189a4d7765c166dc754a022ae373d9729d674b',
 'observations.py': '1d53464bb58ca124dc6cf908298e4ace7bc26a5ed2ad4fcb3cdb6565b8428b33',
 'transition_structure_DRAFT.py': '2bc9ca68845b27c91822b3bd8004d54c2469f866e50c134f391495e7f0f9e32e'}

def _read_sealed(path,expected):
    if not path.is_absolute() or os.path.realpath(path)!=str(path):
        raise FenceError('EXACT_NON_SYMLINK_SOURCE_REQUIRED')
    for parent in reversed(path.parents):
        value=os.lstat(parent)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid!=0
                or (value.st_mode&0o022 and not value.st_mode&stat.S_ISVTX)):
            raise FenceError('ROOT_CONTROLLED_SOURCE_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022
                or before.st_nlink!=1 or before.st_size>4*1024*1024):
            raise FenceError('ROOT_CONTROLLED_SOURCE_FILE_REQUIRED')
        raw=bytearray()
        while len(raw)<=4*1024*1024:
            part=os.read(fd,min(65536,4*1024*1024+1-len(raw)))
            if not part:break
            raw.extend(part)
        after=os.fstat(fd);named=os.lstat(path)
        stamp=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if len(raw)>4*1024*1024 or stamp(before)!=stamp(after) or stamp(after)!=stamp(named):
            raise FenceError('STABLE_SEALED_SOURCE_REQUIRED')
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise FenceError('EXACT_SEALED_SOURCE_HASH_REQUIRED')
        return bytes(raw)
    finally:os.close(fd)

def _fixed_sources():
    names=('guarded_live_observation','guarded_verifier','guarded_sources',
           'guarded_nl','transition_structure_DRAFT','native_structure',
           'guarded_refresh_registry_DRAFT','drain_marker_v3_DRAFT',
           'nft_owner','observations','ci_guardian50_session')
    for name in names:
        path=HERE/(name+'.py')
        _read_sealed(path,CI_SOURCE_SHA256[name+'.py'])
        module=sys.modules.get(name)
        if module is None or os.path.realpath(getattr(module,'__file__',''))!=str(path):
            raise FenceError('SAME_SEALED_IMPORTED_MODULE_REQUIRED')
    raw=_read_sealed(ROOT/'coverage.py',CI_SOURCE_SHA256['coverage.py'])
    _read_sealed(HERE/'ci_nl_probe.py',CI_SOURCE_SHA256['ci_nl_probe.py'])
    # Load this one pure parser from the exact verified bytes; caller cannot
    # supply a coverage implementation or an expected digest.
    coverage=type(sys)('ci_sealed_coverage')
    exec(compile(raw,str(ROOT/'coverage.py'),'exec'),coverage.__dict__)
    return coverage

def _kernel_genid(nl):
    channel=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)
    try:
        channel.bind((0,0));channel.settimeout(3)
        return nl.genid(channel)
    finally:channel.close()

def _sender_holds_writer_fd(coord,pid):
    expected=coord.directory/'writer.lock'
    value=os.lstat(expected)
    if (not stat.S_ISREG(value.st_mode) or value.st_uid!=0
            or stat.S_IMODE(value.st_mode)!=0o600 or value.st_nlink!=1):
        raise FenceError('EXACT_WRITER_LOCK_REQUIRED')
    fd=os.open(expected,os.O_RDWR|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:pass
        else:raise FenceError('WRITER_SHARED_LEASE_NOT_HELD')
    finally:os.close(fd)
    found=[]
    for entry in Path('/proc/%d/fd'%pid).iterdir():
        try:info=entry.stat()
        except (FileNotFoundError,PermissionError):continue
        if (info.st_dev,info.st_ino)==(value.st_dev,value.st_ino):found.append(entry.name)
    if not found:raise FenceError('SENDER_WRITER_FD_NOT_OBSERVED')
    return value.st_dev,value.st_ino

def observe(verified,registry,coord,uid,address):
    import guarded_live_observation as live
    import guarded_verifier as verifier
    import guarded_sources as sources
    import guarded_nl as nl
    import transition_structure_DRAFT as transition
    import guarded_refresh_registry_DRAFT as registry_module
    with coord.admission_or_other_writer() as state:
        coord.base.require_allowed(state,uid,address)
    coverage=_fixed_sources()
    if (type(verified) is not verifier._VerifiedGeneration
            or verified.capability is not verifier._VERIFIED_CAPABILITY
            or verified.guardian_pid!=os.getpid()
            or type(registry) is not registry_module.GuardianRefreshRegistry
            or registry.pid!=os.getpid() or registry.cache is not verified.reader_cache):
        raise FenceError('OWN_GUARDIAN_VERIFIED_STATE_REQUIRED')
    with registry.lock:
        if registry.pending is not None or registry.state=='UNKNOWN':
            raise FenceError('NO_PENDING_OR_UNKNOWN_GUARDIAN_REQUIRED')
    with coord.admission_or_other_writer() as state:
        coord.base.require_allowed(state,uid,address)
        state_digest=hashlib.sha256(json.dumps(state,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    first_genid=_kernel_genid(nl)
    if first_genid!=verified.result['after']:raise FenceError('SAME_ACTIVE_GUARDED_GENERATION_REQUIRED')
    # Verify the complete 50-object structure against the original 47 pin,
    # including the exact gate chain and handles from the Guardian receipt.
    initial=base64.b64decode(verified.anchor['initial'],validate=True)
    pin=transition.OriginalPin(initial)
    raw=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset')
    transition.verify_guarded(pin,raw,observed_chain_handle=verified.result['chain'],
                              observed_rule_handles=tuple(verified.result['handles']))
    proof=live.observe(verified,verifier=verifier,sources=sources,nl=nl,coverage=coverage,
                       probe_path=HERE/'ci_nl_probe.py',probe_sha256=CI_SOURCE_SHA256['ci_nl_probe.py'])
    entries,cores,_prom,errors,generation=registry.cache.snapshot()
    selected=[x for x in entries if x.kind=='core']
    matches=[x for x in cores if x.native_identity.split('/',1)[0]==uid and x.address==address]
    if (errors or len(selected)!=1 or len(matches)!=1 or selected[0]!=matches[0]
            or generation!=proof['observation']['reader_generation']):
        raise FenceError('ORIGINAL_READY_UID_IP_AND_GENERATION_REQUIRED')
    writer_identity=_sender_holds_writer_fd(coord,verified.anchor['pid'])
    with coord.admission_or_other_writer() as state:
        if hashlib.sha256(json.dumps(state,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=state_digest:
            raise FenceError('FENCE_STATE_CHANGED_DURING_OBSERVATION')
        coord.base.require_allowed(state,uid,address)
        with registry.lock:
            if registry.pending is not None or registry.state=='UNKNOWN':
                raise FenceError('NO_PENDING_OR_UNKNOWN_GUARDIAN_REQUIRED')
        if _kernel_genid(nl)!=first_genid:
            raise FenceError('GUARDED_GENERATION_CHANGED_DURING_OBSERVATION')
        _entries,_cores,_prom,errors2,generation2=registry.cache.snapshot()
        if errors2 or generation2!=generation:
            raise FenceError('READER_CHANGED_DURING_OBSERVATION')
        until=min(proof['observation']['kernel_min_deadline_ns'],int(matches[0].expires*1e9))
        if until<=time.monotonic_ns()+250_000_000:
            raise FenceError('GUARDED_WITNESS_EXPIRES_TOO_SOON')
    return {'schema':'ci_guarded_admission_observation_v1','core_uid':uid,'core_ip':address,
            'genid':first_genid,'deadline_ns':until,'writer_lock':list(writer_identity),
            'receipt_sha256':proof['observation']['receipt_sha256'],
            'fifty_object_shape_verified':True,'bpf_rule_fd_map_join_verified':True,
            'kubernetes_proven':False,'production_authority':False}

def evaluate(_request, coordination):
    with coordination.admission_or_other_writer():
        raise FenceError('GUARDED_BPF_ADMISSION_NOT_VALIDATED')
