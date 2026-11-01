"""LAB-only independent precommit 47 custody; not a production authority."""
import hashlib,json,os,re,select,socket,struct,time
from pathlib import Path

class Held(RuntimeError):pass
def need(value,reason):
    if not value:raise Held(reason)

def read_line(channel,maximum=4096):
    raw=bytearray()
    while len(raw)<=maximum:
        part=channel.recv(1);need(bool(part),'PRECOMMIT_CHANNEL_EOF')
        if part==b'\n':break
        raw.extend(part)
    else:raise Held('BOUNDED_PRECOMMIT_REQUEST')
    def pairs(items):
        result={}
        for key,value in items:need(key not in result,'DUPLICATE_PRECOMMIT_FIELD');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs)

def connect(origin,channel,*,guardian_unit,invocation,guardian_argv,source_sha256,identity,nl,structure,transition):
    import secrets
    need(type(origin) is structure._GuardedTransitionOrigin and origin._capability is structure._CAPABILITY
         and origin._pid==os.getpid() and not origin._consumed,'ORIGINAL_PENDING_47_ORIGIN')
    peer=identity.authenticate(channel,unit=guardian_unit,expected_invocation=invocation,
          expected_argv=guardian_argv,source_sha256=source_sha256,expected_uid=0)
    try:
        pin=transition.OriginalPin(origin._raw);nonce=secrets.token_hex(32)
        request={'schema':'lab_precommit47_request_v1','nonce':nonce,'sender_pid':os.getpid(),
                 'sender_start_ticks':nl.startticks(os.getpid()),'origin_digest':pin.digest,'origin_raw_sha256':origin._raw_sha256}
        channel.settimeout(5);channel.sendall(nl.canon(request));answer=read_line(channel)
        need(type(answer) is dict and set(answer)=={'schema','nonce','sender_pid','sender_start_ticks','guardian_pid','invocation_id','origin_digest','origin_raw_sha256','genid','production_authority'}
             and answer['schema']=='lab_precommit47_reply_v1' and answer['nonce']==nonce
             and answer['sender_pid']==request['sender_pid'] and answer['sender_start_ticks']==request['sender_start_ticks']
             and answer['guardian_pid']==peer['pid'] and answer['invocation_id']==invocation
             and answer['origin_digest']==pin.digest and answer['origin_raw_sha256']==origin._raw_sha256
             and type(answer['genid']) is int and 0<answer['genid']<2**32 and answer['production_authority'] is False,
             'INDEPENDENT_GUARDIAN47_ORIGIN_REQUIRED')
        session=structure._GuardedGuardianSession(origin,channel,peer['pid'],peer['start_ticks'],invocation,peer['pidfd'],pin,answer['genid'],structure._CAPABILITY)
        structure._lab_guardian_alive(session);return session
    except BaseException:
        os.close(peer['pidfd']);raise

def serve(channel,*,preparer_identity,sender_argv,source_sha256,probe_path,probe_sha256,identity,nl,structure,transition,nft,host_netns):
    pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(uid==0 and pid>1,'EXACT_PRECOMMIT_SENDER_CREDENTIALS')
    ticks=nl.startticks(pid);pidfd=os.pidfd_open(pid,0)
    def live():
        poll=select.poll();poll.register(pidfd,select.POLLIN)
        need(not poll.poll(0) and nl.startticks(pid)==ticks and os.readlink('/proc/%d/ns/net'%pid)!=host_netns,'LIVE_PRIVATE_PRECOMMIT_SENDER')
        identity._current_ids(pid,uid,gid)
    try:
        live()
        source_index = (3 if type(sender_argv) is list and sender_argv[:3] == ['/usr/bin/python3','-I','-B']
                        else 2 if type(sender_argv) is list and sender_argv[:2] == ['/usr/bin/python3','-B'] else -1)
        need(type(preparer_identity) is dict and source_index > 0 and len(sender_argv)>source_index,'EXACT_PREPARER_IDENTITY_AND_ARGV')
        preparer_pid=preparer_identity['pid'];sender_script=sender_argv[source_index]
        need(Path('/proc/%d/cgroup'%pid).read_bytes()==Path('/proc/%d/cgroup'%preparer_pid).read_bytes(),'SAME_PREPARER_CGROUP')
        argv=Path('/proc/%d/cmdline'%pid).read_bytes();need(argv.endswith(b'\0') and argv[:-1].split(b'\0')==[x.encode() for x in sender_argv],'EXACT_PRECOMMIT_SENDER_ARGV')
        if pid==preparer_pid:
            observed=identity.authenticate(channel,unit=preparer_identity['unit'],expected_invocation=preparer_identity['invocation_id'],expected_argv=sender_argv,source_sha256=source_sha256,expected_uid=0)
            try:need(observed['pid']==preparer_pid and observed['start_ticks']==preparer_identity['start_ticks'] and observed['control_group']==preparer_identity['control_group'],'SAME_ORIGINAL_CONTROLLER_IDENTITY')
            finally:os.close(observed['pidfd'])
        else:
            need(len(sender_argv)>source_index+1 and sender_argv[source_index+1]=='sender','ONLY_EXACT_LAB_CHILD_SENDER_ENTRY')
            fields=Path('/proc/%d/stat'%pid).read_bytes().rsplit(b') ',1)[1].split();need(int(fields[1])==preparer_pid,'DIRECT_PREPARER_CHILD')
        exe=os.stat('/proc/%d/exe'%pid);ref=os.stat('/usr/bin/python3');need((exe.st_dev,exe.st_ino)==(ref.st_dev,ref.st_ino),'EXACT_PRECOMMIT_INTERPRETER')
        identity._secure_source(Path(sender_script),source_sha256);channel.settimeout(10);request=read_line(channel)
        need(type(request) is dict and set(request)=={'schema','nonce','sender_pid','sender_start_ticks','origin_digest','origin_raw_sha256'}
             and request['schema']=='lab_precommit47_request_v1' and request['sender_pid']==pid and request['sender_start_ticks']==ticks
             and all(type(request[k]) is str and re.fullmatch('[a-f0-9]{64}',request[k]) for k in ('nonce','origin_digest','origin_raw_sha256')),'EXACT_PRECOMMIT_REQUEST')
        prefix=['/usr/bin/nsenter','--net=/proc/%d/ns/net'%pid]
        identity._secure_source(Path(probe_path),probe_sha256)
        def probe():
            import fenced_probe_CI
            return json.loads(fenced_probe_CI.call(nl,prefix,probe_path))['genid']
        import fenced_probe_CI
        before=probe();raw=fenced_probe_CI.read_nft(nl,prefix,'-j','list','ruleset');rows,rules,original=structure._objects(raw,_with_origin=True)
        pin=transition.OriginalPin(raw);nft.ruleset_mark_preflight(rules,_original_json=original)
        after=probe();live();identity._secure_source(Path(sender_script),source_sha256);identity._secure_source(Path(probe_path),probe_sha256)
        need(before==after and pin.digest==request['origin_digest'],
             'SAME_INDEPENDENT_PRECOMMIT_ORIGIN_AND_GENERATION')
        invocation=os.environ.get('INVOCATION_ID','');need(re.fullmatch('[a-f0-9]{32}',invocation) is not None,'GUARDIAN_INVOCATION_REQUIRED')
        # The raw hash is echoed only to bind the sender-owned origin; the independently
        # rederived authority is the managed-table digest/handles and live genid.
        channel.sendall(nl.canon({'schema':'lab_precommit47_reply_v1','nonce':request['nonce'],'sender_pid':pid,
            'sender_start_ticks':ticks,'guardian_pid':os.getpid(),'invocation_id':invocation,'origin_digest':pin.digest,
            'origin_raw_sha256':request['origin_raw_sha256'],'genid':before,'production_authority':False}))
        channel.settimeout(.5)
        while True:
            live()
            try:
                data=channel.recv(1)
                if not data:break
                raise Held('NO_PRECOMMIT_CHANNEL_REUSE')
            except socket.timeout:continue
    finally:os.close(pidfd)
