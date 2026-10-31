"""Exercise terminal sender proof against live systemd units in CI only."""
import array,fcntl,hashlib,json,os,signal,socket,subprocess,sys,tempfile,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'runtime'))
import drain_marker_v3_DRAFT as v3
import guarded_unit_identity as identity
import recovery_terminality_DRAFT as terminal
import ci_reader_fixture,guarded_nl as nl,guarded_program_identity_DRAFT as program
import guarded_sources as sources,native_io,nft_owner as nft,recovery_read_DRAFT as recovery

root=Path(__file__).resolve().parent;peer=(root/'systemd_peer.py').resolve();path=root/'terminal-peer.sock'
coord=v3.CoordinatorV3(root/'coord');coord.initialize_for_ci()
writer_lock=root/'writer.lock';writer_lock.touch(mode=0o600)
native_io.ROOT=root/'native-custody';native_io.ROOT.mkdir(mode=0o700);native_io.configure();native_io.end_initialization()
def endpoints(_):
    now=time.monotonic()
    rows=[nft.Backend(k,a,nft.PORTS[k],now,now+20,'old/container' if k=='core' else 'synthetic') for k,a in
          [('core','10.244.1.2'),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    return rows,[rows[0]],[nft.PrometheusSource('10.244.1.9',now,now+20,'synthetic')]
cache=ci_reader_fixture.start(endpoints)
subprocess.run(['/usr/sbin/nft','add','table','ip','ci_custody_read'],check=True,timeout=5)
netlink=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);netlink.bind((0,0));netlink.settimeout(4)
genid=nl.genid(netlink);reference=program.GuardianProgramReference();wanted=sources.build_expected(cache)
records=[]
unit='ci-terminal-proof-'+uuid.uuid4().hex+'.service';unit_file=Path('/run/systemd/system')/unit
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(str(path));server.listen(2);server.settimeout(12)
child_path=root/'terminal-child.pid';childfd=None
argv=['/usr/bin/python3','-B',str(peer),str(path)];anchor=None;channels=[]
def launch():
    child_path.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl','start',unit],check=True,timeout=10)
    channel,_=server.accept();channels.append(channel);return channel
try:
    unit_file.write_text('[Service]\nType=simple\nKillMode=process\nNetworkNamespacePath=/proc/'+str(os.getpid())+'/ns/net\nRuntimeMaxSec=30s\nEnvironment=CI_TERM_WRITER_LOCK='+str(writer_lock)+'\nEnvironment=CI_TERM_TRANSFER_BPF=1\nEnvironment=CI_CONTROLLER_UNIT='+unit+'\nEnvironment=CI_TERM_CHILD_PIDFILE='+str(child_path)+'\nEnvironment=CI_TERM_RUNTIME='+str(root/'runtime')+'\nEnvironment=CI_TERM_COORD='+str(coord.directory)+'\nExecStart='+' '.join(argv)+'\n')
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
    channel=launch();props=identity._properties(unit);digest=hashlib.sha256(peer.read_bytes()).hexdigest()
    anchor=terminal.capture_authenticated(channel,unit=unit,invocation=props['InvocationID'],argv=argv,source_sha256=digest)
    marker=terminal.capture_marker(anchor,coord)
    requested={role:[(key.hex(),expiry) for key,expiry in wanted[role].items()] for role in ('inbound','reverse')}
    channel.sendall((json.dumps(requested,sort_keys=True)+'\n').encode())
    raw,anc,flags,_=channel.recvmsg(65536,socket.CMSG_SPACE(4*array.array('i').itemsize))
    if not raw.endswith(b'\n') or flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) or len(anc)!=1:
        raise RuntimeError('EXACT_BPF_DESCRIPTOR_TRANSFER_REQUIRED')
    level,kind,data=anc[0];fds=array.array('i');fds.frombytes(data[:len(data)-(len(data)%fds.itemsize)])
    if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS or len(fds)!=4:raise RuntimeError('EXACT_FOUR_BPF_FDS_REQUIRED')
    records=json.loads(raw);assert len(records)==2
    for record,pf,mf in zip(records,fds[::2],fds[1::2]):
        record['program_fd'],record['map_fd']=pf,mf
    childfd=os.pidfd_open(int(child_path.read_text()))
    try:terminal.prove_terminal(anchor);raise AssertionError('live sender accepted')
    except terminal.Held as error:assert str(error)=='ORIGINAL_SENDER_STILL_ALIVE'
    subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',unit],check=True,timeout=10)
    time.sleep(.2)
    print('CI_TERMINAL_SYSTEMD',terminal._systemd(unit),flush=True)
    try:terminal.prove_terminal_for_marker(marker);raise AssertionError('live descendant accepted')
    except terminal.Held as error:assert str(error)=='SENDER_CGROUP_OR_DESCENDANTS_STILL_POPULATED',str(error)
    print('PASS dead leader with live child denied',flush=True)
    with open(writer_lock,'rb') as fence:
        try:fcntl.flock(fence,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('live child failed to hold shared fence')
        except BlockingIOError:pass
    signal.pidfd_send_signal(childfd,signal.SIGKILL)
    deadline=time.monotonic()+5
    while True:
        try:result=terminal.prove_terminal_for_marker(marker);break
        except terminal.Held:
            if time.monotonic()>=deadline:raise
            time.sleep(.05)
    assert result['pidfd_dead'] and result['cgroup_unpopulated'] and not result['effect_or_send_authority']
    print('PASS original marker, pidfd, exact InvocationID, terminal unit/job and empty cgroup',flush=True)
    with open(writer_lock,'rb') as fence:
        fcntl.flock(fence,fcntl.LOCK_EX|fcntl.LOCK_NB)
        terminal.prove_terminal_for_marker(marker)
        sample=recovery.sample(coord,netlink,expected_marker=marker.key,expected_genid=genid,
                               records=records,reference=reference,cache=cache)
        terminal.prove_terminal_for_marker(marker)
        assert not sample['effect_or_recovery_authority'] and not sample['nft_attachment_verified']
        print('PASS same custodian: terminal marker, exclusive writer flock, real genid, frozen BPF and fresh Readers',flush=True)
        print('PASS BPF FDs received from authenticated sender remain readable after its death',flush=True)
        print('BOUNDARY fixture-created maps are not yet proven attached to nft rules',flush=True)
    # Real private mount namespace; no mount change propagates to host.
    with tempfile.TemporaryDirectory(prefix='wrong-cgroup-mount-') as wrong:
        subprocess.run(['/usr/bin/mount','--bind',wrong,'/sys/fs/cgroup'],check=True,timeout=5)
        try:
            try:terminal.prove_terminal_for_marker(marker);raise AssertionError('wrong cgroup mount accepted')
            except terminal.Held as error:
                assert str(error) in ('CGROUP_MOUNT_OR_NAMESPACE_CHANGED','EXACT_UNIFIED_CGROUP_MOUNT_REQUIRED'),str(error)
        finally:subprocess.run(['/usr/bin/umount','/sys/fs/cgroup'],check=True,timeout=5)
    print('PASS actual cgroup mount replacement rejected in private namespace',flush=True)
    # Attempting to restart the participating writer must leave the marker.
    subprocess.run(['/usr/bin/systemctl','start',unit],check=False,timeout=10)
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        props=terminal._systemd(unit)
        if props['InvocationID']!=anchor.verified['invocation_id']:break
        time.sleep(.05)
    assert props['InvocationID']!=anchor.verified['invocation_id'] and coord.marker.exists()
    try:terminal.prove_terminal_for_marker(marker);raise AssertionError('replacement lifetime accepted')
    except terminal.Held as error:assert str(error)=='SAME_TERMINAL_INVOCATION_WITHOUT_JOB_REQUIRED'
    print('PASS replacement lifetime blocked by pending marker and proof rejected',flush=True)
    # Test-only simulated external tampering: mutate content, never authorize clearing it.
    with coord.marker.open('ab') as fd:fd.write(b' ')
    try:terminal.prove_terminal_for_marker(marker);raise AssertionError('changed marker accepted')
    except terminal.Held as error:assert str(error)=='ORIGINAL_MARKER_CHANGED'
    print('PASS changed marker rejected by original digest',flush=True)

finally:
    if childfd is not None:
        try:signal.pidfd_send_signal(childfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(childfd)
    if anchor is not None:anchor.close()
    for rec in records:os.close(rec['program_fd']);os.close(rec['map_fd'])
    reference.close();netlink.close()
    for channel in channels:channel.close()
    server.close();subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10);path.unlink(missing_ok=True);child_path.unlink(missing_ok=True)
    unit_file.unlink(missing_ok=True);subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
