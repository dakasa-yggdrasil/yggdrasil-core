"""Exercise terminal sender proof against live systemd units in CI only."""
import hashlib,os,signal,socket,subprocess,sys,tempfile,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'runtime'))
import drain_marker_v3_DRAFT as v3
import guarded_unit_identity as identity
import recovery_terminality_DRAFT as terminal

root=Path(__file__).resolve().parent;peer=(root/'systemd_peer.py').resolve();path=root/'terminal-peer.sock'
coord=v3.CoordinatorV3(root/'coord');coord.initialize_for_ci()
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
    unit_file.write_text('[Service]\nType=simple\nKillMode=process\nRuntimeMaxSec=30s\nEnvironment=CI_CONTROLLER_UNIT='+unit+'\nEnvironment=CI_TERM_CHILD_PIDFILE='+str(child_path)+'\nEnvironment=CI_TERM_RUNTIME='+str(root/'runtime')+'\nEnvironment=CI_TERM_COORD='+str(coord.directory)+'\nExecStart='+' '.join(argv)+'\n')
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
    channel=launch();props=identity._properties(unit);digest=hashlib.sha256(peer.read_bytes()).hexdigest()
    anchor=terminal.capture_authenticated(channel,unit=unit,invocation=props['InvocationID'],argv=argv,source_sha256=digest)
    marker=terminal.capture_marker(anchor,coord)
    childfd=os.pidfd_open(int(child_path.read_text()))
    try:terminal.prove_terminal(anchor);raise AssertionError('live sender accepted')
    except terminal.Held as error:assert str(error)=='ORIGINAL_SENDER_STILL_ALIVE'
    subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',unit],check=True,timeout=10)
    time.sleep(.2)
    print('CI_TERMINAL_SYSTEMD',terminal._systemd(unit),flush=True)
    try:terminal.prove_terminal_for_marker(marker);raise AssertionError('live descendant accepted')
    except terminal.Held as error:assert str(error)=='SENDER_CGROUP_OR_DESCENDANTS_STILL_POPULATED',str(error)
    print('PASS dead leader with live child denied',flush=True)
    signal.pidfd_send_signal(childfd,signal.SIGKILL)
    deadline=time.monotonic()+5
    while True:
        try:result=terminal.prove_terminal_for_marker(marker);break
        except terminal.Held:
            if time.monotonic()>=deadline:raise
            time.sleep(.05)
    assert result['pidfd_dead'] and result['cgroup_unpopulated'] and not result['effect_or_send_authority']
    print('PASS original marker, pidfd, exact InvocationID, terminal unit/job and empty cgroup',flush=True)
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
    for channel in channels:channel.close()
    server.close();subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10);path.unlink(missing_ok=True);child_path.unlink(missing_ok=True)
    unit_file.unlink(missing_ok=True);subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
