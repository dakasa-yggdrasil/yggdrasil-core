"""Exercise terminal sender proof against live systemd units in CI only."""
import hashlib,os,socket,subprocess,sys,time,uuid
from pathlib import Path
import guarded_unit_identity as identity
import recovery_terminality_DRAFT as terminal

root=Path(__file__).resolve().parent;peer=(root/'systemd_peer.py').resolve();path=root/'terminal-peer.sock'
unit='ci-terminal-proof-'+uuid.uuid4().hex+'.service';unit_file=Path('/run/systemd/system')/unit
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(str(path));server.listen(2);server.settimeout(12)
argv=['/usr/bin/python3','-B',str(peer),str(path)];anchor=None;channels=[]
def launch():
    subprocess.run(['/usr/bin/systemctl','start',unit],check=True,timeout=10)
    channel,_=server.accept();channels.append(channel);return channel
try:
    unit_file.write_text('[Service]\nType=simple\nRuntimeMaxSec=30s\nExecStart='+' '.join(argv)+'\n')
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
    channel=launch();props=identity._properties(unit);digest=hashlib.sha256(peer.read_bytes()).hexdigest()
    anchor=terminal.capture_authenticated(channel,unit=unit,invocation=props['InvocationID'],argv=argv,source_sha256=digest)
    try:terminal.prove_terminal(anchor);raise AssertionError('live sender accepted')
    except terminal.Held as error:assert str(error)=='ORIGINAL_SENDER_STILL_ALIVE'
    subprocess.run(['/usr/bin/systemctl','stop',unit],check=True,timeout=10)
    print('CI_TERMINAL_SYSTEMD',terminal._systemd(unit),flush=True)
    deadline=time.monotonic()+5
    while True:
        try:result=terminal.prove_terminal(anchor);break
        except terminal.Held:
            if time.monotonic()>=deadline:raise
            time.sleep(.05)
    assert result['pidfd_dead'] and result['cgroup_unpopulated'] and not result['effect_or_send_authority']
    print('PASS original pidfd, exact InvocationID, terminal unit/job and empty cgroup',flush=True)
    launch()
    try:terminal.prove_terminal(anchor);raise AssertionError('replacement invocation accepted')
    except terminal.Held as error:assert str(error)=='SAME_TERMINAL_INVOCATION_WITHOUT_JOB_REQUIRED'
    print('PASS replacement lifetime rejected even though original pidfd is dead',flush=True)
finally:
    if anchor is not None:anchor.close()
    for channel in channels:channel.close()
    server.close();subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10);path.unlink(missing_ok=True)
    unit_file.unlink(missing_ok=True);subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
