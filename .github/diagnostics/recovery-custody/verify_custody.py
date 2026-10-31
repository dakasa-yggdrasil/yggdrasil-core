"""Real systemd senders, child, SCM_RIGHTS, flock and custodian death, CI-only."""
import hashlib,json,os,select,signal,socket,subprocess,sys,time,uuid
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import drain_marker_v3_DRAFT as v3
uid=uuid.uuid4().hex[:12];sender='ci-custody-sender-'+uid+'.service';guardian='ci-custody-guardian-'+uid+'.service'
units=[sender,guardian];files=[Path('/run/systemd/system')/unit for unit in units]
coord=v3.CoordinatorV3(root/'coord');coord.initialize_for_ci();lock=root/'writer.lock';lock.touch(mode=0o600)
lock_stat=lock.stat();lock_identity='%d:%d'%(lock_stat.st_dev,lock_stat.st_ino)
sockpath=root/'custody.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(sockpath));server.listen(2)
source=hashlib.sha256((root/'writer.py').read_bytes()).hexdigest();custodian=None;childfd=None

def query(command=None):
    if command is not None:custodian.stdin.write(command+'\n');custodian.stdin.flush()
    ready,_,_=select.select([custodian.stdout],[],[],15)
    if not ready:raise RuntimeError('CUSTODIAN_RESPONSE_TIMEOUT')
    line=custodian.stdout.readline()
    if not line:raise RuntimeError('CUSTODIAN_EXITED: '+str(custodian.poll()))
    return json.loads(line)

def wait_for(path):
    deadline=time.monotonic()+8
    while not path.exists():
        if time.monotonic()>deadline:raise RuntimeError('FILE_TIMEOUT '+str(path))
        time.sleep(.02)

def signal_main(unit):
    subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',unit],check=True,timeout=10)
    time.sleep(.2)

try:
    for unit,role,unit_file in zip(units,['sender','guardian'],files):
        args=[str(root/'writer.py'),str(root),role,unit,str(coord.directory),str(lock),str(sockpath),str(root/(role+'.stage')),lock_identity]
        unit_file.write_text('[Service]\nType=simple\nKillMode=process\nRuntimeMaxSec=45s\nEnvironment=CI_CONTROLLER_UNIT='+unit+'\nExecStart=/usr/bin/python3 -B '+' '.join(args)+'\n')
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
    custodian=subprocess.Popen(['/usr/bin/python3','-B',str(root/'custodian.py'),str(root),str(server.fileno()),sender,guardian,source,str(lock),lock_identity],
        pass_fds=[server.fileno()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    server.close()
    subprocess.run(['/usr/bin/systemctl','start',sender],check=True,timeout=10)
    wait_for(root/'child.pid');childfd=os.pidfd_open(int((root/'child.pid').read_text()))
    subprocess.run(['/usr/bin/systemctl','start',guardian],check=True,timeout=10)
    ready=query();assert ready['state']=='READY' and len(ready['fds'])==2 and len(set(ready['fds']))==2,ready
    if '--early-custodian-death' in sys.argv:
        os.kill(custodian.pid,signal.SIGKILL);custodian.wait(timeout=5)
        with open(lock,'rb') as f:
            import fcntl
            try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('live writers lost their fence')
            except BlockingIOError:pass
        assert coord.marker.exists()
        print('PASS custodian dies with writers live: inherited shared fence and marker remain',flush=True)
        sys.exit(0)
    signal_main(guardian)
    pinned=query('sockets');assert pinned['state']=='SOCKETS' and pinned['inodes']==ready['fds'],pinned
    assert query('acquire')['state']=='HOLD'
    print('PASS Guardian killed; custodian retains both real netlink sockets and refuses live sender',flush=True)
    signal_main(sender)
    held=query('acquire');assert held['state']=='HOLD' and 'POPULATED' in held['reason'],held
    print('PASS inherited sender child/socket/lock prevents terminal evidence',flush=True)
    signal.pidfd_send_signal(childfd,signal.SIGKILL)
    deadline=time.monotonic()+5
    while True:
        acquired=query('acquire')
        if acquired['state']=='EXCLUSIVE':break
        if time.monotonic()>deadline:raise RuntimeError(str(acquired))
        time.sleep(.05)
    assert acquired['old_sockets_closed'] and not acquired['production_authority']
    # Replacing the pathname cannot silently turn a different flock into the fence.
    displaced=root/'writer.lock.original';lock.rename(displaced);lock.touch(mode=0o600)
    try:
        changed=query('lockcheck');assert changed=={'reason':'ORIGINAL_LOCK_INODE_REQUIRED','state':'HOLD'},changed
    finally:
        lock.unlink();displaced.rename(lock)
    assert query('lockcheck')['state']=='ORIGINAL_LOCK'
    print('PASS replaced lock inode is rejected even with original exclusive fd open',flush=True)
    (root/'sender.stage').unlink()
    subprocess.run(['/usr/bin/systemctl','start',sender],check=False,timeout=10)
    wait_for(root/'sender.stage')
    assert (root/'sender.stage').read_text()=='BLOCKED_BEFORE_SOCKET'
    assert coord.marker.exists()
    print('PASS exclusive custody fence blocks cooperative restart before socket open',flush=True)
    os.kill(custodian.pid,signal.SIGKILL);custodian.wait(timeout=5)
    with open(lock,'rb') as f:
        import fcntl
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert coord.marker.exists()
    print('PASS custodian death releases kernel lock but leaves original marker pending; no authority reconstructed',flush=True)
finally:
    if custodian is not None and custodian.poll() is None:
        custodian.kill();custodian.wait(timeout=5)
    if childfd is not None:
        try:signal.pidfd_send_signal(childfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(childfd)
    for unit in units:subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10)
    for f in files:f.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
