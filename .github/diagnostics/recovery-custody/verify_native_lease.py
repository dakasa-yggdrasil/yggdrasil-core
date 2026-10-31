"""Real subprocess FD inheritance, killed parent, read-only and clean reexec."""
import fcntl,os,signal,subprocess,sys,time,uuid
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import drain_marker_v3_DRAFT as marker
coord=marker.CoordinatorV3(root/'coord');coord.initialize_for_ci();lock=coord.writer_lock
st=lock.stat();identity='%d:%d'%(st.st_dev,st.st_ino);unit='ci-native-lease-'+uuid.uuid4().hex+'.service';unit_file=Path('/run/systemd/system')/unit
childfd=None

def wait_file(path):
    end=time.monotonic()+8
    while not path.exists():
        if time.monotonic()>end:raise RuntimeError('FILE_TIMEOUT '+str(path))
        time.sleep(.02)

def launch(mode):
    global childfd
    for name in ('native-child.pid','native-child.report'):(root/name).unlink(missing_ok=True)
    import shutil
    shutil.rmtree(root/'native-io-root',ignore_errors=True)
    unit_file.write_text('[Service]\nType=simple\nKillMode=process\nRuntimeMaxSec=50s\nEnvironment=CI_GUARDED_FIXTURE=1\nExecStart=/usr/bin/python3 -B '+str(root/'native_parent.py')+' '+str(root)+' '+mode+' '+str(lock)+' '+identity+'\n')
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,timeout=10)
    subprocess.run(['/usr/bin/systemctl','start',unit],check=True,timeout=10)
    wait_file(root/'native-child.pid');childfd=os.pidfd_open(int((root/'native-child.pid').read_text()))
    wait_file(root/'native-child.report')
    assert (root/'native-child.report').read_text()==('INHERITED' if mode=='writer' else 'ABSENT')
    subprocess.run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=KILL',unit],check=True,timeout=10)
    time.sleep(.15)

def exclusive():
    with open(lock,'rb') as f:
        try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
        except BlockingIOError:return False

def close_child():
    global childfd
    signal.pidfd_send_signal(childfd,signal.SIGKILL);os.close(childfd);childfd=None
    deadline=time.monotonic()+5
    while not exclusive():
        if time.monotonic()>deadline:raise RuntimeError('WRITER_LOCK_NOT_RELEASED')
        time.sleep(.02)

try:
    sys.path.insert(0,str(root/'runtime'))
    import native_io,original_process
    try:
        original_process.native(['/usr/sbin/nft','-f','-'],deadline=time.monotonic()+5,writer_lease=object())
        raise AssertionError('untyped lease accepted')
    except original_process.Held as error:assert str(error)=='TYPED_WRITER_LEASE_REQUIRED'
    print('PASS untyped writer lease rejected',flush=True)
    launch('writer');assert not exclusive();close_child()
    print('PASS real nft child retains passed FD after parent death; exclusive succeeds only after child exit',flush=True)
    launch('reader');assert exclusive();close_child()
    print('PASS real nft read-only child does not inherit writer lock; prior writer FD did not leak on reexec',flush=True)
    # Successful child exit followed by read-only exec must release the lease.
    with coord.writer_lease() as lease:
        output,facts=original_process.native(['/usr/sbin/nft','-f','-'],stdin=b'# no-op\n',
                                               deadline=time.monotonic()+5,writer_lease=lease)
        assert facts['exit_code']==0 and facts['local_child_joined']
    output,facts=original_process.native(['/usr/sbin/nft','--version'],deadline=time.monotonic()+5)
    assert b'nftables' in output and facts['exit_code']==0 and exclusive()
    print('PASS clean typed writer completion and read-only reexec release lease',flush=True)

finally:
    if childfd is not None:
        try:signal.pidfd_send_signal(childfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(childfd)
    subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10);unit_file.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
