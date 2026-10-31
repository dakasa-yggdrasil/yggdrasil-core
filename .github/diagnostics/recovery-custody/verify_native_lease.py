"""Real subprocess FD inheritance, killed parent, read-only and clean reexec."""
import fcntl,os,signal,subprocess,sys,time,uuid
from pathlib import Path
root=Path(__file__).resolve().parent;lock=root/'native-writer.lock';lock.touch(mode=0o600)
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
    unit_file.write_text('[Service]\nType=simple\nKillMode=process\nRuntimeMaxSec=50s\nExecStart=/usr/bin/python3 -B '+str(root/'native_parent.py')+' '+str(root)+' '+mode+' '+str(lock)+' '+identity+'\n')
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
        native_io.command(['/usr/sbin/nft','-j','list','ruleset'],role='ruleset_mark',writer_lease_fd=0)
        raise AssertionError('read-only role accepted writer lease')
    except original_process.Held as error:assert str(error)=='WRITER_LEASE_FOR_APPLY_ONLY'
    print('PASS native_io rejects writer lease for read-only role',flush=True)
    launch('writer');assert not exclusive();close_child()
    print('PASS real nft child retains passed FD after parent death; exclusive succeeds only after child exit',flush=True)
    launch('reader');assert exclusive();close_child()
    print('PASS real nft read-only child does not inherit writer lock; prior writer FD did not leak on reexec',flush=True)
    # Clean, successful exit as opposed to the forced-death paths above.
    code=('import os,sys; key=(int(sys.argv[1]),int(sys.argv[2])); found=False; '
          'fds=os.listdir("/proc/self/fd"); '
          'print(int(any((lambda s:(s.st_dev,s.st_ino)==key)(os.stat("/proc/self/fd/"+n)) '
          'for n in fds if os.path.exists("/proc/self/fd/"+n))))')
    with open(lock,'rb') as lease:
        fcntl.flock(lease,fcntl.LOCK_SH|fcntl.LOCK_NB)
        args=['/usr/bin/python3','-B','-c',code,str(st.st_dev),str(st.st_ino)]
        output,_=original_process.native(args,deadline=time.monotonic()+5,writer_lease_fd=lease.fileno())
        assert output.strip()==b'1'
    output,_=original_process.native(args,deadline=time.monotonic()+5)
    assert output.strip()==b'0' and exclusive()
    print('PASS normal child exit and read-only reexec leave no writer lease FD',flush=True)
finally:
    if childfd is not None:
        try:signal.pidfd_send_signal(childfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(childfd)
    subprocess.run(['/usr/bin/systemctl','stop',unit],check=False,timeout=10);unit_file.unlink(missing_ok=True)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=False,timeout=10)
