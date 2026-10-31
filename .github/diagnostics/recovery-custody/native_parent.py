"""CI service wrapper through actual native_io.command and original_process."""
import os,signal,sys,time
from pathlib import Path
root,mode,lock_path,lock_identity=sys.argv[1:]
sys.path.insert(0,str(Path(root)/'runtime'))
import native_io,original_process as process
import lock_guard
with lock_guard.open_checked(lock_path,lock_identity) as lock:
    import fcntl
    fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    dev,ino=map(int,lock_identity.split(':'))
    native_io.ROOT=Path(root)/'native-io-root';native_io.ROOT.mkdir(mode=0o700)
    native_io.configure();native_io.end_initialization()
    real_popen=process.subprocess.Popen
    def suspend_nft(*args,**kwargs):
        child=real_popen(*args,**kwargs)
        assert os.path.realpath('/proc/%d/exe'%child.pid)==os.path.realpath('/usr/sbin/nft')
        fd=os.pidfd_open(child.pid)
        try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
        finally:os.close(fd)
        for _ in range(200):
            if '\nState:\tT' in Path('/proc/%d/status'%child.pid).read_text():break
            time.sleep(.005)
        else:raise RuntimeError('NFT_NOT_STOPPED')
        found=False
        for name in os.listdir('/proc/%d/fd'%child.pid):
            try:st=os.stat('/proc/%d/fd/%s'%(child.pid,name))
            except FileNotFoundError:continue
            if (st.st_dev,st.st_ino)==(dev,ino):found=True
        Path(root,'native-child.report').write_text('INHERITED' if found else 'ABSENT')
        Path(root,'native-child.pid').write_text(str(child.pid))
        return child
    process.subprocess.Popen=suspend_nft
    if mode=='writer':
        native_io.command(['/usr/sbin/nft','-f','-'],data=b'list ruleset\n',timeout=10,
                          role='hot_dynamic_apply',writer_lease_fd=lock.fileno())
    else:
        native_io.command(['/usr/sbin/nft','-j','list','ruleset'],timeout=10,role='ruleset_mark')
