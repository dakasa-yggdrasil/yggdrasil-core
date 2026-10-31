"""CI service wrapper around real original_process.native."""
import os,signal,sys,threading,time
from pathlib import Path
root,mode,lock_path,lock_identity=sys.argv[1:]
sys.path.insert(0,str(Path(root)/'runtime'))
import original_process as process
import lock_guard
with lock_guard.open_checked(lock_path,lock_identity) as lock:
    import fcntl
    fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    dev,ino=lock_identity.split(':')
    if mode=='writer':
        facts={}
        class BlockingInput:
            def read(self,_):time.sleep(40);return b''
        def suspend_real_nft():
            while not facts.get('pid'):time.sleep(.005)
            pid=facts['pid'];fd=os.pidfd_open(pid)
            try:
                # Popen returns only after exec succeeded; suspend the actual nft
                # while it awaits input, before any test command is submitted.
                assert os.path.realpath('/proc/%d/exe'%pid)==os.path.realpath('/usr/sbin/nft')
                signal.pidfd_send_signal(fd,signal.SIGSTOP)
                for _ in range(200):
                    if '\nState:\tT' in Path('/proc/%d/status'%pid).read_text():break
                    time.sleep(.005)
                else:raise RuntimeError('NFT_NOT_STOPPED')
                found=False
                for name in os.listdir('/proc/%d/fd'%pid):
                    try:st=os.stat('/proc/%d/fd/%s'%(pid,name))
                    except FileNotFoundError:continue
                    if (st.st_dev,st.st_ino)==(int(dev),int(ino)):found=True
                Path(root,'native-child.report').write_text('INHERITED' if found else 'ABSENT')
                Path(root,'native-child.pid').write_text(str(pid))
            finally:os.close(fd)
        threading.Thread(target=suspend_real_nft,daemon=True).start()
        process.native(['/usr/sbin/nft','-f','-'],deadline=time.monotonic()+45,
                       stdin=BlockingInput(),custody=facts,writer_lease_fd=lock.fileno())
    else:
        process.native(['/usr/bin/python3','-B',str(Path(root)/'native_child.py'),
                        str(Path(root)/'native-child.pid'),str(Path(root)/'native-child.report'),dev,ino,'40'],
                       deadline=time.monotonic()+45,writer_lease_fd=None)
