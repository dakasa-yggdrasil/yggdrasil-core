"""CI service wrapper around real original_process.native."""
import sys,time
from pathlib import Path
root,mode,lock_path,lock_identity=sys.argv[1:]
sys.path.insert(0,str(Path(root)/'runtime'))
import original_process as process
import lock_guard
with lock_guard.open_checked(lock_path,lock_identity) as lock:
    import fcntl
    fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    dev,ino=lock_identity.split(':')
    process.native(['/usr/bin/python3','-B',str(Path(root)/'native_child.py'),
                    str(Path(root)/'native-child.pid'),str(Path(root)/'native-child.report'),dev,ino,'40'],
                   deadline=time.monotonic()+45,writer_lease_fd=lock.fileno() if mode=='writer' else None)
