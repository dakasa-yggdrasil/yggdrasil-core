"""CI-only flock file identity under a trusted, root-owned private directory."""
import os,stat
from pathlib import Path
class Held(RuntimeError):pass

def open_checked(path,expected):
    p=Path(path)
    directory=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        st=os.fstat(directory)
        if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o077:raise Held('TRUSTED_PRIVATE_DIRECTORY_REQUIRED')
        fd=os.open(p.name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=directory)
        try:
            obj=os.fstat(fd);named=os.stat(p.name,dir_fd=directory,follow_symlinks=False)
            key=lambda x:(x.st_dev,x.st_ino)
            if (not stat.S_ISREG(obj.st_mode) or obj.st_uid!=0 or obj.st_nlink!=1
                    or stat.S_IMODE(obj.st_mode)!=0o600 or key(obj)!=key(named)
                    or '%d:%d'%key(obj)!=expected):raise Held('ORIGINAL_LOCK_INODE_REQUIRED')
            return os.fdopen(fd,'rb')
        except BaseException:os.close(fd);raise
    finally:os.close(directory)
