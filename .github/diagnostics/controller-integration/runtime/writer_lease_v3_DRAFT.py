"""CI-only cooperative writer FD lifetime lock; not production authority."""
import fcntl
import os
import stat
from drain_coordination_DRAFT import FenceError

_CAPABILITY=object()

class WriterLease:
    def __init__(self,coord,capability):
        if capability is not _CAPABILITY:raise FenceError('ONLY_COORDINATOR_WRITER_LEASE')
        self.coord=coord;self.pid=os.getpid();self.closed=False;self.capability=capability
        coord.base._private_directory()
        self.fd=os.open(coord.writer_lock,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            self._identity()
            fcntl.flock(self.fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
            self._identity()
        except BaseException:
            os.close(self.fd);self.closed=True;raise

    def _identity(self):
        self.coord.base._private_directory()
        opened=os.fstat(self.fd);named=os.lstat(self.coord.writer_lock)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid!=0
                or stat.S_IMODE(opened.st_mode)!=0o600 or opened.st_nlink!=1
                or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)):
            raise FenceError('ROOT_PRIVATE_STABLE_WRITER_LOCK_REQUIRED')
        current=(opened.st_dev,opened.st_ino)
        if self.coord._writer_identity is not None and self.coord._writer_identity!=current:
            raise FenceError('WRITER_LOCK_REPLACED')
        self.coord._writer_identity=current

    def validate(self):
        if self.capability is not _CAPABILITY or self.closed or self.pid!=os.getpid():
            raise FenceError('ORIGINAL_LIVE_WRITER_LEASE_REQUIRED')
        self._identity()
        # Reassert SH: if another code path erroneously unlocked the FD,
        # recovery EX wins instead of permitting a writer without custody.
        fcntl.flock(self.fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        self._identity()
        return self.fd

    def close(self):
        if not self.closed:
            if self.pid!=os.getpid():raise FenceError('ONLY_OWNER_CAN_CLOSE_WRITER_LEASE')
            os.close(self.fd);self.closed=True

def acquire(coord):
    import drain_marker_v3_DRAFT as marker
    if type(coord) is not marker.CoordinatorV3:
        raise FenceError('BOUND_WRITER_COORDINATOR_REQUIRED')
    return WriterLease(coord,_CAPABILITY)
