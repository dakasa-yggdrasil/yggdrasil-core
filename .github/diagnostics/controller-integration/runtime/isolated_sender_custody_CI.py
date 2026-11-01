"""Bounded CI-only sender quiescence custody. Grants no cancellation authority.

All socket-capable writers must cooperate with the same stable writer inode;
this cannot exclude an unparticipating CAP_NET_ADMIN writer. The caller must
retain the marker and separately authenticate/reconcile Guardian state.
"""
import fcntl,os,socket,stat
import drain_marker_v3_DRAFT as marker
import guarded_nl as nl
import recovery_terminality_DRAFT as terminal

class Held(RuntimeError):pass

def require(value,reason):
    if not value:raise Held(reason)

class ExclusiveObservation:
    def __init__(self,anchor,netlink,expected_genid):
        require(type(anchor) is terminal.MarkerAnchor and type(netlink) is socket.socket
                and type(expected_genid) is int,'EXACT_CUSTODIAN_INPUTS_REQUIRED')
        self.anchor=anchor;self.netlink=netlink;self.expected_genid=expected_genid
        self.fd=None;self.pid=os.getpid()
    def __enter__(self):
        coord=self.anchor.coordinator
        observed=marker._durable_marker_identity(coord)
        require(observed[:3]==self.anchor.key,'ORIGINAL_MARKER_REQUIRED')
        recorded=observed[3].get('writer_lock_identity')
        require(type(recorded) is list and len(recorded)==2 and all(type(x) is int for x in recorded),
                'MARKER_WRITER_INODE_REQUIRED')
        fd=os.open(coord.writer_lock,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            self.fd=fd;self.writer_identity=tuple(recorded);self._same_inode()
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.verify()
            return self
        except BaseException:
            os.close(fd);self.fd=None;raise
    def _same_inode(self):
        opened=os.fstat(self.fd);named=os.lstat(self.anchor.coordinator.writer_lock)
        require(stat.S_ISREG(opened.st_mode) and opened.st_uid==0 and opened.st_nlink==1
                and stat.S_IMODE(opened.st_mode)==0o600 and
                (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino)==self.writer_identity,
                'SAME_ROOT_PRIVATE_WRITER_INODE_REQUIRED')
    def verify(self):
        require(self.fd is not None and self.pid==os.getpid(),'SAME_LIVE_EXCLUSIVE_CUSTODIAN_REQUIRED')
        self._same_inode()
        terminal.prove_terminal_for_marker(self.anchor)
        require(nl.genid(self.netlink)==self.expected_genid,'EXCLUSIVE_OBSERVATION_GENID_CHANGED')
        self._same_inode()
        terminal.prove_terminal_for_marker(self.anchor)
        require(nl.genid(self.netlink)==self.expected_genid,'EXCLUSIVE_OBSERVATION_GENID_CHANGED')
        return {'terminal_sender':True,'writer_inode':self.writer_identity,'genid':self.expected_genid,
                'marker':self.anchor.key,'cancel_authority':False,'production_authority':False}
    def __exit__(self,*_):
        if self.fd is not None:os.close(self.fd);self.fd=None
