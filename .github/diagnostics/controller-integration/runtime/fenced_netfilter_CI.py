"""Cooperative CI-only custody for privileged netfilter observation sockets.

Not a proof about uninstrumented processes or SCM_RIGHTS recipients. A close
failure retains the raw lease FD and never grants exclusive recovery.
"""
import os,socket
import drain_marker_v3_DRAFT as marker

class Held(RuntimeError):pass

def _bind(sock):sock.bind((0,0));sock.settimeout(5)
def _close(sock):sock.close()

class FencedSocket:
    def __init__(self,coord):
        if type(coord) is not marker.CoordinatorV3:raise Held('EXACT_COORDINATOR_REQUIRED')
        self.lease=None;self.sock=None;self.inode=None;self.pid=os.getpid()
        try:
            self.lease=coord.acquire_writer_lease()
            self.sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)
            self.inode=os.fstat(self.sock.fileno()).st_ino
            _bind(self.sock)
        except BaseException:
            self.close();raise
    def close(self):
        if self.pid!=os.getpid():raise Held('SAME_PROCESS_SOCKET_CUSTODY_REQUIRED')
        if self.sock is not None:
            _close(self.sock);self.sock=None  # close error retains SH
        if self.inode is not None:
            expected='socket:['+str(self.inode)+']'
            for fd in os.listdir('/proc/self/fd'):
                try:target=os.readlink('/proc/self/fd/'+fd)
                except FileNotFoundError:continue
                if target==expected:raise Held('OBSERVATION_SOCKET_STILL_REFERENCED')
            self.inode=None
        if self.lease is not None:self.lease.close();self.lease=None
    def __enter__(self):return self.sock
    def __exit__(self,*_):self.close()
