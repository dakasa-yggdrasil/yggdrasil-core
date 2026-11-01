"""Real Linux netlink socket and writer lock lifetime; CI namespace only."""
import fcntl,os,socket,sys
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import drain_marker_v3_DRAFT as marker,guarded_nl as nl,guarded_sender_session_DRAFT as sender
coord=marker.CoordinatorV3(root/'session-coord');coord.initialize_for_ci()
class Identity:
    @staticmethod
    def authenticate(*_args,**_kwargs):return {'pidfd':os.pidfd_open(os.getpid())}
identity=Identity();guard={'unit':'ci-only.service','invocation_id':'f'*32,'argv':['ci'],'source_sha256':'a'*64}
def new_session():
    left,right=socket.socketpair()
    try:return sender.SenderSession(left,identity=identity,guardian=guard,nl=nl,coord=coord),right
    except BaseException:left.close();right.close();raise

def exclusive_possible():
    fd=os.open(coord.writer_lock,os.O_RDONLY|os.O_CLOEXEC)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
        except BlockingIOError:return False
    finally:os.close(fd)

# A duplicated same-process netfilter FD must keep SH until its last close.
session,peer=new_session();copy=os.dup(session.netlink.fileno())
try:
    try:session.close();raise AssertionError('live alias accepted')
    except sender.Held as error:assert str(error)=='SESSION_NETLINK_SOCKET_STILL_REFERENCED'
    assert not exclusive_possible()
    os.close(copy);copy=None;session.close();assert exclusive_possible()
    print('PASS live duplicate netfilter FD retains writer SH until alias terminal',flush=True)
finally:
    if copy is not None:os.close(copy)
    session.close();peer.close()

# A forked child inherits socket and lease together. Even after the parent
# closes its session, the open-file-description lock remains until child exit.
session,peer=new_session();rfd,wfd=os.pipe();child=os.fork()
if child==0:
    os.close(wfd)
    try:os.read(rfd,1)
    finally:os._exit(0)
os.close(rfd)
try:
    session.close();assert not exclusive_possible()
    os.write(wfd,b'x');os.close(wfd);wfd=None
    _pid,status=os.waitpid(child,0);assert os.WIFEXITED(status) and exclusive_possible()
    print('PASS child-inherited socket and writer lock block EX until child exit',flush=True)
finally:
    if wfd is not None:os.close(wfd)
    try:os.waitpid(child,0)
    except ChildProcessError:pass
    session.close();peer.close()

# A bind failure is pre-effect: close the created socket before releasing SH.
original_bind=sender._bind_netlink
try:
    def bad_bind(_sock):raise OSError('CI_BIND_FAILURE')
    sender._bind_netlink=bad_bind
    try:new_session();raise AssertionError('bind failure accepted')
    except OSError as error:assert str(error)=='CI_BIND_FAILURE'
    assert exclusive_possible()
    print('PASS bind failure closes its original socket before releasing writer SH',flush=True)
finally:sender._bind_netlink=original_bind

# An uncertain close must retain the lease and let an explicit retry close it.
session,peer=new_session();original_close=sender._close_netlink
try:
    def bad_close(_sock):raise OSError('CI_CLOSE_FAILURE')
    sender._close_netlink=bad_close
    try:session.close();raise AssertionError('close failure accepted')
    except OSError as error:assert str(error)=='CI_CLOSE_FAILURE'
    assert not exclusive_possible()
    sender._close_netlink=original_close;session.close();assert exclusive_possible()
    print('PASS uncertain close retains writer SH until confirmed socket closure',flush=True)
finally:
    sender._close_netlink=original_close;session.close();peer.close()
print('BOUNDARY: cooperative writers and same-process aliases; independent SCM transfers require separate custody',flush=True)
