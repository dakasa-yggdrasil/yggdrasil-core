"""Real Linux netlink socket and writer lock lifetime; CI namespace only."""
import fcntl,os,signal,socket,subprocess,sys,time
from pathlib import Path
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root/'runtime'))
import drain_marker_v3_DRAFT as marker,guarded_nl as nl,guarded_sender_session_DRAFT as sender
import fenced_netfilter_CI as fenced
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
observer=fenced.FencedSocket(coord);copy=os.dup(observer.sock.fileno())
try:
    try:observer.close();raise AssertionError('observer alias accepted')
    except fenced.Held as error:assert str(error)=='OBSERVATION_SOCKET_STILL_REFERENCED'
    assert not exclusive_possible()
    os.close(copy);copy=None;observer.close();assert exclusive_possible()
    print('PASS privileged observer alias retains SH until final socket closes',flush=True)
finally:
    if copy is not None:os.close(copy)
    observer.close()
original_bind=fenced._bind
try:
    def bad_observer_bind(_sock):raise OSError('CI_OBSERVER_BIND_FAILURE')
    fenced._bind=bad_observer_bind
    try:fenced.FencedSocket(coord);raise AssertionError('observer bind failure accepted')
    except OSError as error:assert str(error)=='CI_OBSERVER_BIND_FAILURE'
    assert exclusive_possible()
finally:fenced._bind=original_bind
observer=fenced.FencedSocket(coord);original_close=fenced._close
try:
    def bad_observer_close(_sock):raise OSError('CI_OBSERVER_CLOSE_FAILURE')
    fenced._close=bad_observer_close
    try:observer.close();raise AssertionError('observer close failure accepted')
    except OSError as error:assert str(error)=='CI_OBSERVER_CLOSE_FAILURE'
    assert not exclusive_possible()
    fenced._close=original_close;observer.close();assert exclusive_possible()
    print('PASS observer bind/close failures preserve socket-before-lease ordering',flush=True)
finally:fenced._close=original_close;observer.close()
# A privileged probe inherits the same SH open-file-description through
# nsenter+exec. Closing the parent's copy cannot make EX available while the
# child remains alive with its socket-capable privilege.
lease=coord.acquire_writer_lease();fd=lease.validate()
child_code=('import fcntl,os,sys; fd=int(sys.argv[1]); os.fstat(fd); '
            'fcntl.flock(fd,fcntl.LOCK_SH|fcntl.LOCK_NB); '
            'sys.stdout.write("READY\\n"); sys.stdout.flush(); sys.stdin.read(1)')
child=subprocess.Popen(['/usr/bin/nsenter','--net=/proc/self/ns/net','--','/usr/bin/python3','-I','-B','-c',child_code,str(fd)],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,))
try:
    assert child.stdout.readline()==b'READY\n'
    lease.close();assert not exclusive_possible()
    child.stdin.write(b'x');child.stdin.flush();assert child.wait(timeout=5)==0
    assert exclusive_possible()
    print('PASS inherited probe SH survives nsenter and exec until child exit',flush=True)
finally:
    if child.poll() is None:child.kill();child.wait(timeout=5)
    lease.close()
# The exact native launcher passes SH into an actual nft child, including a
# read/check invocation. Kill the launcher while nft waits on a FIFO, and
# prove the child alone keeps recovery EX unavailable until its pidfd exits.
# The FIFO blocks before the nft read: this does not prove its netlink socket
# was opened, only the actual nft process inherited and retained the lease.
import original_process as original
fifo=root/'ci-native-nft-input.fifo'
os.mkfifo(fifo,0o600)
rfd,wfd=os.pipe();launcher=os.fork()
if launcher==0:
    os.close(rfd)
    lease=coord.acquire_writer_lease()
    real_popen=original.subprocess.Popen
    def spawn_then_die(*args,**kwargs):
        proc=real_popen(*args,**kwargs)
        os.write(wfd,(str(proc.pid)+'\n').encode())
        os._exit(0)
    original.subprocess.Popen=spawn_then_die
    original.native(['/usr/sbin/nft','-c','-f',str(fifo)],deadline=time.monotonic()+5,writer_lease=lease)
    os._exit(91)
os.close(wfd); nft_pidfd=None
try:
    raw=os.read(rfd,32); assert raw.endswith(b'\n')
    nft_pid=int(raw); nft_pidfd=os.pidfd_open(nft_pid)
    _,status=os.waitpid(launcher,0);assert os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
    assert not exclusive_possible()
    signal.pidfd_send_signal(nft_pidfd,signal.SIGKILL)
    import select
    poll=select.poll();poll.register(nft_pidfd,select.POLLIN);assert poll.poll(5000)
    assert exclusive_possible()
    print('PASS nft process inherits SH through launcher death while blocked before read (socket opening not proved)',flush=True)
finally:
    os.close(rfd)
    if nft_pidfd is not None:
        try:signal.pidfd_send_signal(nft_pidfd,signal.SIGKILL)
        except ProcessLookupError:pass
        os.close(nft_pidfd)
    fifo.unlink(missing_ok=True)
print('BOUNDARY: cooperative writers and same-process aliases; independent SCM transfers require separate custody',flush=True)
