"""CI-only independent custody; no writes to netlink, no recovery authority."""
import array,fcntl,json,os,socket,stat,sys
from pathlib import Path
root,listener_fd,sender_unit,guardian_unit,source,lock_path,lock_identity=sys.argv[1:]
sys.path.insert(0,str(Path(root)/'runtime'))
sys.path.insert(0,root)
import drain_marker_v3_DRAFT as v3
import guarded_unit_identity as identity
import recovery_terminality_DRAFT as terminal
import lock_guard
listener=socket.socket(fileno=int(listener_fd));anchors={};received=[];exclusive=None
coord=v3.CoordinatorV3(Path(root)/'coord')
def report(**kw):print(json.dumps(kw,sort_keys=True),flush=True)
def accept(role,unit):
    channel,_=listener.accept();props=identity._properties(unit)
    argv=['/usr/bin/python3','-B',str(Path(root)/'writer.py'),root,role,unit,
          str(Path(root)/'coord'),lock_path,str(Path(root)/'custody.sock'),str(Path(root)/(role+'.stage')),lock_identity]
    anchor=terminal.capture_authenticated(channel,unit=unit,invocation=props['InvocationID'],argv=argv,source_sha256=source)
    data,anc,flags,_=channel.recvmsg(1,socket.CMSG_SPACE(array.array('i').itemsize))
    if data!=b'F' or flags&(socket.MSG_CTRUNC|socket.MSG_TRUNC) or len(anc)!=1:raise RuntimeError('EXACT_NETLINK_DESCRIPTOR_REQUIRED')
    level,kind,raw=anc[0];fds=array.array('i');fds.frombytes(raw[:len(raw)-(len(raw)%fds.itemsize)])
    if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS or len(fds)!=1 or not stat.S_ISSOCK(os.fstat(fds[0]).st_mode):raise RuntimeError('ONE_SOCKET_FD_REQUIRED')
    probe=socket.socket(fileno=fds[0])
    try:
        if (probe.getsockopt(socket.SOL_SOCKET,socket.SO_DOMAIN)!=socket.AF_NETLINK
                or probe.getsockopt(socket.SOL_SOCKET,socket.SO_PROTOCOL)!=12
                or probe.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_RAW):
            raise RuntimeError('EXACT_NETFILTER_NETLINK_SOCKET_REQUIRED')
    finally:probe.detach()
    received.append(fds[0]);anchors[role]=(anchor,channel)
    if role=='sender':return terminal.capture_marker(anchor,coord)
try:
    marker=accept('sender',sender_unit);accept('guardian',guardian_unit)
    report(state='READY',fds=[os.fstat(fd).st_ino for fd in received])
    for line in sys.stdin:
        command=line.strip()
        if command=='acquire':
            try:
                terminal.prove_terminal_for_marker(marker)
                terminal.prove_terminal(anchors['guardian'][0])
                candidate=lock_guard.open_checked(lock_path,lock_identity)
                try:fcntl.flock(candidate,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BaseException:candidate.close();raise
                # All cooperative writers must hold shared lock before socket open.
                # Recheck proof while exclusive fence stays held, then discard old sockets.
                try:
                    terminal.prove_terminal_for_marker(marker)
                    terminal.prove_terminal(anchors['guardian'][0])
                    with lock_guard.open_checked(lock_path,lock_identity):pass
                    for fd in received:os.close(fd)
                    received.clear();exclusive=candidate
                except BaseException:candidate.close();raise
                report(state='EXCLUSIVE',old_sockets_closed=True,production_authority=False)
            except (terminal.Held,lock_guard.Held,BlockingIOError) as error:report(state='HOLD',reason=str(error))
        elif command=='lockcheck':
            try:
                with lock_guard.open_checked(lock_path,lock_identity):pass
                report(state='ORIGINAL_LOCK')
            except lock_guard.Held as error:report(state='HOLD',reason=str(error))
        elif command=='sockets':
            report(state='SOCKETS',inodes=[os.fstat(fd).st_ino for fd in received])
        elif command=='exit':break
        else:raise RuntimeError('BAD_COMMAND')
finally:
    if exclusive is not None:exclusive.close()
    for fd in received:os.close(fd)
    for anchor,channel in anchors.values():anchor.close();channel.close()
    listener.close()
