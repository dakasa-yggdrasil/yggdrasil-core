"""CI-only cooperative systemd writer; never sends netlink messages."""
import array,fcntl,os,socket,sys,time,types
from pathlib import Path
root,role,unit,coord_dir,lock_path,peer_path,stage,lock_identity=sys.argv[1:]
sys.path.insert(0,str(Path(root)/'runtime'))
import drain_marker_v3_DRAFT as v3
import lock_guard
with lock_guard.open_checked(lock_path,lock_identity) as lock:
    try:fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
    except BlockingIOError:
        Path(stage).write_text('BLOCKED_BEFORE_SOCKET');sys.exit(75)
    nl=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12)
    nl.bind((0,0))
    Path(stage).write_text('SOCKET_CREATED')
    if role=='sender':
        coord=v3.CoordinatorV3(coord_dir)
        core=types.SimpleNamespace(native_identity='old/container',address='10.244.1.2',expires=time.monotonic()+60)
        coord.begin(core,[core])
    channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);channel.connect(peer_path)
    channel.sendmsg([b'F'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[nl.fileno()]))])
    if role=='sender':
        child=os.fork()
        if child==0:
            channel.close()
            while True:time.sleep(60)
        Path(root,'child.pid').write_text(str(child))
    channel.recv(1)
