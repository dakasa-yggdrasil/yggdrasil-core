"""Root-owned throwaway systemd peer used only by Linux CI."""
import array,json,os,socket,sys,time
from pathlib import Path
lock_path=os.environ.get('CI_TERM_WRITER_LOCK')
if lock_path:
    import fcntl
    writer_lock=open(lock_path,'rb');fcntl.flock(writer_lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
runtime=os.environ.get('CI_TERM_RUNTIME')
if runtime:
    import types
    sys.path.insert(0,runtime)
    import drain_marker_v3_DRAFT as v3
    coord=v3.CoordinatorV3(os.environ['CI_TERM_COORD'])
    core=types.SimpleNamespace(native_identity='old/container',address='10.244.1.2',expires=time.monotonic()+60)
    coord.begin(core,[core])
child_path=os.environ.get("CI_TERM_CHILD_PIDFILE")
if child_path:
    child=os.fork()
    if child==0:
        while True:time.sleep(60)
    Path(child_path).write_text(str(child))
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
if os.environ.get('CI_TERM_TRANSFER_BPF')=='1':
    import guarded_nl as nl
    line=bytearray()
    while not line.endswith(b'\n'):
        part=s.recv(1)
        if not part:raise RuntimeError('MISSING_PIN_REQUEST')
        line.extend(part)
    requested=json.loads(line);records=[]
    try:
        for role in ('inbound','reverse'):records.append(nl.make_program(requested[role]))
        raw=(json.dumps(records,sort_keys=True)+'\n').encode()
        fds=array.array('i',[r[key] for r in records for key in ('program_fd','map_fd')])
        if s.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,fds)])!=len(raw):
            raise RuntimeError('INCOMPLETE_BPF_FD_TRANSFER')
        s.recv(1)
    finally:
        for record in records:os.close(record['program_fd']);os.close(record['map_fd'])
else:s.recv(1)
