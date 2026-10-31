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
    intent=coord.begin(core,[core])
child_path=os.environ.get("CI_TERM_CHILD_PIDFILE")
if child_path:
    child=os.fork()
    if child==0:
        while True:time.sleep(60)
    Path(child_path).write_text(str(child))
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
if os.environ.get('CI_TERM_TRANSFER_BPF')=='1':
    import hashlib
    import guarded_nl as nl,guarded_generation as generation,native_structure,transition_structure_DRAFT as transition
    line=bytearray()
    while not line.endswith(b'\n'):
        part=s.recv(1)
        if not part:raise RuntimeError('MISSING_PIN_REQUEST')
        line.extend(part)
    requested=json.loads(line);records=[]
    try:
        for role in ('inbound','reverse'):records.append(nl.make_program(requested['maps'][role]))
        initial=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset')
        objects,_=native_structure._objects(initial)
        native_structure.COMPILED_NATIVE_AST_SHA256=hashlib.sha256(native_structure._structure(objects,keep_handles=False)).hexdigest()
        receipts=Path(os.environ['CI_TERM_RECEIPTS']);receipts.mkdir(mode=0o700)
        emitter=generation.GenerationEmitter(initial_raw=initial,transition=transition,receipt_dir=receipts,
                    host_netns=os.environ['CI_HOST_NETNS'])
        receipt=emitter.submit(requested,records,drain_permit=coord.barrier(intent,core,[core]))
        raw=(json.dumps({'records':records,'receipt':receipt},sort_keys=True)+'\n').encode()
        fds=array.array('i',[r[key] for r in records for key in ('program_fd','map_fd')])
        if s.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,fds)])!=len(raw):
            raise RuntimeError('INCOMPLETE_BPF_FD_TRANSFER')
        s.recv(1)
    finally:
        for record in records:os.close(record['program_fd']);os.close(record['map_fd'])
else:s.recv(1)
