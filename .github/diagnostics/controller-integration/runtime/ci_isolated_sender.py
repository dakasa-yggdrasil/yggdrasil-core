"""Disposable CI systemd sender, staging only; does not grant cancellation."""
import array,hashlib,json,os,socket,sys,time,types
from pathlib import Path
import drain_marker_v3_DRAFT as marker,guarded_generation as generation,guarded_nl as nl
import native_structure,transition_structure_DRAFT as transition

root=Path(sys.argv[1]);channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
channel.connect(str(root/'sender.sock'))
coord=marker.CoordinatorV3(root/'coord');generation.CI_DRAIN_COORDINATION=coord
receipts=root/'sender-receipts';receipts.mkdir(mode=0o700)
raw=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset')
objects,_=native_structure._objects(raw)
native_structure.COMPILED_NATIVE_AST_SHA256=hashlib.sha256(native_structure._structure(objects,keep_handles=False)).hexdigest()
emitter=generation.GenerationEmitter(initial_raw=raw,transition=transition,receipt_dir=receipts,host_netns=os.environ['CI_HOST_NETNS'])
core=types.SimpleNamespace(native_identity='old/container',address='10.244.1.2',expires=time.monotonic()+60)
intent=coord.begin(core,[core],writer_lease=emitter.writer_lease)
records=[nl.make_program([('0b'*12,time.monotonic_ns()+20_000_000_000)]),nl.make_program([('0c'*12,time.monotonic_ns()+20_000_000_000)])]
# The child inherits the writer lease and socket: death of the leader alone
# must never establish exclusive recovery.
child=os.fork()
if child==0:
    while True:time.sleep(60)
(root/'sender-child.pid').write_text(str(child))
msg=(json.dumps({'records':records},sort_keys=True)+'\n').encode()
fds=array.array('i',[r[k] for r in records for k in ('program_fd','map_fd')])
if channel.sendmsg([msg],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,fds)])!=len(msg):raise RuntimeError('FD_TRANSFER_FAILED')
# This fixture does not consume a Guardian permit and does not invoke submit.
# Kill makes inherited writer custody and terminality observable independently.
channel.recv(1)
raise RuntimeError('UNEXPECTED_SENDER_RESUME')
