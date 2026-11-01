"""Bounded independent systemd Guardian precommit for a private CI netns."""
import hashlib,os,socket,sys,threading
from pathlib import Path
import guarded_guardian47_ci as precommit,guarded_unit_identity as identity,guarded_nl as nl
import native_structure as structure,nft_owner as nft,transition_structure_DRAFT as trans

root=Path(__file__).resolve().parent
import drain_marker_v3_DRAFT as marker,guarded_generation as generation
generation.CI_DRAIN_COORDINATION=marker.CoordinatorV3(root.parent/'drain-coordinator')
path=Path(sys.argv[1]);server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(str(path));server.listen(2);server.settimeout(15);channel=None;peer=None;watch_channel=None;worker=None;closing=threading.Event();errors=[]
try:
    channel,_=server.accept()
    unit=os.environ['CI_CONTROLLER_UNIT'];props=identity._properties(unit);pid=int(props['MainPID'])
    argv=Path('/proc/%d/cmdline'%pid).read_bytes().rstrip(b'\0').decode().split('\0')
    source=Path(argv[2]);source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
    peer=identity.authenticate(channel,unit=unit,expected_invocation=props['InvocationID'],expected_argv=argv,source_sha256=source_sha)
    raw=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset');rows,_=structure._objects(raw)
    structure.COMPILED_NATIVE_AST_SHA256=hashlib.sha256(structure._structure(rows,keep_handles=False)).hexdigest()
    probe=root/'ci_nl_probe.py'
    def run_precommit():
        try:precommit.serve(channel,preparer_identity=peer,sender_argv=argv,source_sha256=source_sha,
              probe_path=str(probe),probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
              identity=identity,nl=nl,structure=structure,transition=trans,nft=nft,host_netns=os.environ['CI_HOST_NETNS'])
        except BaseException as error:
            if not closing.is_set():errors.append(error)
    worker=threading.Thread(target=run_precommit);worker.start()
    watch_channel,_=server.accept()
    import ci_guardian50_session
    ci_guardian50_session.serve(watch_channel,server)
finally:
    closing.set()
    if watch_channel is not None:watch_channel.close()
    if channel is not None:
        try:channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
    if worker is not None:worker.join(5)
    if peer is not None:os.close(peer['pidfd'])
    if channel is not None:channel.close()
    server.close();path.unlink(missing_ok=True)
    if errors:raise RuntimeError('Guardian precommit session failed') from errors[0]
