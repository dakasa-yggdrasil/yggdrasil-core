"""Non-authorizing 50 watch session in an already authenticated CI Guardian."""
import base64,hashlib,importlib.util,json,os,threading,time,types
from pathlib import Path
import ci_reader_fixture,guarded_nl as nl,guarded_sources,guarded_unit_identity as identity
import guarded_verifier,guarded_live_observation,transition_structure_DRAFT as trans
import native_io,native_structure,nft_owner as nft
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
spec=importlib.util.spec_from_file_location('ci_guardian',ROOT/'network_guardian.py');guardian=importlib.util.module_from_spec(spec);spec.loader.exec_module(guardian)
spec=importlib.util.spec_from_file_location('ci_coverage',ROOT/'coverage.py');coverage=importlib.util.module_from_spec(spec);spec.loader.exec_module(coverage)

def endpoints(suffix):
    now=time.monotonic()
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+20,'synthetic') for k,a in
       [('core','10.244.1.'+str(suffix)),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    return entries,[entries[0]],[nft.PrometheusSource('10.244.1.9',now,now+20,'synthetic')]

def read_line(channel):
    data=bytearray()
    while len(data)<=1024*1024:
        ch=channel.recv(1)
        if not ch:raise RuntimeError('fixture controller closed')
        if ch==b'\n':return json.loads(data)
        data.extend(ch)
    raise RuntimeError('bounded fixture message')

def serve(channel):
    verified=None;controller=None
    try:
        channel.settimeout(10);request=read_line(channel)
        controller=identity.authenticate(channel,unit=request['unit'],expected_invocation=request['invocation'],
                      expected_argv=request['argv'],source_sha256=request['source_sha256'])
        assert controller['pid']==request['anchor']['pid'] and controller['start_ticks']==request['anchor']['start_ticks']
        native_io.ROOT=ROOT/'guardian-custody';native_io.ROOT.mkdir(mode=0o700);native_io.configure();native_io.end_initialization()
        cache=ci_reader_fixture.start(endpoints,setup=False)
        original=base64.b64decode(request['anchor']['initial'],validate=True)
        rows,_=native_structure._objects(original)
        native_structure.COMPILED_NATIVE_AST_SHA256=hashlib.sha256(native_structure._structure(rows,keep_handles=False)).hexdigest()
        probe=HERE/'ci_nl_probe.py';probe_sha=hashlib.sha256(probe.read_bytes()).hexdigest()
        verified=guarded_verifier.verify_and_seal(result=request['result'],anchor=request['anchor'],plan=request['plan'],
              receipt_dir=ROOT/'receipts',reader_cache=cache,nl=nl,sources=guarded_sources,transition=trans,
              coverage=coverage,probe_path=probe,probe_sha256=probe_sha)
        guardian.RUNTIME=HERE;guardian.RUNTIME_HASHES['nft_owner.py']=hashlib.sha256((HERE/'nft_owner.py').read_bytes()).hexdigest()
        observer=guardian.Owner.__new__(guardian.Owner)
        observer.C=types.SimpleNamespace(_objects=native_structure._objects,_structure=native_structure._structure,
                        AST47=native_structure.COMPILED_NATIVE_AST_SHA256)
        observer.coverage=coverage;observer.call=lambda name,args:nl.cmd(*args)
        ctx={'verified':verified,'verifier':guarded_verifier,'sources':guarded_sources,'nl':nl,'transition':trans,
             'live':guarded_live_observation,'probe':probe,'probe_sha256':probe_sha}
        channel.sendall(nl.canon({'event':'READY','pid':os.getpid(),'production_authority':False}))
        observer.watch(guarded=ctx,stop=threading.Event(),publish=lambda row:channel.sendall(nl.canon(row)),duration=10)
    finally:
        if verified is not None:verified.close()
        if controller is not None:os.close(controller['pidfd'])
