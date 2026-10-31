"""Real Linux/netns systemd marker + BPF + Readers; no recovery authority."""
import os,socket,subprocess,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'runtime'))
import ci_reader_fixture,drain_marker_v3_DRAFT as marker,guarded_nl as nl
import guarded_program_identity_DRAFT as program,guarded_sources as sources,native_io,nft_owner as nft,recovery_read_DRAFT as recovery

def endpoints(_):
    now=time.monotonic()
    entries=[nft.Backend(k,a,nft.PORTS[k],now,now+20,'synthetic') for k,a in
             [('core','10.244.1.4'),('broker','172.18.1.2'),('rds','172.18.1.3'),('redis','172.18.1.4')]]
    return entries,[entries[0]],[nft.PrometheusSource('10.244.1.9',now,now+20,'synthetic')]

def refuse(fn,reason):
    try:fn()
    except Exception as error:
        if reason not in str(error):raise
    else:raise AssertionError('MUST_HOLD '+reason)

native_io.ROOT=HERE/'recovery-read-native-custody';native_io.ROOT.mkdir(mode=0o700)
native_io.configure();native_io.end_initialization()
cache=ci_reader_fixture.start(endpoints);coord=marker.CoordinatorV3(HERE/'recovery-read-marker');coord.initialize_for_ci()
core=endpoints(4)[1][0];lease=coord.acquire_writer_lease();coord.begin(core,[core],writer_lease=lease);marker_key=marker._durable_marker_identity(coord)[:3]
subprocess.run(['/usr/sbin/nft','add','table','ip','ci_read_observe'],check=True,timeout=5)
sock=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);sock.bind((0,0));sock.settimeout(4)
genid=nl.genid(sock);ref=program.GuardianProgramReference();records=[]
try:
    wanted=sources.build_expected(cache)
    for role in ('inbound','reverse'):
        records.append(nl.make_program([(key.hex(),expiry) for key,expiry in wanted[role].items()]))
    def sample(**kwargs):
        return recovery.sample(coord,sock,expected_marker=kwargs.get('expected_marker',marker_key),
            expected_genid=kwargs.get('genid',genid),records=kwargs.get('records',records),reference=ref,cache=cache)
    result=sample()
    assert result['fd_custody_checked'] and result['fresh_readers_checked'] and not any(result[x] for x in
        ('nft_attachment_verified','nft_dynamic_collections_verified','sender_terminality_verified',
         'exclusive_writer_custody_verified','effect_or_recovery_authority'))
    print('PASS real marker, frozen BPF descriptors/maps, genid and fresh synthetic DNS/route witnesses',flush=True)
    bad=[dict(x) for x in records];bad[0]['program_id']+=1
    refuse(lambda:sample(records=bad),'PINNED_BPF_DESCRIPTOR_IDENTITY')
    duplicate=[dict(records[0]),dict(records[0])]
    refuse(lambda:sample(records=duplicate),'DISTINCT_PROGRAM_AND_MAP_IDS')
    print('PASS wrong pinned BPF identity and duplicate map/program rejected',flush=True)
    with coord.marker.open('ab') as f:f.write(b' ')
    refuse(sample,'ORIGINAL_MARKER_CHANGED')
    with coord.marker.open('rb+') as f:f.seek(-1,os.SEEK_END);f.truncate()
    assert marker._durable_marker_identity(coord)[:3]==marker_key
    subprocess.run(['/usr/sbin/nft','add','table','ip','ci_external_genid_change'],check=True,timeout=5)
    refuse(sample,'ORIGINAL_GENID_CHANGED')
    genid=nl.genid(sock)
    cache.dns_failed('rds','CI_FAILURE')
    refuse(sample,'ORIGINAL_DNS_ROUTE_WITNESS_REQUIRED')
    print('PASS marker mutation, real external genid change and Reader failure rejected',flush=True)
    print('BOUNDARY no rule attachment, four nft collections, exclusive custody or recovery authority',flush=True)
finally:
    for r in records:os.close(r['program_fd']);os.close(r['map_fd'])
    ref.close();sock.close();lease.close()
