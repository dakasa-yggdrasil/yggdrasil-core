"""CI-only preflight observation of pending intent, real genid, BPF and Readers.

No authorization, no writes, no replay, no cleanup. Input record provenance,
real rule attachment, four collections, terminal custody and exclusivity are
NOT proved here. This is one read-only building block, never a recovery permit.
"""
import ctypes,hashlib,json,os,socket,stat,time
import drain_marker_v3_DRAFT as marker_v3
import guarded_nl as nl
import guarded_program_identity_DRAFT as program_module
import guarded_sources as sources

class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def _pins(records,reference):
    need(type(reference) is program_module.GuardianProgramReference
         and reference.pid==os.getpid() and not reference.closed,'ORIGINAL_LIVE_REFERENCE_REQUIRED')
    need(type(records) is list and len(records)==2,'EXACT_TWO_PINNED_PROGRAMS_REQUIRED')
    seen_p=set();seen_m=set();rows={}
    for role,record in zip(('inbound','reverse'),records):
        need(type(record) is dict and all(type(record.get(k)) is int and record[k]>0
             for k in ('program_fd','program_id','map_fd','map_id')),'EXACT_PIN_FIELDS_REQUIRED')
        pf,mf=record['program_fd'],record['map_fd']
        pi=nl.ProgInfo();ids=(ctypes.c_uint32*8)();pi.nr_map_ids=8;pi.map_ids=ctypes.addressof(ids)
        nl.info(pf,pi);mi=nl.info(mf,nl.MapInfo())
        own_p=nl.fdinfo(os.getpid(),pf);own_m=nl.fdinfo(os.getpid(),mf)
        need(pi.id==record['program_id'] and pi.type==1 and pi.nr_map_ids==1
             and ids[0]==record['map_id']==mi.id and bytes(pi.tag).hex()==record.get('program_tag')
             and int(own_p['prog_id'])==pi.id and int(own_m['map_id'])==mi.id
             and own_m['frozen'].strip()=='1' and mi.type==1 and mi.key_size==12
             and mi.value_size==8 and mi.map_flags&128,'PINNED_BPF_DESCRIPTOR_IDENTITY')
        reference.verify(pi.id,mi.id)
        seen_p.add(pi.id);seen_m.add(mi.id);actual=nl.map_rows(mi.id)
        need(len(actual)>0 and len(actual)==len(dict(actual)),'EXACT_NONEMPTY_BPF_MAP')
        rows[role]=actual
    need(len(seen_p)==2 and len(seen_m)==2,'DISTINCT_PROGRAM_AND_MAP_IDS')
    return rows

def sample(coordinator,netlink,*,expected_marker,expected_genid,records,reference,cache):
    """Same-process sample; never conflates inventory with attached nft state."""
    need(type(coordinator) is marker_v3.CoordinatorV3,'EXACT_V3_COORDINATOR_REQUIRED')
    need(type(netlink) is socket.socket and netlink.family==socket.AF_NETLINK
         and netlink.getsockopt(socket.SOL_SOCKET,socket.SO_PROTOCOL)==12,'NETFILTER_NETLINK_SOCKET_REQUIRED')
    need(type(expected_genid) is int and 0<expected_genid<2**32,'EXACT_EXPECTED_GENID_REQUIRED')
    need(type(expected_marker) is tuple and len(expected_marker)==3,'EXACT_ANCHORED_MARKER_REQUIRED')
    marker=marker_v3._durable_marker_identity(coordinator)
    need(marker[:3]==expected_marker,'ORIGINAL_MARKER_CHANGED')
    # CI-only identity check for both separate locks and their root directory.
    # It does not acquire a writer lease or prove writer exclusivity.
    with coordinator.base.locked(nonblocking=True):
        record=marker[3];writer=os.lstat(coordinator.writer_lock)
        need(stat.S_ISREG(writer.st_mode) and writer.st_uid==0 and writer.st_nlink==1
             and stat.S_IMODE(writer.st_mode)==0o600
             and record.get('writer_lock_identity')==[writer.st_dev,writer.st_ino]
             and (record.get('lock_dev'),record.get('lock_ino'))==coordinator.base._lock_identity
             and record.get('directory_identity')==list(coordinator.base._directory_identity)
             and record.get('mount_identity')==list(coordinator.base._mount_identity),
             'RECOVERY_LOCK_DIRECTORY_OR_MOUNT_CHANGED')
    need(marker_v3._marker_identity(coordinator)[:3]==expected_marker,'ORIGINAL_MARKER_CHANGED')
    records=json.loads(json.dumps(records))
    before=nl.genid(netlink);need(before==expected_genid,'ORIGINAL_GENID_CHANGED')
    expected=sources.build_expected(cache);rows=_pins(records,reference);now=time.monotonic_ns()
    for role in ('inbound','reverse'):
        actual=dict(rows[role]);wanted=expected[role]
        need(set(actual)==set(wanted) and all(now<expiry<=wanted[k] for k,expiry in actual.items()),
             'PINNED_MAP_DIFFERS_FROM_FRESH_READERS')
    final=sources.build_expected(cache);after=nl.genid(netlink)
    need(after==before and final['invalidation_epoch']==expected['invalidation_epoch']
         and final['source_generation']==expected['source_generation'],'GENID_OR_READER_CHANGED_DURING_SAMPLE')
    for role in ('inbound','reverse'):
        actual=dict(rows[role]);wanted=final[role];now=time.monotonic_ns()
        need(set(actual)==set(wanted) and all(now<expiry<=wanted[k] for k,expiry in actual.items()),
             'MAP_OR_SOURCE_EXPIRED_DURING_SAMPLE')
    need(marker_v3._marker_identity(coordinator)[:3]==marker[:3],'INTENT_CHANGED_DURING_SAMPLE')
    canonical={k:[[key.hex(),expiry] for key,expiry in sorted(v)] for k,v in rows.items()}
    return {'schema':'ci_readonly_recovery_preflight_v1','marker_dev':marker[0],'marker_ino':marker[1],
            'marker_sha256':marker[2],'genid':before,'reader_generation':expected['source_generation'],
            'reader_epoch':expected['invalidation_epoch'],'maps_sha256':hashlib.sha256(nl.canon(canonical)).hexdigest(),
            'fd_custody_checked':True,'fresh_readers_checked':True,'nft_attachment_verified':False,
            'nft_dynamic_collections_verified':False,'sender_terminality_verified':False,
            'exclusive_writer_custody_verified':False,'effect_or_recovery_authority':False}

def sample_attached(coordinator,netlink,*,expected_marker,expected_genid,records,reference,cache,
                    original_pin,receipt,coverage):
    """Join original 50-shape and four nft collections; still no authority.

    Rule wire/FD references and structure are observations, not an independent
    proof of hidden kernel pointer identity or trust/provenance of the receipt.
    """
    import struct
    import transition_structure_DRAFT as transition
    need(type(original_pin) is transition.OriginalPin,'ORIGINAL_47_PIN_REQUIRED')
    need(type(receipt) is dict and receipt.get('after')==expected_genid
         and type(receipt.get('chain')) is int and type(receipt.get('handles')) is list
         and len(receipt['handles'])==2,'ORIGINAL_50_RECEIPT_SHAPE_REQUIRED')
    first=sample(coordinator,netlink,expected_marker=expected_marker,expected_genid=expected_genid,
                 records=records,reference=reference,cache=cache)
    rules=nl.rules(netlink,'admit_deadline')
    need(len(rules)==2,'TWO_OBSERVED_GATE_RULES_REQUIRED')
    for rec,handle,(fields,body) in zip(records,receipt['handles'],rules):
        attrs=dict((k&0x3fff,v) for k,v in fields)
        need(struct.unpack('>Q',attrs[3])[0]==handle
             and struct.pack('<HHi',2,0,rec['program_fd']) in body,'SAME_RULE_HANDLE_AND_FD_REFERENCE')
    raw=nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset')
    transition.verify_guarded(original_pin,raw,observed_chain_handle=receipt['chain'],
                              observed_rule_handles=tuple(receipt['handles']))
    text=nl.cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network')
    maps=_pins(records,reference)
    joined=sources.verify(cache,coverage.kernel_text(text),maps)
    last=sample(coordinator,netlink,expected_marker=expected_marker,expected_genid=expected_genid,
                records=records,reference=reference,cache=cache)
    need(last['reader_epoch']==first['reader_epoch']==joined['invalidation_epoch']
         and last['reader_generation']==first['reader_generation']==joined['source_generation']
         and last['maps_sha256']==first['maps_sha256'] and nl.rules(netlink,'admit_deadline')==rules,
         'RECOVERY_OBSERVATION_CHANGED_DURING_JOIN')
    return {**last,'four_nft_collections_joined':True,'nft_rule_fd_reference_observed':True,
            'kernel_bpf_pointer_proven':False,'receipt_provenance_verified':False,
            'effect_or_recovery_authority':False}
