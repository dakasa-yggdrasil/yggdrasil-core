"""Disposable CI-only deny experiment under retained writer EX; not a permit.

Never invokes this module in production. It creates a *new*, separately journaled
netlink batch with expired maps and empty dynamic collections. Unknown original
and unknown deny ACKs remain unknown; original intent/marker are never removed.
"""
import fcntl,hashlib,json,os,socket,stat,struct
from pathlib import Path
import guarded_nl as nl
import guarded_sources as sources
import recovery_read_DRAFT as recovery
import recovery_terminality_DRAFT as terminal
import transition_structure_DRAFT as transition

class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def run(*,marker_anchor,writer_lock,fence,old_directory,sender_records,expected_genid,
        original_pin,coverage,deny_dir,cache,simulate_ack_loss):
    need(os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),
         'ONLY_DISPOSABLE_NETWORK_NAMESPACE')
    need(type(marker_anchor) is terminal.MarkerAnchor and type(simulate_ack_loss) is bool,
         'ORIGINAL_CUSTODY_REQUIRED')
    lockst=os.fstat(fence.fileno());named=os.lstat(writer_lock)
    need(stat.S_ISREG(lockst.st_mode) and lockst.st_uid==0 and stat.S_IMODE(lockst.st_mode)==0o600
         and (lockst.st_dev,lockst.st_ino)==(named.st_dev,named.st_ino),'ORIGINAL_WRITER_LOCK_REQUIRED')
    fcntl.flock(fence,fcntl.LOCK_EX|fcntl.LOCK_NB)
    import drain_marker_v3_DRAFT as marker_v3
    observed=marker_v3._marker_identity(marker_anchor.coordinator)
    need(observed[:3]==marker_anchor.key
         and observed[3].get('writer_lock_identity')==[lockst.st_dev,lockst.st_ino],
         'SAME_ORIGINAL_MARKER_AND_WRITER_LOCK_REQUIRED')
    old=recovery.inspect_unknown(marker_anchor,old_directory,counter=1,sender_records=sender_records)
    fresh=sources.build_expected(cache)
    recovery._marker_reader_join(observed[3],cache,fresh)
    net=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);net.bind((0,0));net.settimeout(3)
    probe=None;records=[]
    try:
        need(nl.genid(net)==expected_genid,'PRE_DENY_GENID_CHANGED')
        current=nl.rules(net,'admit_deadline');need(len(current)==2,'EXACT_TWO_OLD_GATE_RULES_REQUIRED')
        for role in ('inbound','reverse'):
            records.append(nl.make_program([(('ab' if role=='inbound' else 'cd')*12,1)]))
        seq=201;parts=[]
        for fields,_ in current:
            h=dict((k&0x3fff,v) for k,v in fields)[3]
            parts.append(nl.msg((10<<8)|8,1|4,seq,struct.pack('>BBH',1,0,0)+nl.attr(1,b'dakasa_capacity_network\0')+nl.attr(2,b'admit_deadline\0')+nl.attr(3,h)));seq+=1
        for rec in records:parts.append(nl.xtjump(rec['program_fd'],seq));seq+=1
        for name in ('core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'):
            parts.append(nl.flush(name,seq));seq+=1
        wire=nl.begin(expected_genid,200)+b''.join(parts)+nl.end(seq)
        digest=hashlib.sha256(wire).hexdigest()
        need(digest!=old['wire_sha256'],'DENY_MUST_USE_DISTINCT_WIRE')
        deny_dir=Path(deny_dir);deny_dir.mkdir(mode=0o700)
        nl.durable(deny_dir/'DENY-WIRE.bin',wire)
        nl.durable(deny_dir/'DENY-INTENT.json',nl.canon({'schema':'ci_distinct_deny_after_unknown_v1',
            'genid':expected_genid,'marker_sha256':marker_anchor.key[2],
            'old_unknown_wire_sha256':old['wire_sha256'],'wire_sha256':digest,
            'programs':records,'no_retry':True,'production_authority':False}))
        terminal.prove_terminal_for_marker(marker_anchor)
        current_source=sources.build_expected(cache)
        recovery._marker_reader_join(observed[3],cache,current_source)
        need(current_source['source_generation']==fresh['source_generation']
             and current_source['invalidation_epoch']==fresh['invalidation_epoch'],
             'FRESH_READER_CHANGED_BEFORE_DENY')
        need(nl.genid(net)==expected_genid,'PRE_DISPATCH_GENID_CHANGED')
        need(net.send(wire)==len(wire),'WHOLE_DENY_BATCH_REQUIRED')
        if not simulate_ack_loss:
            pending=set(range(201,seq));acks={}
            while set(acks)!=pending:
                for typ,number,data in nl.packets(net.recv(65536)):
                    need(typ==2 and number in pending and number not in acks and len(data)>=4,'EXACT_DENY_ACK_REQUIRED')
                    acks[number]=struct.unpack_from('<i',data)[0]
            need(all(code==0 for code in acks.values()),'DENY_ACK_ERROR')
        # Independent socket; in ACK-loss mode no read/replay of original wire.
        probe=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,12);probe.bind((0,0));probe.settimeout(3)
        after=nl.genid(probe);need(after==((expected_genid+1)&0xffffffff or 1),'DENY_GENID_NOT_ADVANCED')
        gates=nl.rules(probe,'admit_deadline');need(len(gates)==2,'TWO_DENY_GATES_REQUIRED')
        handles=[]
        for record,(fields,raw) in zip(records,gates):
            handles.append(struct.unpack('>Q',dict((k&0x3fff,v) for k,v in fields)[3])[0])
            need(struct.pack('<HHi',2,0,record['program_fd']) in raw,'DENY_GATE_FD_REFERENCE')
            need(all(deadline==1 for _,deadline in nl.map_rows(record['map_id'])),'ALL_DENY_MAPS_EXPIRED')
        import native_structure
        objects,_=native_structure._objects(nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset'))
        chains=[x['chain']['handle'] for x in objects if 'chain' in x and x['chain']['name']=='admit_deadline']
        need(len(chains)==1,'DENY_CHAIN_REQUIRED')
        transition.verify_guarded(original_pin,nl.cmd('/usr/sbin/nft','-a','-j','list','ruleset'),
                                  observed_chain_handle=chains[0],observed_rule_handles=tuple(handles))
        dynamic=coverage.kernel_text(nl.cmd('/usr/sbin/nft','-a','list','table','inet','dakasa_capacity_network'))
        need(all(not rows for rows in dynamic['dynamic_collections'].values()),'ALL_FOUR_COLLECTIONS_MUST_BE_EMPTY')
        need(nl.genid(probe)==after,'DENY_GENID_CHANGED_DURING_READBACK')
        still=recovery.inspect_unknown(marker_anchor,old_directory,counter=1,sender_records=sender_records)
        final_source=sources.build_expected(cache)
        recovery._marker_reader_join(observed[3],cache,final_source)
        need(final_source['source_generation']==fresh['source_generation']
             and final_source['invalidation_epoch']==fresh['invalidation_epoch'],
             'FRESH_READER_CHANGED_DURING_DENY_OBSERVATION')
        need(still['wire_sha256']==old['wire_sha256'],'ORIGINAL_UNKNOWN_WIRE_CHANGED')
        return {'after_genid':after,'deny_wire_sha256':digest,'old_wire_sha256':old['wire_sha256'],
                'deny_ack_unknown':simulate_ack_loss,'original_ack_unknown':True,
                'marker_retained':True,'fresh_reader_generation':fresh['source_generation'],
                'reader_epoch':fresh['invalidation_epoch'],'production_authority':False}
    finally:
        # If send/ACK/verification fails, no retry is made and both intents stay.
        if probe is not None:probe.close()
        net.close()
        for rec in records:os.close(rec['program_fd']);os.close(rec['map_fd'])
