"""Pure conservative coverage of ALL original joined R11 batches, never samples only.

R13 successor: a hot batch may carry the typed in-process netlink record
capacity_netlink_hot_batch_v1, and a KNOWN netlink outcome that changed the
kernel is logged as a discard record without a commit sequence. Both are read
here; neither ever extends a window.
"""
import json
import math

class Held(Exception):pass
def require(ok,code):
    if not ok:raise Held(code)
def number(value):return type(value)in(int,float)and math.isfinite(value)
# R13 sends the batch inside sendmsg right after send_start; the kernel stamps
# each element's expiry from tick-granular jiffies, so a match can end up to
# about one tick before send_start+timeout. Same bound as the R13 controller's
# KERNEL_TIMEOUT_ROUNDING_MARGIN_SECONDS (HZ>=100; the Brain runs HZ 1000).
NETLINK_KERNEL_TICK_MARGIN=.010
def _netlink(body):
    """None for an R11/R12 batch; else the earliest EARLIER committed attempt (or None)."""
    facts=body.get('original_native_command_facts')
    if type(facts)is not dict or facts.get('schema')!='capacity_netlink_hot_batch_v1':return None
    attempts=facts.get('attempts')
    require(facts.get('role')=='hot_dynamic_apply'and facts.get('committed')is True and facts.get('late')is False
        and facts.get('closed_before_original_deadline_zero')is True and type(facts.get('fenced'))is bool
        and facts.get('equivalent_text_sha256')==body.get('nft_source_sha256')
        and type(attempts)is list and 1<=len(attempts)<=6 and body.get('netlink_attempts')==attempts,'R13_ONE_COMMITTED_NOT_LATE_NETLINK_BATCH_RECORD')
    for item in attempts:
        require(type(item)is dict and type(item.get('committed'))is bool and type(item.get('late'))is bool and type(item.get('fenced'))is bool
            and number(item.get('send_start'))and number(item.get('send_returned'))and item['send_start']<=item['send_returned'],'R13_CLOSED_NETLINK_ATTEMPT_FACTS')
    require(all(a['send_returned']<=b['send_start']for a,b in zip(attempts,attempts[1:])),'R13_ORDERED_NETLINK_ATTEMPTS')
    last=attempts[-1]
    require(last['committed']is True and last['late']is False and last['fenced']is facts['fenced']
        and last['send_start']==body['render_started']and last['send_returned']==body['native_apply_returned'],'R13_RECORD_CLOCKS_ARE_THE_FINAL_COMMITTED_ATTEMPT')
    earlier=[a['send_start']for a in attempts[:-1]if a['committed']]
    return {'earlier_commit_started':min(earlier)if earlier else None}
def kernel_change_cut(body):
    """R13: start of a KNOWN kernel replacement that no committed batch record describes, else None.

    A discard record whose known netlink outcome changed the kernel, or an
    earlier (late) committed attempt inside one batch, replaced the four sets
    outside the reduced batch sequence. Any open window ends there: conservative,
    never a union or extension.
    """
    schema=body.get('schema')
    if schema=='capacity_owned_nft_refresh_discarded_before_send_v1':
        started,known=body.get('native_apply_started'),body.get('known_netlink_outcome')
        require(type(started)is bool and number(body.get('render_started'))and(known is None or type(known)is dict),'CLOSED_ORIGINAL_DISCARD_RECORD')
        if started is False:
            require(known is None,'NO_NETLINK_OUTCOME_WITHOUT_SEND');return None
        require(type(known.get('kernel_changed'))is bool,'CLOSED_KNOWN_NETLINK_OUTCOME')
        return body['render_started']if known['kernel_changed']else None
    if schema=='capacity_owned_nft_native_batch_v3':
        netlink=_netlink(body)
        return None if netlink is None else netlink['earlier_commit_started']
    return None
def _window(body):
    require(body['schema']=='capacity_owned_nft_native_batch_v3'and body['applied']is True and body['Core_or_VM_authority']is False,'ORIGINAL_R11_BATCH_ONLY')
    start,end,budget=body['render_started'],body['native_apply_returned'],body['proposed_native_budget_seconds']
    if body['phase']=='initial_static_no_dynamic':
        require(number(start)and number(end)and type(budget)is float and budget==5.0 and 0<=end-start<budget,'ORIGINAL_STATIC_EMPTY_BUDGET')
        require(body.get('static_dynamic_collections_empty')is True and body['backend_freshness']=={} and body['core_source_freshness']==[] and body['prometheus_source_freshness']==[] and body['backends_admitted']==0 and body['prometheus_sources_admitted']==0,'STATIC_BATCH_NEVER_CONTRIBUTES_DYNAMIC_AUTHORITY')
        return start,end,start,False
    require(number(start)and number(end)and type(budget)is float and budget==.25 and 0<=end-start<budget,'ORIGINAL_JOIN_WITHIN_RENDER_BUDGET')
    require(body['phase']=='only_dynamic_elements','CLOSED_BATCH_PHASE')
    backends=body['backend_freshness'];require(type(backends)is dict and set(backends)<=set(('core','broker','rds','redis')),'CLOSED_FOUR_NATIVE_BACKENDS')
    source=body['core_source_freshness'];prom=body['prometheus_source_freshness']
    require(type(source)is list and len(source)<=8 and type(prom)is list and len(prom)<=1,'CLOSED_REVERSE_SOURCE_CENSUS')
    eligible=set(backends)==set(('core','broker','rds','redis'))and len(source)>=1 and len(prom)==1 and body['held_native_read_classes']=={} and body['backends_admitted']==4 and body['prometheus_sources_admitted']==1
    timeouts=[]
    for item in(*backends.values(),*source,*prom):
        issued,expiry,timeout=item['original_started'],item['original_expires'],item['kernel_timeout_ms']
        require(number(issued)and number(expiry)and 0<expiry-issued<=30 and issued<=start and type(timeout)is int and timeout>=0,'ORIGINAL_LOCAL_EXPIRY_AND_KERNEL_TIMEOUT')
        require(timeout==max(0,math.floor(1000*(expiry-start-budget))),'EXACT_FLOORED_TIMEOUT_NO_EXPIRY_EXTENSION')
        timeouts.append(timeout)
    lower=start+min(timeouts,default=0)/1000
    if _netlink(body)is not None:lower-=NETLINK_KERNEL_TICK_MARGIN
    return start,end,lower,eligible and lower>end

def _initial_proof(adoption,batches):
    if adoption is not None:
        return {'initial_structure_proof_kind':'original_owned_read_adoption',
            'initial_original_echo_handles':None,'initial_original_read_handles':adoption['original_native_read_handles'],
            'initial_original_structure_handles':adoption['original_native_read_handles'],
            'compiled_native_ast_sha256':adoption['compiled_native_ast_sha256'],
            'original_read_adoption':adoption}
    first=batches[0]if batches else None
    handles=None if first is None else first['original_native_echo_handles']
    return {'initial_structure_proof_kind':None if first is None else'original_native_apply_echo',
        'initial_original_echo_handles':handles,'initial_original_read_handles':None,
        'initial_original_structure_handles':handles,
        'compiled_native_ast_sha256':None if first is None else first['compiled_native_ast_sha256'],
        'original_read_adoption':None}

def _adoption(body):
    require(body.get('schema')=='capacity_owned_nft_original_read_adoption_v1' and body.get('phase')=='existing_exact_47_read_adoption'
        and body.get('initial_structure_proof_kind')=='original_owned_read_adoption'
        and body.get('commit_sequence')==0 and body.get('applied')is False and body.get('native_mutations')==0
        and body.get('Core_or_VM_authority')is False and body.get('capacity_or_Core_freshness_credit')is False
        and body.get('original_native_echo_handles')is None,'HONEST_READ_ADOPTION_ZERO_MUTATIONS_ZERO_COVERAGE')
    start,end=body['read_started'],body['read_returned'];require(number(start)and number(end)and 0<=start<=end,'ORIGINAL_ADOPTION_READ_CLOCKS')
    handles=body['original_native_read_handles']
    require(type(handles)is list and len(handles)==47 and all(type(x)is dict and set(x)=={'key','handle'}and type(x['key'])is list and type(x['handle'])is int and x['handle']>0 for x in handles)
        and len({tuple(x['key'])for x in handles})==47 and sum(x['key'][0]=='rule'for x in handles)==33,'ACTUAL_READ_47_HANDLES_NO_INVENTED_ECHO')
    require(body['compiled_native_ast_sha256']=='5f985c480924eaa7dea9930307a4efaf503c2fdc342455b72763a512f707f8ba','SOURCE_COMPILED_47_READ_ADOPTION_AST')
    reads=body['original_native_reads'];require(type(reads)is list and len(reads)==2,'TWO_ORIGINAL_FULL_NATIVE_READS')
    for read in(*reads,body['original_native_text_read']):
        facts=read['native_facts'];require(type(read['bytes'])is int and 0<read['bytes']<=8<<20 and type(read['sha256'])is str and len(read['sha256'])==64
            and facts['closed_before_original_deadline_zero']is True and facts['stdout_sha256']==read['sha256']and facts['stdout_bytes']==read['bytes'],'ORIGINAL_JOINED_NATIVE_ADOPTION_READ_FACTS')
    return start,end

def journal(raw,pid,invocation,now,*,minimum_original_batches=0):
    require(type(raw)is bytes and len(raw)<=64*1024**2 and number(now),'BOUNDED_ORIGINAL_JOURNAL')
    batches=[];adoption=None;events=[]
    for line in raw.splitlines():
        row=json.loads(line)
        if row.get('_PID')!=str(pid)or row.get('_SYSTEMD_INVOCATION_ID')!=invocation:continue
        require(row.get('MESSAGE')is not None,'ORIGINAL_JOURNAL_FULL_MESSAGE_REQUIRED_USE_ALL')
        message=row.get('MESSAGE')
        if not isinstance(message,str)or not message.startswith('{'):continue
        body=json.loads(message)
        if body.get('schema')=='capacity_owned_nft_original_read_adoption_v1':
            require(adoption is None and not batches,'ONE_ORIGINAL_READ_ADOPTION_BEFORE_ANY_HOT_COMMIT')
            _adoption(body);require(body['read_returned']<=now,'NO_FUTURE_ORIGINAL_ADOPTION');adoption=body;continue
        cut=kernel_change_cut(body)
        if cut is not None:
            require(len(events)<65536,'BOUNDED_KERNEL_CHANGE_EVENTS');events.append(('cut',cut,len(batches)))
        if body.get('schema')!='capacity_owned_nft_native_batch_v3':continue
        require(len(batches)<32768 and body.get('commit_sequence')==len(batches)+1,'ALL_ORIGINAL_BATCHES_FROM_INITIAL_COMMIT_NO_SKIPS')
        require((body['phase']=='initial_static_no_dynamic')==(not batches and adoption is None),'ONE_COLD_ECHO_OR_READ_ADOPTION_THEN_ONLY_HOT')
        if batches:require(body['render_started']>=batches[-1]['native_apply_returned'],'ORIGINAL_SINGLE_COMMITTER_CAUSAL_ORDER')
        elif adoption is not None:require(body['render_started']>=adoption['read_returned'],'HOT_NORMAL_AFTER_ORIGINAL_READ_ADOPTION')
        _window(body);batches.append(body);events.append(('batch',body,None))
    require(type(minimum_original_batches)is int and minimum_original_batches>=0 and len(batches)>=minimum_original_batches,'NO_LOST_ORIGINAL_BATCH_HISTORY_AFTER_FIRST_COMMIT')
    initial=_initial_proof(adoption,batches)
    if not batches:
        return {'schema':'root_conservative_original_R11_all_batch_coverage_v1','all_original_batches':0,'all_segments':[],'all_gaps':[],'current_continuous_window':None,'qualified_15_seconds':False,**initial,'latest_original_batch':None,'reducer_open_after_last_row':False,'not_a_packet_delivery_or_Guest_authority_proof':True}
    segments,gaps,current=[],[],None
    for kind,body,at in events:
        if kind=='cut':
            if current is not None:
                current[1]=min(current[1],body);segments.append(current);current=None
            gaps.append({'sequence':at,'reason':'KNOWN_NETLINK_KERNEL_CHANGE_OUTSIDE_COMMITTED_BATCH','at':body})
            continue
        start,returned,lower,eligible=_window(body)
        require(returned<=now,'NO_FUTURE_ORIGINAL_BATCH')
        if not eligible:
            if current is not None:
                current[1]=min(current[1],start);segments.append(current);current=None
            gaps.append({'sequence':body['commit_sequence'],'reason':'ORIGINAL_BATCH_NOT_FULLY_ELIGIBLE','render_started':start,'native_returned':returned})
            continue
        if current is None:current=[returned,lower]
        elif current[1]<returned:
            gaps.append({'sequence':body['commit_sequence'],'reason':'CONSERVATIVE_EXPIRY_BEFORE_NEXT_ORIGINAL_RETURN','from':current[1],'to':returned});segments.append(current);current=[returned,lower]
        else:
            # The next atomic replacement can shorten the prior timeout. Do
            # NOT union an obsolete longer expiry after its set was replaced.
            current[1]=lower
    if current is not None:segments.append(current)
    measured=[{'start':s,'guaranteed_until':e,'observed_until':min(e,now),'observed_seconds':max(0,min(e,now)-s)}for s,e in segments]
    active=measured[-1]if current is not None and current[1]>now else None
    return {'schema':'root_conservative_original_R11_all_batch_coverage_v1','all_original_batches':len(batches),'all_segments':measured,'all_gaps':gaps,'current_continuous_window':active,'qualified_15_seconds':active is not None and active['observed_seconds']>=15,**initial,'latest_original_batch':batches[-1],'reducer_open_after_last_row':current is not None,'not_a_packet_delivery_or_Guest_authority_proof':True}

def _duration(text):
    import re
    parts=re.findall(r'([0-9]+)(ms|[dhms])',text)
    require(parts and ''.join(n+u for n,u in parts)==text and len({u for _,u in parts})==len(parts),'EXACT_NATIVE_TEXT_DURATION')
    value=sum(int(n)*{'d':86400000,'h':3600000,'m':60000,'s':1000,'ms':1}[u]for n,u in parts)
    require(0<=value<=30000,'BOUNDED_NATIVE_TEXT_REMAINDER');return value

def kernel_text(raw):
    import ipaddress,re
    require(type(raw)is bytes and 0<len(raw)<=262144,'BOUNDED_ORIGINAL_NATIVE_TABLE_TEXT')
    text=raw.decode('ascii');require(text.startswith('table inet dakasa_capacity_network { # handle '),'SAME_NATIVE_TABLE_TEXT_HEADER')
    found={}
    for kind,name,body in re.findall(r'^\t(set|map) ([a-z_0-9]+) \{[^\n]*\n(.*?)^\t\}',text,re.M|re.S):
        if name not in('core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'):continue
        require(name not in found,'ONE_ORIGINAL_DYNAMIC_COLLECTION')
        elements=re.findall(r'elements = \{ ([^{}]*) \}',body)
        require(len(elements)<=1,'CLOSED_NATIVE_COLLECTION_ELEMENTS')
        rows=[]
        for value in elements[0].split(',')if elements else []:
            value=' '.join(value.split());m=re.fullmatch(r'(.+) timeout ([0-9a-z]+) expires ([0-9a-z]+)(?: : (.+))?',value)
            require(m is not None,'COMPLETE_NATIVE_TIMEOUT_AND_EXPIRY_TEXT')
            timeout,expires=_duration(m[2]),_duration(m[3]);require(expires<=timeout,'NATIVE_EXPIRY_NO_TIMEOUT_EXTENSION')
            rows.append({'value':m[1],'target':m[4],'timeout_ms':timeout,'expires_ms':expires})
        found[name]=rows
    require(set(found)=={'core_ready4','prometheus_ready4','backend_forward4','backend_dnat4'},'ALL_FOUR_DYNAMIC_COLLECTIONS_EXIST')
    cores,prom=found['core_ready4'],found['prometheus_ready4'];forward=found['backend_forward4'];dnat=found['backend_dnat4']
    require(len(cores)<=8 and len(prom)<=1 and len(forward)<=4 and len(dnat)<=4,'BOUNDED_NATIVE_DYNAMIC_COUNTS')
    for item in cores+prom:
        require(item['target']is None and ipaddress.IPv4Address(item['value'])in ipaddress.IPv4Network('10.42.0.0/16'),'SEPARATE_NATIVE_CORE_PROM_SOURCE_RANGE')
    require(not prom or prom[0]['value']not in{v['value']for v in cores},'SEPARATE_NATIVE_CORE_PROM_ROLES')
    expected={('10.200.24.1','9443'):('core','9443'),('10.200.24.1','5671'):('broker','32674'),('10.200.24.2','5432'):('rds','5432'),('10.200.24.3','6379'):('redis','6379')}
    kinds={};forward_values=set()
    for item in dnat:
        key=tuple(item['value'].split(' . '));target=tuple((item['target']or'').split(' . '))
        require(key in expected and len(target)==2,'ONLY_FOUR_FIXED_NATIVE_VIPS')
        role,port=expected[key];require(role not in kinds and target[1]==port and ipaddress.IPv4Address(target[0])in ipaddress.IPv4Network('10.42.0.0/16'if role=='core'else'10.43.0.0/16'),'FIXED_NATIVE_BACKEND_ROLE_AND_PORT')
        if role=='core':require(target[0]in{v['value']for v in cores},'NATIVE_CORE_REVERSE_AND_FORWARD_JOIN')
        kinds[role]=item;forward_values.add(' . '.join(key+target))
    require(all(v['target']is None for v in forward)and len({v['value']for v in forward})==len(forward)and {v['value']for v in forward}==forward_values,'SAME_NATIVE_FORWARD_AND_DNAT_TUPLES')
    positive=set(kinds)=={'core','broker','rds','redis'}and len(cores)>=1 and len(prom)==1 and all(v['expires_ms']>0 for rows in found.values()for v in rows)
    return {'schema':'root_original_R11_native_kernel_ms_snapshot_v1','all_four_backends_and_reverse_sources_positive':positive,'dynamic_collections':found,'minimum_actual_expires_ms':min((v['expires_ms']for rows in found.values()for v in rows),default=0)}
