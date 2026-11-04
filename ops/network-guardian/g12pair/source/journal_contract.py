"""Pure original journal cursor contracts, extracted Source-only.

R13 successor: closing_journal folds coverage.kernel_change_cut exactly like
coverage.journal, and resumes the prefix reducer from its explicit open state.
"""
import copy,hashlib,json,math,re

def require(ok,guard):
    if not ok:raise RuntimeError(guard)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def journal_row(row,pid,invocation,boot):
    require(type(row)is dict and row.get('_PID')==str(pid)
        and row.get('_SYSTEMD_INVOCATION_ID')==invocation and row.get('_BOOT_ID')==boot,
        'SAME_ORIGINAL_JOURNAL_PID_INVOCATION_AND_BOOT')
    cursor=row.get('__CURSOR');stamp=row.get('__MONOTONIC_TIMESTAMP')
    require(type(cursor)is str and re.fullmatch('[a-z0-9;=]{1,4096}',cursor)
        and type(stamp)is str and stamp.isdecimal() and len(stamp)<=32,
        'BOUNDED_ORIGINAL_JOURNAL_CURSOR_AND_CLOCK')
    require(row.get('MESSAGE')is not None,'ORIGINAL_JOURNAL_FULL_MESSAGE_REQUIRED_USE_ALL')
    return cursor,int(stamp)

def journal_anchor(raw,pid,invocation,boot,now):
    require(type(raw)is bytes and 0<len(raw)<=64<<20 and type(boot)is str
        and re.fullmatch('[a-f0-9]{32}',boot) and type(now)in(int,float)and math.isfinite(now),
        'WHOLE_ORIGINAL_JOURNAL_PREFIX_AND_BOOT')
    cursor,stamp=journal_row(json.loads(raw.splitlines()[-1]),pid,invocation,boot)
    require(stamp/1000000<=now,'NO_FUTURE_ORIGINAL_JOURNAL_CURSOR')
    return {'cursor':cursor,'monotonic_microseconds':stamp,'observed_monotonic':now,
        'full_original_bytes':len(raw),'full_original_sha256':sha(raw)}

def closing_journal(prefix,raw,pid,invocation,boot,anchor,now,coverage):
    """Fold one complete after-cursor suffix with the unchanged _window rules.

    The complete prefix was already audited by coverage.journal. Its last
    active reducer state is retained even when its guarantee aged out while
    parsing: a later return then creates the same real gap as a full replay.
    Atomic replacements may shorten, never union, the old guarantee.
    """
    require(type(raw)is bytes and len(raw)<=64<<20 and coverage.number(now)
        and anchor['observed_monotonic']<=now
        and prefix['schema']=='root_conservative_original_R11_all_batch_coverage_v1'
        and type(prefix['all_original_batches'])is int and 1<=prefix['all_original_batches']<=32768,
        'ONE_BOUNDED_ORIGINAL_CLOSING_JOURNAL_SUFFIX')
    count=prefix['all_original_batches'];latest=prefix['latest_original_batch']
    require(latest['commit_sequence']==count,'PREFIX_ORIGINAL_BATCH_CENSUS_AND_LAST_COMMIT')
    segments=[[x['start'],x['guaranteed_until']]for x in prefix['all_segments']]
    gaps=copy.deepcopy(prefix['all_gaps']);current=None
    # R13: a kernel-change cut after the latest batch closes the reducer even
    # when that batch was eligible; the prefix states its own end state.
    require(type(prefix['reducer_open_after_last_row'])is bool and(not prefix['reducer_open_after_last_row']or coverage._window(latest)[3]),
        'EXPLICIT_PREFIX_REDUCER_END_STATE')
    if prefix['reducer_open_after_last_row']:
        require(segments and segments[-1][1]==coverage._window(latest)[2],
            'EXACT_PREFIX_LAST_ATOMIC_GUARANTEE')
        current=segments.pop()
    seen={anchor['cursor']};last_stamp=anchor['monotonic_microseconds'];rows=0;added=0
    for line in raw.splitlines():
        row=json.loads(line);cursor,stamp=journal_row(row,pid,invocation,boot)
        require(cursor not in seen and last_stamp<=stamp and stamp/1000000<=now,
            'EXACT_AFTER_CURSOR_NO_DUPLICATE_BACKWARD_OR_FUTURE_ROW')
        seen.add(cursor);last_stamp=stamp;rows+=1
        message=row['MESSAGE']
        if not isinstance(message,str)or not message.startswith('{'):continue
        body=json.loads(message)
        require(body.get('schema')!='capacity_owned_nft_original_read_adoption_v1','NO_SECOND_READ_ADOPTION_IN_ORIGINAL_HOT_SUFFIX')
        cut=coverage.kernel_change_cut(body)
        if cut is not None:
            if current is not None:
                current[1]=min(current[1],cut);segments.append(current);current=None
            gaps.append({'sequence':count,'reason':'KNOWN_NETLINK_KERNEL_CHANGE_OUTSIDE_COMMITTED_BATCH','at':cut})
        if body.get('schema')!='capacity_owned_nft_native_batch_v3':continue
        require(count<32768 and body.get('commit_sequence')==count+1
            and body['phase']=='only_dynamic_elements'
            and body['render_started']>=latest['native_apply_returned'],
            'ALL_ORIGINAL_SUFFIX_BATCHES_CONTIGUOUS_SINGLE_COMMITTER')
        start,returned,lower,eligible=coverage._window(body)
        require(returned<=now,'NO_FUTURE_ORIGINAL_BATCH')
        count+=1;added+=1;latest=body
        if not eligible:
            if current is not None:
                current[1]=min(current[1],start);segments.append(current);current=None
            gaps.append({'sequence':count,'reason':'ORIGINAL_BATCH_NOT_FULLY_ELIGIBLE',
                'render_started':start,'native_returned':returned})
        elif current is None:current=[returned,lower]
        elif current[1]<returned:
            gaps.append({'sequence':count,'reason':'CONSERVATIVE_EXPIRY_BEFORE_NEXT_ORIGINAL_RETURN',
                'from':current[1],'to':returned});segments.append(current);current=[returned,lower]
        else:current[1]=lower
    if current is not None:segments.append(current)
    measured=[{'start':s,'guaranteed_until':e,'observed_until':min(e,now),
        'observed_seconds':max(0,min(e,now)-s)}for s,e in segments]
    active=measured[-1]if current is not None and current[1]>now else None
    result={'schema':prefix['schema'],'all_original_batches':count,'all_segments':measured,
        'all_gaps':gaps,'current_continuous_window':active,
        'qualified_15_seconds':active is not None and active['observed_seconds']>=15,
        **{k:prefix[k]for k in ('initial_structure_proof_kind','initial_original_echo_handles','initial_original_read_handles','initial_original_structure_handles','original_read_adoption')},
        'compiled_native_ast_sha256':prefix['compiled_native_ast_sha256'],
        'latest_original_batch':latest,'reducer_open_after_last_row':current is not None,
        'not_a_packet_delivery_or_Guest_authority_proof':True}
    return result,{'prefix_original_batches':prefix['all_original_batches'],
        'suffix_original_batches':added,'suffix_rows':rows,'suffix_bytes':len(raw),
        'suffix_sha256':sha(raw),'original_anchor':anchor,
        'exactly_one_suffix_no_retry_wait_or_new_epoch':True}
