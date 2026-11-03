"""Pure current15 from every row of one finite tail and one closing suffix.

Uses the owning coverage._window and, for R13, coverage.kernel_change_cut:
a KNOWN netlink kernel change outside a committed batch record ends any open
window. No lifetime continuity, new120, packet delivery, Guest business or
native capacity authority is inferred.
"""
import json,math
def require(v,g):
 if not v:raise RuntimeError(g)
def measure(prefix,suffix,identity,boot,prefix_observed,finished,coverage,journal):
 require(type(prefix)is bytes and type(suffix)is bytes and 0<len(prefix)<=8<<20 and len(suffix)<=8<<20 and all(type(v)in(int,float)and math.isfinite(v)for v in(prefix_observed,finished))and 0<=prefix_observed<=finished,'ONE_BOUNDED_CURRENT_TAIL_AND_ONE_CLOSING_SUFFIX');first=prefix.splitlines();last=suffix.splitlines();require(1<=len(first)<=512 and len(last)<=1024,'ALL_AND_ONLY_FINITE512_TAIL_AND_BOUNDED_CLOSING_ROWS');seen=set();stamp=0;sequence=None;initial_sequence=None;latest=None;current=None;gaps=[];batches=0;other=0;prefix_cursor=None;schema_counts={}
 for group,rows,limit in(('tail',first,prefix_observed),('closing',last,finished)):
  for line in rows:
   value=json.loads(line);cursor,at=journal.journal_row(value,identity['pid'],identity['InvocationID'],boot.replace('-',''));require(cursor not in seen and stamp<=at and at/1000000<=limit,'EXACT_SAME_LIFETIME_ALL_ROWS_FORWARD_NO_CURSOR_SKIP_OR_REPLAY');seen.add(cursor);stamp=at
   if group=='tail':prefix_cursor=cursor
   message=value['MESSAGE']
   if not isinstance(message,str)or not message.startswith('{'):other+=1;continue
   body=json.loads(message);require(type(body)is dict,'ORIGINAL_JOURNAL_MESSAGE_OBJECT');schema=body.get('schema');require(schema is None or type(schema)is str and len(schema)<=160,'BOUNDED_OBSERVED_SCHEMA_NAME');schema_counts[str(schema)]=schema_counts.get(str(schema),0)+1;require(len(schema_counts)<=128,'BOUNDED_ALL_OTHER_ORIGINAL_ROWS_ACCOUNTED');cut=coverage.kernel_change_cut(body)
   if cut is not None:
    if current is not None:current[1]=min(current[1],cut)
    current=None;gaps.append({'sequence':sequence,'reason':'KNOWN_NETLINK_KERNEL_CHANGE_OUTSIDE_COMMITTED_BATCH','at':cut})
   if schema!='capacity_owned_nft_native_batch_v3':other+=1;continue
   seq=body.get('commit_sequence');require(type(seq)is int and 1<=seq<2**63 and(sequence is None or seq==sequence+1),'EVERY_ORIGINAL_BATCH_IN_REQUESTED_TAIL_AND_SUFFIX_CONTIGUOUS');require(latest is None or body['render_started']>=latest['native_apply_returned'],'ONE_ORIGINAL_NORMAL_COMMITTER_FORWARD_ORDER');require(latest is None or body['phase']=='only_dynamic_elements','NO_LATER_STATIC_RESET_WITHIN_OBSERVED_TAIL');start,returned,lower,eligible=coverage._window(body);require(returned<=limit,'NO_FUTURE_ORIGINAL_JOINED_BATCH');initial_sequence=seq if initial_sequence is None else initial_sequence;sequence=seq;latest=body;batches+=1
   if not eligible:
    if current is not None:current[1]=min(current[1],start)
    current=None;gaps.append({'sequence':seq,'reason':'ORIGINAL_BATCH_NOT_FULLY_ELIGIBLE','render_started':start,'native_returned':returned})
   elif current is None:current=[returned,lower]
   elif current[1]<returned:gaps.append({'sequence':seq,'reason':'CONSERVATIVE_EXPIRY_BEFORE_NEXT_ORIGINAL_RETURN','from':current[1],'to':returned});current=[returned,lower]
   else:current[1]=lower
 require(batches>0 and sequence-initial_sequence+1==batches,'COMPLETE_CONSECUTIVE_OBSERVED_BATCH_CENSUS');window=None
 if current is not None and current[1]>finished:window={'start':current[0],'guaranteed_until':current[1],'observed_until':finished,'observed_seconds':max(0,finished-current[0])}
 return{'schema':'Root_current15_exact_finite_original_tail_and_one_suffix_v1','requested_tail_maximum_rows':512,'tail_rows':len(first),'closing_rows':len(last),'all_requested_rows_accounted_for':len(first)+len(last)==batches+other,'observed_original_batch_count':batches,'first_observed_commit_sequence':initial_sequence,'last_observed_commit_sequence':sequence,'other_original_rows':other,'observed_schema_counts':schema_counts,'prefix_last_cursor':prefix_cursor,'prefix_observed_monotonic':prefix_observed,'finished_monotonic':finished,'current_continuous_window':window,'qualified_15_seconds':window is not None and window['observed_seconds']>=15,'gaps_within_observed_rows':gaps,'full_lifetime_or_unobserved_continuity_qualified':False,'historical_original120_or_Guest_business_capacity_authority':False}
