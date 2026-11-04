"""Pure-history cache. Every consumed byte is rehashed before cached use.

No native operation, clock extension or current observation is implemented here.
The full owning Core qualifier supplies its already-qualified network context once; later uses recheck every
original copy, source copy and index byte that those qualifiers consumed.
"""
import re,types
from pathlib import Path

def qualify(owner,g):
 R=g.require
 if hasattr(owner,'_qualified_historical_cache'):
  c=owner._qualified_historical_cache
  for path,pin,extent in c['files']:
   b=g.read(path,64<<20,0o600);R(len(b)==extent and g.sha(b)==pin,'ALL_CONSUMED_ORIGINAL_SOURCE_BYTES_REHASHED_BEFORE_CACHE_USE')
  R(g.sha(g.wire(c['anchor']))==c['anchor_sha256']and g.sha(g.wire(c['core']))==c['core_sha256'],'UNCHANGED_FULLY_QUALIFIED_TYPED_HISTORICAL_CACHE');return c['anchor']
 ref=owner.config['proof_index_ref'];raw=g.read(ref['path'],2<<20,0o600);R(g.sha(raw)==ref['sha256'],'EXACT_PUBLIC_PROOF_INDEX_SHA');v=g.loads(raw)
 R(type(v)is dict and set(v)=={'schema','reference_copies'}and v['schema']=='Root_Core262_R43_guardian_explicit_public_proof_index_v1'and type(v['reference_copies'])is list and 1<=len(v['reference_copies'])<=4096,'BOUNDED_CLOSED_WHOLE_ORIGINAL_PROOF_INDEX')
 rows={};paths={};used=set();pins={ref['path']:(ref['sha256'],len(raw))}
 for row in v['reference_copies']:
  R(type(row)is dict and set(row)=={'original_ref','copy_ref','bytes'},'EXACT_ORIGINAL_WHOLE_COPY_ROW');original,copy=row['original_ref'],row['copy_ref'];g.exact_ref(original);g.exact_ref(copy);key=g.wire(original)
  R(key not in rows and original['path']not in paths and 'PRIVATE'not in original['path'].upper() and copy['path']==str(g.HERE/('PROOF-'+original['sha256']+'.PUBLIC'))and copy['sha256']==original['sha256']and type(row['bytes'])is int and 0<=row['bytes']<=64<<20,'UNIQUE_HASH_ADDRESSED_PUBLIC_COPY_INCLUDING_EMPTY_FILES');rows[key]=row;paths[original['path']]=original
 def original(r):
  g.exact_ref(r);key=g.wire(r);R(key in rows,'ONLY_EXPLICIT_REVIEWED_WHOLE_ORIGINAL_BYTES');row=rows[key];copy=row['copy_ref'];body=g.read(copy['path'],64<<20,0o600);R(len(body)==row['bytes']and g.sha(body)==r['sha256'],'ORIGINAL_FULL_HASH_EXTENT_AND_EMPTY_EOF');used.add(key);pins[copy['path']]=(copy['sha256'],row['bytes']);return body
 def owned(path):R(str(path)in paths,'ONLY_EXPLICIT_ORIGINAL_PUBLIC_PATH');return original(paths[str(path)])
 def closed(f):R(type(f.get('exit_code'))is int and f['exit_code']==0 and f.get('captured_output_truncated')is False and all(f.get(k)is True for k in('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ACTUAL_ORIGINAL_FULL_ZERO_IO_JOIN')
 p=types.SimpleNamespace(require=R,sha=g.sha,loads=g.loads,raw=original,owned=owned,closed=closed)
 get=lambda r:g.loads(original(r))
 sources=owner.config['context_sources'];R(type(sources)is dict and set(sources)=={'network_anchor_source_ref','network_qualification_source_ref','Core_context_source_ref','Root_factual_Source_review_ref'},'EXPLICIT_REVIEWED_OWNING_CONTEXT_SOURCES')
 for r in sources.values():g.exact_ref(r)
 review=get(sources['Root_factual_Source_review_ref']);R(type(review)is dict and set(review)=={'schema','network_anchor_source_ref','network_qualification_source_ref','Core_context_source_ref','expected_Core_source','expected_generation','expected_schema','Root_review'}and review['schema']=='Root_Core262_R43_Guardian_owning_context_Source_review_v1'and all(review[k]==sources[k]for k in('network_anchor_source_ref','network_qualification_source_ref','Core_context_source_ref'))and review['expected_Core_source']=='2de33bbca46000d86a6dc0d5162383a6128e3517'and review['expected_generation']==262 and review['expected_schema']==81 and type(review['Root_review'])is str and 120<=len(review['Root_review'])<=8192,'EXACT_ROOT_FACTUAL_REVIEW_OF_FULL_OWNING_QUALIFIERS')
 def source(r):
  m=types.ModuleType('Core262_guardian_owning_'+Path(r['path']).stem);m.__file__=r['path'];exec(compile(original(r),m.__file__,'exec'),m.__dict__);return m
 proofs=owner.config['R43_proofs'];core=source(sources['Core_context_source_ref']).qualify(p,get(owner.config['Core262_context_ref']));original(sources['network_qualification_source_ref']);anchor=core['network_R43_qualified_context']
 R(core['schema']=='verified_Core262_original600_context_v1'and core['Core_source']==review['expected_Core_source']and core['actual_deployment_generation']==262 and core['schema_version']==81 and core['Core_firstReady600_qualified']is True and core['same_native_identity']['restart_count']==0 and core['network_R43_return_ref']==proofs['return_ref']and core['network_R43_caller_ref']==proofs['original_SSM_caller_ref']and core['network_R43_execution_proofs']=={k:proofs[k]for k in('request_ref','recipe_ref','stage_caller_refs')}and core['network_R43_anchor_source_ref']==sources['network_anchor_source_ref']and core['network_R43_qualification_source_ref']==sources['network_qualification_source_ref'],'GENUINE_CORE262_OWN600_SAME_REVIEWED_R43_ORIGINALS')
 R(anchor['schema']=='verified_R43_same13_pair_handoff_network_anchor_v1'and all(anchor[k]is True for k in('own_original_new120_and_whole_zero_qualified','strict_current15_original_qualified','same_original47_handles_preserved','all_four_backends_and_eight_bridge_MSS_qualified'))and anchor['Core262_roll_or_original600_qualified']is False and anchor['historical_qualification_only_no_current_or_new_boot_claim']is True and anchor['approved_core_pairs'][1]['image']==get(core['release_artifact_ref'])['image'],'GENUINE_SEPARATE_NETWORK120_AND_CORE262600_DOMAINS')
 R(used==set(rows),'ALL_AND_ONLY_CONSUMED_PUBLIC_ORIGINAL_AND_SOURCE_BYTES');R(sum(size for _,size in pins.values())<=256<<20,'BOUNDED_TOTAL_CONSUMED_HISTORICAL_PROOF_BYTES');owner.Core262_context=core;owner.proof_original=original
 owner._qualified_historical_cache={'anchor':anchor,'anchor_sha256':g.sha(g.wire(anchor)),'core':core,'core_sha256':g.sha(g.wire(core)),'files':[(path,pin,size)for path,(pin,size)in sorted(pins.items())]};return anchor
