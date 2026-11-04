"""Owning readonly finite current15 observation. No new epoch or effect."""
import json,time

def initializer(owner,g,identity):
 """Select historical initializer provenance, never cached current health."""
 if owner.boot==g.INITIAL_BOOT:
  # Preserve the initial-boot contract exactly: the immutable R43 initializer
  # must still match native handles. No new read can relabel its old handles.
  ref=owner.Core262_context['network_R43_return_ref'];historic=g.loads(owner.proof_original(ref))
  return historic['new120_return']['measurement'],{'schema':'Root_current15_initializer_provenance_v1','kind':'same_initial_boot_R43_original','original_ref':ref,'current_health_or_new_epoch_authority':False}
 proof=owner.original_qualification_measurement(identity)
 g.require(proof is not None and proof['identity']==identity,'CURRENT_LIFETIME_AUTHENTICATED_ORIGINAL_INITIALIZER_REQUIRED')
 # The exact current lifetime's source/standing-authorized full120 original
 # was recomputed from fixed prefix/closing refs. Fresh current15 still comes
 # exclusively from the new bounded tail, kernel read and closing suffix.
 return proof['measurement'],{k:v for k,v in proof.items()if k!='measurement'}

def observe(owner,g,*,before_kernel=None):
 R=g.require;R(getattr(owner,'current_read_capture',None)is None,'ONE_NONNESTED_CURRENT_READ_CAPTURE');owner.current_read_capture=[]
 try:
  # The original first120 measurement contributes only its immutable exact47
  # handle identity. Fresh current15 comes exclusively from this finite tail.
  identity=owner.identity();seal=owner.static();original47,initializer_ref=initializer(owner,g,identity);wg=owner.wg_snapshot(seal);transport=owner.transport();owner.journal_identity=identity;argv=owner.journal_argv(identity);prefix=owner.call('current15-exact-finite512-tail',argv+['--lines=512'],cap=8<<20,seconds=8);prefix_observed=time.monotonic();lines=prefix.splitlines();R(1<=len(lines)<=512,'FINITE512_FULL_NATIVE_TAIL');cursor,_=owner.journal_contract.journal_row(g.loads(lines[-1]),identity['pid'],identity['InvocationID'],owner.boot.replace('-',''))
  if before_kernel is not None:before_kernel()
  R(owner.identity()==identity and owner.wg_snapshot(seal)==wg,'SAME_LIFETIME_AND_WG_BEFORE_FRESH_KERNEL');kernel,observed=owner.kernel(original47);suffix=owner.call('current15-one-after-cursor-closing',argv+['--after-cursor='+cursor],cap=8<<20,seconds=8);R(owner.identity()==identity,'SAME_CONTROLLER_AT_CURRENT_CLOSURE');finished=time.monotonic();measurement=g.tail.measure(prefix,suffix,identity,owner.boot,prefix_observed,finished,owner.coverage,owner.journal_contract);current=measurement['current_continuous_window'];R(finished<owner.deadline and measurement['all_requested_rows_accounted_for']is True and measurement['qualified_15_seconds']is True and current is not None and current['start']<=observed<=current['observed_until']<=finished<current['guaranteed_until']and kernel['all_four_backends_and_reverse_sources_positive']is True,'FINITE_ORIGINAL_CURRENT15_SAME47_WG8_AND_FRESH_KERNEL')
  return{'schema':'Root_owning_finite512_current15_readonly_observation_v1','identity':identity,'initializer47_provenance':initializer_ref,'WG_public_shape':wg,'transport':transport,'kernel':kernel,'kernel_observed':observed,'prefix_observed_monotonic':prefix_observed,'finished_monotonic':finished,'measurement':measurement,'full_lifetime_unobserved_continuity_or_new120_qualified':False,'service_kernel_Controller_Hub_Core_or_Guest_mutations':0},prefix,suffix,list(owner.current_read_capture)
 finally:owner.current_read_capture=None

def persist(owner,g,observed,prefix,suffix,reads,key):
 R=g.require;R(type(key)is str and 1<=len(key)<=180 and all(c.isalnum()or c in'-_'for c in key),'FINITE_OWNING_READ_ARTIFACT_KEY');rows=[]
 for index,row in enumerate(reads):
  body=row['body'];path=g.LEDGER/(key+'-READ-%03d.PUBLIC'%index);g.once(path,body);rows.append({k:v for k,v in row.items()if k!='body'}|{'output_ref':{'path':str(path),'sha256':g.sha(body)}})
 prefix_rows=[row for row in rows if row['role']=='current15-exact-finite512-tail'];suffix_rows=[row for row in rows if row['role']=='current15-one-after-cursor-closing'];R(len(prefix_rows)==len(suffix_rows)==1 and prefix_rows[0]['sha256']==g.sha(prefix)and suffix_rows[0]['sha256']==g.sha(suffix),'EXACT_RETAINED_TAIL_AND_CLOSING_READS');value={**observed,'source_sha256':owner.sha,'standing_config_sha256':g.sha(owner.raw_config),'prefix_ref':prefix_rows[0]['output_ref'],'suffix_ref':suffix_rows[0]['output_ref'],'original_public_read_output_refs':rows,'original_native_calls':owner.calls};path=g.LEDGER/(key+'-RETURN.PUBLIC.json');g.once(path,g.wire(value));return{'path':str(path),'sha256':g.sha(g.wire(value))}
