import hashlib,json,types,unittest
import guardian_own_first15_contract as c
class Tests(unittest.TestCase):
 def setUp(self):
  self.boot='7d6b3ec1-139d-4089-bac1-4621cbff83d0';self.inv='a'*32;self.root='/var/lib/dakasa-capacity-network-recovery/'+self.boot+'-GUARDIAN-'+self.inv+'-FIRST-CURRENT15';self.identity={'pid':19};self.bodies={};self.rows=[];self.calls=[];self.hash=lambda raw:hashlib.sha256(raw).hexdigest();self.f={'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
  for i,role in enumerate(('current15-exact-finite512-tail','current15-one-after-cursor-closing','native-dynamic-expiries')):
   raw=role.encode();path=self.root+'-READ-'+str(i);ref={'path':path,'sha256':self.hash(raw)};self.bodies[path]=raw;self.rows.append({'original_call_index':i,'output_ref':ref,'sha256':ref['sha256'],'bytes':len(raw),'role':role,'argv':['read',role]});self.calls.append({'role':role,'argv':['read',role],'stdout_sha256':ref['sha256'],'stdout_bytes':len(raw),'original_transport':dict(self.f)})
  self.v={'schema':'Root_owning_finite512_current15_readonly_observation_v1','source_sha256':'b'*64,'standing_config_sha256':'c'*64,'identity':self.identity,'original_public_read_output_refs':self.rows,'original_native_calls':self.calls,'prefix_observed_monotonic':1,'finished_monotonic':20,'measurement':{'qualified_15_seconds':True},'kernel':{'all_four_backends_and_reverse_sources_positive':True}}
  self.tail=types.SimpleNamespace(measure=lambda *_:{'qualified_15_seconds':True});self.coverage=types.SimpleNamespace(kernel_text=lambda _:{'all_four_backends_and_reverse_sources_positive':True});self.p=types.SimpleNamespace(raw=lambda ref:self.bodies[ref['path']],loads=json.loads,sha=self.hash)
 def call(self,**changes):
  raw=json.dumps(self.v).encode();path=self.root+'-RETURN.PUBLIC.json';self.bodies[path]=raw;args={'p':self.p,'ref':{'path':path,'sha256':self.hash(raw)},'boot_id':self.boot,'guardian_invocation':self.inv,'guardian_source_sha256':'b'*64,'authority_sha256':'c'*64,'controller_identity':self.identity,'guardian_start_monotonic':2,'tail':self.tail,'coverage':self.coverage,'journal':object()};args.update(changes);return c.qualify(**args)
 def test_first15_is_historical_not_live_now(self):
  v=self.call();self.assertTrue(v['first15_rederived']);self.assertTrue(v['historical_only']);self.assertFalse(v['fresh_current15_or_original120_inferred'])
 def test_wrong_invocation_or_controller_rejected(self):
  for args in ({'guardian_invocation':'d'*32},{'controller_identity':{'pid':20}},{'guardian_start_monotonic':21}):
   with self.assertRaises(c.Held):self.call(**args)
 def test_original_call_and_kernel_must_be_derived(self):
  self.calls[0]['original_transport']['stdout_EOF']=False
  with self.assertRaises(c.Held):self.call()
  self.calls[0]['original_transport']['stdout_EOF']=True;self.v['kernel']['all_four_backends_and_reverse_sources_positive']=False
  with self.assertRaises(c.Held):self.call()
if __name__=='__main__':unittest.main(verbosity=2)
