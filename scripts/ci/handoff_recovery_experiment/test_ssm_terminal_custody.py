import base64,copy,hashlib,json,unittest
import ssm_terminal_custody as c
class CustodyTest(unittest.TestCase):
 def setUp(self):
  self.id='12345678-1234-1234-1234-123456789abc';self.i='i-0123456789abcdef0';self.req={'DocumentName':'AWS-RunShellScript','InstanceIds':[self.i],'Parameters':{'commands':['exact command'],'executionTimeout':['285']}};self.raw=json.dumps(self.req).encode();self.s={'Command':{**self.req,'CommandId':self.id}};self.g={'CommandId':self.id,'InstanceId':self.i,'DocumentName':'AWS-RunShellScript','Status':'Failed','ResponseCode':1};self.t={'exit_code':0,'captured_output_truncated':False,**{k:True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')}}
 def diag(self,value):
  b=json.dumps(value).encode();return {'schema':'private_original_baker_SSH_diagnostic_v1','original_local_transport':self.t,'stdout_base64':base64.b64encode(b).decode(),'stdout_sha256':hashlib.sha256(b).hexdigest(),'stdout_bytes':len(b)}
 def call(self,**updates):
  args={'request_bytes':self.raw,'send_diagnostic':self.diag(self.s),'get_diagnostic':self.diag(self.g),'command_id':self.id,'instance_id':self.i,'expected_request_sha256':hashlib.sha256(self.raw).hexdigest()};args.update(updates);return c.qualify(**args)
 def test_terminal_failure_is_not_success_nor_process_proof(self):
  v=self.call();self.assertEqual(v['status'],'Failed');self.assertTrue(v['terminal_does_not_prove_remote_process_or_job_absent'])
 def test_unknown_running_or_response_unknown_rejected(self):
  for status,response in [('InProgress',-1),('TimedOut',-1)]:
   g={**self.g,'Status':status,'ResponseCode':response}
   with self.assertRaises(c.Held):self.call(get_diagnostic=self.diag(g))
 def test_wrong_target_request_and_unclosed_transport_rejected(self):
  d=self.diag(self.g);d['original_local_transport']={**self.t,'stdout_EOF':False}
  for args in ({'instance_id':'i-11111111111111111'},{'expected_request_sha256':'0'*64},{'get_diagnostic':d}):
   with self.assertRaises(c.Held):self.call(**args)
 def test_original_request_parameters_must_match_send(self):
  s=copy.deepcopy(self.s);s['Command']['Parameters']['commands']=['other']
  with self.assertRaises(c.Held):self.call(send_diagnostic=self.diag(s))
 def test_diagnostic_tamper_rejected(self):
  d=self.diag(self.g);d['stdout_base64']=base64.b64encode(b'{}').decode()
  with self.assertRaises(c.Held):self.call(get_diagnostic=d)
if __name__=='__main__':unittest.main(verbosity=2)
