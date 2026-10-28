"""Pure validator of captured AWS CLI original SEND and terminal GET evidence.

This authenticates transport provenance only to the extent the caller validates
and supplies the originals. Terminal SSM does not prove remote descendants or a
systemd job are gone: those require separate host-side proof before recovery.
"""
import hashlib,json,re
class Held(Exception):pass
def need(v,why):
 if not v:raise Held(why)
def closed(row):
 need(type(row)is dict and type(row.get('exit_code'))is int and row['exit_code']==0 and row.get('captured_output_truncated') is False and all(row.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_CLOSED_ZERO_LOCAL_TRANSPORT')
def qualify(*,request_bytes,send_stdout,get_stdout,send_transport,get_transport,command_id,instance_id,expected_request_sha256):
 closed(send_transport);closed(get_transport)
 need(type(request_bytes)is bytes and hashlib.sha256(request_bytes).hexdigest()==expected_request_sha256,'EXACT_EXECUTED_REQUEST_BYTES')
 need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',command_id) is not None and re.fullmatch(r'i-[0-9a-f]{17}',instance_id) is not None,'EXACT_COMMAND_AND_INSTANCE_IDENTIFIERS')
 request=json.loads(request_bytes);send=json.loads(send_stdout);got=json.loads(get_stdout)
 need(type(request)is dict and request.get('DocumentName')=='AWS-RunShellScript' and request.get('InstanceIds')==[instance_id] and type(request.get('Parameters'))is dict,'EXACT_REQUEST_TARGET')
 c=send['Command'];need(c['CommandId']==command_id and c['InstanceIds']==[instance_id] and c['DocumentName']==request['DocumentName'] and c['Parameters']==request['Parameters'],'SEND_ORIGINAL_REQUEST_JOIN')
 need(got.get('CommandId')==command_id and got.get('InstanceId')==instance_id and got.get('DocumentName')=='AWS-RunShellScript' and got.get('Status') in ('Success','Failed','Cancelled','TimedOut') and type(got.get('ResponseCode'))is int and got.get('ResponseCode')!=-1,'ACTUAL_TERMINAL_INVOCATION')
 return {'schema':'verified_ssm_terminal_transport_only_v1','command_id':command_id,'instance_id':instance_id,'request_sha256':expected_request_sha256,'status':got['Status'],'response_code':got['ResponseCode'],'terminal_does_not_prove_remote_process_or_job_absent':True}
