"""Validate original closed AWS CLI diagnostics for one terminal SSM command.

Evidence must be obtained through a source-pinned trusted native caller and its
original diagnostic files, not caller-synthesized records. Terminal SSM does not
prove remote descendants or a systemd job are gone; inspect them independently.
"""
import base64,hashlib,json,re
class Held(Exception):pass
def need(v,why):
 if not v:raise Held(why)
def stdout(row):
 need(type(row)is dict and row.get('schema')=='private_original_baker_SSH_diagnostic_v1','ORIGINAL_NATIVE_DIAGNOSTIC')
 t=row['original_local_transport'];need(type(t)is dict and type(t.get('pid'))is int and t['pid']>1 and type(t.get('exit_code'))is int and t['exit_code']==0 and t.get('captured_output_truncated') is False and all(t.get(k)is True for k in ('native_started','wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_CLOSED_ZERO_LOCAL_TRANSPORT')
 try:raw=base64.b64decode(row['stdout_base64'],validate=True)
 except (ValueError,TypeError):raise Held('ORIGINAL_DIAGNOSTIC_BASE64')
 need(len(raw)==row['stdout_bytes'] and hashlib.sha256(raw).hexdigest()==row['stdout_sha256'],'DIAGNOSTIC_STDOUT_BYTES_AND_SHA');return raw
def qualify(*,request_bytes,send_diagnostic,get_diagnostic,command_id,instance_id,expected_request_sha256):
 send_stdout=stdout(send_diagnostic);get_stdout=stdout(get_diagnostic)
 need(type(request_bytes)is bytes and hashlib.sha256(request_bytes).hexdigest()==expected_request_sha256,'EXACT_EXECUTED_REQUEST_BYTES')
 need(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',command_id) is not None and re.fullmatch(r'i-[0-9a-f]{17}',instance_id) is not None,'EXACT_COMMAND_AND_INSTANCE_IDENTIFIERS')
 request=json.loads(request_bytes);send=json.loads(send_stdout);got=json.loads(get_stdout)
 need(type(request)is dict and request.get('DocumentName')=='AWS-RunShellScript' and request.get('InstanceIds')==[instance_id] and type(request.get('Parameters'))is dict,'EXACT_REQUEST_TARGET')
 c=send['Command'];need(c['CommandId']==command_id and c['InstanceIds']==[instance_id] and c['DocumentName']==request['DocumentName'] and c['Parameters']==request['Parameters'],'SEND_ORIGINAL_REQUEST_JOIN')
 need(got.get('CommandId')==command_id and got.get('InstanceId')==instance_id and got.get('DocumentName')=='AWS-RunShellScript' and got.get('Status') in ('Success','Failed','Cancelled','TimedOut') and type(got.get('ResponseCode'))is int and got.get('ResponseCode')!=-1,'ACTUAL_TERMINAL_INVOCATION')
 return {'schema':'verified_ssm_terminal_transport_only_v1','command_id':command_id,'instance_id':instance_id,'request_sha256':expected_request_sha256,'status':got['Status'],'response_code':got['ResponseCode'],'terminal_does_not_prove_remote_process_or_job_absent':True}
