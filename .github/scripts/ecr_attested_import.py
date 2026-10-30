"""One distinct ECR pull-through import with original process custody.

Runs only in the reviewed GitHub hosted workflow. A failed/uncertain pull is
never retried; later reads do not rewrite that history. Docker's daemon may
continue after a client timeout, which remains UNKNOWN. Login tokens stay in
memory/private temporary Docker config and are never put in receipts.
"""
import base64,hashlib,importlib.util,json,os,pathlib,re,shutil,subprocess,sys,tempfile,time
P=pathlib.Path(__file__).resolve().parent;OUT=pathlib.Path('receipts');REPO='ghcr/dakasa-yggdrasil/yggdrasil-core';ACCOUNT='153828470928';DIGEST='sha256:54aad8a4bec50f447a2b9e3351d5422a6bdd734a3fad5c98dda1b27b5ce74f05';ELF='22c39c565d2dc5d662dc6965a70b4fa84e67fbec9f44bbac669d35a1714fe658';SOURCE='d52465ec5b26014406d2b010dce4fe09e2c169dd';REGISTRY=ACCOUNT+'.dkr.ecr.us-east-1.amazonaws.com';TARGET=REGISTRY+'/'+REPO+'@'+DIGEST
class Held(RuntimeError):pass
def need(v,r):
 if not v:raise Held(r)
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False);source=P/'ecr_frozen_native.py';need(sha(source.read_bytes())=='4326b46957a8df0ef8b940e864df41b68db74a70349b1f9007d731c512c955bc','PINNED_NATIVE_REQUIRED');spec=importlib.util.spec_from_file_location('frozen_native',source);n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
 cli=pathlib.Path(os.environ['R6_AWS_CLI']).resolve(strict=True);docker=pathlib.Path(shutil.which('docker') or '').resolve(strict=True);need(cli.is_file() and docker.is_file(),'EXACT_RUNNER_EXECUTABLES');cli_sha=sha(cli.read_bytes());docker_sha=sha(docker.read_bytes());env=dict(os.environ,AWS_REGION='us-east-1',AWS_DEFAULT_REGION='us-east-1',AWS_MAX_ATTEMPTS='1',AWS_EC2_METADATA_DISABLED='true',AWS_PAGER='',AWS_CLI_AUTO_PROMPT='off')
 summary=json.loads(pathlib.Path('verified-input/summary.json').read_bytes());need(summary.get('source_commit')==SOURCE and summary.get('image')=='ghcr.io/dakasa-yggdrasil/yggdrasil-core@'+DIGEST and summary.get('core_binary_sha256')==ELF and summary.get('four_attestations_verified') is True and summary.get('github_hosted_runner_enforced') is True and summary.get('production_activation') is False,'EXACT_VERIFIED_PRODUCER_SUMMARY')
 def run(label,argv,seconds=40):
  child_env=env if argv[0]==str(cli) else {k:v for k,v in env.items() if not k.startswith('AWS_') and k not in ('GH_TOKEN','GITHUB_TOKEN')}
  raw,facts=n.native(argv,deadline=time.monotonic()+seconds,env=child_env,cap=4*1024*1024);record={'schema':'github_hosted_original_native_return_v1','argv':argv,'stdout_base64':base64.b64encode(raw).decode(),'stdout_sha256':sha(raw),'stdout_bytes':len(raw),'stderr_sha256':facts.get('stderr_sha256'),'stderr_bytes':facts.get('stderr_bytes'),'transport':facts,'production_authority':False};n.once(OUT/(label+'.json'),record);return raw,facts
 def checked(label,argv,seconds=40):
  raw,facts=run(label,argv,seconds);need(all(facts.get(k)is True for k in ('wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_CLOSED_ZERO_REQUIRED');return raw
 def aws(*args):return [str(cli),*args,'--region','us-east-1','--output','json']
 identity=json.loads(checked('STS',aws('sts','get-caller-identity')));need(identity.get('Account')==ACCOUNT and identity.get('Arn','').startswith('arn:aws:sts::'+ACCOUNT+':assumed-role/dakasa-r6-ecr-d524-20261030/'),'ONLY_DEDICATED_ROLE')
 _,pre=run('ABSENCE-BEFORE',aws('ecr','describe-images','--repository-name',REPO,'--image-ids','imageDigest='+DIGEST));need(pre.get('wait_zero') is False and pre.get('error_code')=='ImageNotFoundException','ONLY_ABSENT_NEW_DIGEST')
 need(not os.environ.get('DOCKER_CONFIG'),'NO_INHERITED_DOCKER_CONFIG');temp=pathlib.Path(tempfile.mkdtemp(prefix='r6-ecr-auth-',dir=os.environ['RUNNER_TEMP']));os.chmod(temp,0o700);env['DOCKER_CONFIG']=str(temp)
 try:
  # Credentials are never persisted in receipts or argv, and temp config is removed.
  password=subprocess.run([str(cli),'ecr','get-login-password','--region','us-east-1'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=30);need(password.returncode==0 and 0<len(password.stdout)<4096,'ECR_LOGIN_PASSWORD_HOLD');login=subprocess.run([str(docker),'login','--username','AWS','--password-stdin',REGISTRY],input=password.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={k:v for k,v in env.items() if not k.startswith('AWS_') and k not in ('GH_TOKEN','GITHUB_TOKEN')},timeout=30);need(login.returncode==0,'DOCKER_LOGIN_HOLD');del password,login
  n.once(OUT/'IMPORT-INTENT.json',{'schema':'one_distinct_attested_ecr_import_intent_v1','target':TARGET,'source_commit':SOURCE,'producer_run':41115565265,'verifier_run':41116032126,'expected_elf_sha256':ELF,'aws_cli_sha256':cli_sha,'docker_cli_sha256':docker_sha,'no_retry':True,'production_activation':False})
  raw,facts=run('PULL-ORIGINAL',[str(docker),'pull','--platform','linux/amd64',TARGET],seconds=240);need(all(facts.get(k)is True for k in ('wait_zero','stdout_EOF','stderr_EOF','all_local_FDs_closed','local_child_joined')),'ORIGINAL_PULL_UNCERTAIN_NO_RETRY')
  # Only GET/describe reads may poll eventual visibility; never resend the pull.
  end=time.monotonic()+90;attempt=0
  while time.monotonic()<end:
   attempt+=1;raw,facts=run('DESCRIBE-%03d'%attempt,aws('ecr','describe-images','--repository-name',REPO,'--image-ids','imageDigest='+DIGEST))
   if facts.get('wait_zero'):
    details=json.loads(raw).get('imageDetails',[]);need(len(details)==1 and details[0].get('imageDigest')==DIGEST,'EXACT_ECR_IMAGE');break
   need(facts.get('error_code')=='ImageNotFoundException','READBACK_FAILED_HOLD');time.sleep(2)
  else:raise Held('READBACK_NOT_VISIBLE_HOLD')
  reply=json.loads(checked('MANIFEST',aws('ecr','batch-get-image','--repository-name',REPO,'--image-ids','imageDigest='+DIGEST)));need(reply.get('failures')==[] and len(reply.get('images',[]))==1,'ONE_ECR_MANIFEST');entry=reply['images'][0];manifest=entry['imageManifest'].encode();need(entry.get('registryId')==ACCOUNT and entry.get('repositoryName')==REPO and entry.get('imageId',{}).get('imageDigest')==DIGEST and 'sha256:'+sha(manifest)==DIGEST,'SAME_ECR_MANIFEST_DIGEST');m=json.loads(manifest);layers=[x['digest'] for x in m['layers']];need(0<len(layers)<=100 and len(set(layers))==len(layers),'EXACT_ECR_LAYER_SET')
  available=json.loads(checked('LAYERS',aws('ecr','batch-check-layer-availability','--repository-name',REPO,'--layer-digests',*layers)));need(not available.get('failures') and {x['layerDigest'] for x in available.get('layers',[])}==set(layers) and all(x['layerAvailability']=='AVAILABLE' for x in available['layers']),'ALL_ECR_LAYERS_AVAILABLE')
  inspected=checked('LOCAL-IMAGE',[str(docker),'image','inspect','--format','{{.Os}} {{.Architecture}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}',TARGET]).decode().strip().split();need(inspected==['linux','amd64',SOURCE],'EXACT_LOCAL_IMAGE_CONFIG')
  cid=checked('LOCAL-CREATE',[str(docker),'create','--platform','linux/amd64',TARGET]).decode().strip();need(re.fullmatch('[a-f0-9]{64}',cid) is not None,'EXACT_LOCAL_CONTAINER');binary=temp/'core'
  try:
   checked('LOCAL-COPY',[str(docker),'cp',cid+':/app/yggdrasil-core',str(binary)],seconds=90);need(sha(binary.read_bytes())==ELF,'SAME_ATTESTED_ELF')
  finally:
   removed=subprocess.run([str(docker),'rm','-f',cid],env={k:v for k,v in env.items() if not k.startswith('AWS_') and k not in ('GH_TOKEN','GITHUB_TOKEN')},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30);need(removed.returncode==0,'LOCAL_CONTAINER_CLEANUP_HOLD')
  n.once(OUT/'ECR-RETURN.json',{'schema':'attested_distinct_ecr_readback_v1','source_commit':SOURCE,'image':TARGET,'manifest_sha256':DIGEST,'core_binary_sha256':ELF,'all_layers_available':True,'original_pull_wait_zero_and_eof':True,'actual_docker_pull_count':1,'no_retry':True,'production_activation':False,'release_qualified':False})
 finally:shutil.rmtree(temp)
 print(json.dumps({'status':'DISTINCT_ECR_READBACK_COMPLETE','target':TARGET,'production_authority':False}),flush=True)
if __name__=='__main__':
 try:main()
 except BaseException as e:print('HOLD',type(e).__name__,str(e) if isinstance(e,Held) else '',flush=True);sys.exit(2)
