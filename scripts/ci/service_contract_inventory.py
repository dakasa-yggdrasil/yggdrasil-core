"""Deterministic source census; parses Go tokens, never executes product source."""
from pathlib import Path
import argparse,hashlib,json,re
TOK=re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z0-9_]*|\d+|[^\s]')
def tokens(text):return [(m.group(),m.start(),m.end()) for m in TOK.finditer(text) if not m.group().startswith(('//','/*'))]
def endcall(ts,start):
 depth=0
 for i in range(start,len(ts)):
  if ts[i][0]=='(':depth+=1
  elif ts[i][0]==')':
   depth-=1
   if not depth:return i
 raise ValueError('unclosed call')
PRODUCTION_COMMANDS=('goose','bootstrap','bootstrap-admin')
EXCLUDED_PARTS=('vendor','.git','superpowers','functional_tests','third_party')
def source_path(rel):
 parts=Path(rel).parts
 if not rel.endswith('.go') or rel.endswith('_test.go') or any(x in EXCLUDED_PARTS for x in parts):return False
 if 'scripts' in parts:return len(parts)>=3 and parts[0]=='scripts' and parts[1] in PRODUCTION_COMMANDS
 return True
def generate(root):
 sources={};routes=[];events=[];egress=[];consumers=[];constants=[];schema=[];auth=[];intercepts=[];sdk=[];commands=[]
 for p in sorted(root.rglob('*.go')):
  rel=p.relative_to(root).as_posix()
  if not source_path(rel):continue
  if p.is_symlink():raise ValueError('source symlink refused: '+rel)
  text=p.read_text();ts=tokens(text);sha=hashlib.sha256(p.read_bytes()).hexdigest();tag=re.search(r'^//go:build (.*)$',text,re.M);tag=tag.group(1) if tag else 'default'
  sources[rel]={'sha256':sha,'build_constraint':tag,'bytes':len(p.read_bytes())}
  functions=[];declarations=set()
  for k,(word,pos,_) in enumerate(ts):
   if word!='func' or k+1>=len(ts):continue
   j=k+1
   if ts[j][0]=='(':
    j=endcall(ts,j)+1
   if j<len(ts) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',ts[j][0]):
    functions.append((pos,ts[j][0]));declarations.add(ts[j][1])
  def ref(pos):
   fn=next((f for s,f in reversed(functions) if s<=pos),'package')
   return {'file':rel,'line':text.count('\n',0,pos)+1,'function':fn,'build_constraint':tag}
  for i,(value,start,finish) in enumerate(ts):
   if rel.startswith(tuple('scripts/'+name+'/' for name in PRODUCTION_COMMANDS)) and i>=2 and ts[i-1][0]=='.' and i+1<len(ts) and ts[i+1][0]=='(' and value in ('Open','LoadConfig','Ping','Up','Down','Status','SetDialect','DiscoverFiles','LoadDocument','NormalizeDocument','ValidateDocument','ResolveManifest','CreateManifestVersion','GetCollaboratorByPrimaryEmail','BeginTx','AddCollaboratorToTeamBySlugTx','Commit','Rollback','WriteFile'):
    stop=endcall(ts,i+1);args=text[ts[i+1][2]:ts[stop][1]]
    commands.append(dict(ref(start),command=rel.split('/')[1],callee=ts[i-2][0]+'.'+value,argument_expression=args,argument_expression_sha256=hashlib.sha256(args.encode()).hexdigest()))
   if value=='case' and rel in ('controllers/httpapi/capacity_guest.go','controllers/httpapi/capacity_mutations.go','controllers/httpapi/capacity_host_original_factory.go','controllers/httpapi/capacity_canary_authority.go'):
    j=i+1;depth=0
    while j<len(ts):
     if ts[j][0] in ('(', '['):depth+=1
     elif ts[j][0] in (')', ']'):depth-=1
     elif ts[j][0]==':' and depth==0:break
     j+=1
    if j<len(ts):intercepts.append(dict(ref(start),predicate=text[finish:ts[j][1]].strip()))
   if value in ('CreateBucket','PutBucketCors','VerifyEmailIdentity','CreateTopic','GetTopicAttributes') and i>0 and ts[i-1][0]=='.' and i+1<len(ts) and ts[i+1][0]=='(':sdk.append(dict(ref(start),operation=value))
   if value in ('Handle','HandleFunc') and i>0 and ts[i-1][0]=='.' and i+1<len(ts) and ts[i+1][0]=='(':
    stop=endcall(ts,i+1);args=text[ts[i+1][2]:ts[stop][1]].strip();route=args.split(',',1)[0].strip();handler=args.split(',',1)[1].strip() if ',' in args else ''
    routes.append(dict(ref(start),registration=value,pattern_expression=route,handler_expression=handler))
   if value in ('EmitEvent','EmitEventWithOutcome','PublishEvent') and i+1<len(ts) and ts[i+1][0]=='(' and start not in declarations:
    stop=endcall(ts,i+1);excerpt=text[ts[i+1][2]:ts[stop][1]];types=re.findall(r'\bType\s*:\s*([^,\n}]+)',excerpt)
    events.append(dict(ref(start),callee=value,type_expressions=types,argument_expression_sha256=hashlib.sha256(excerpt.encode()).hexdigest()))
   if value in ('NewRequest','NewRequestWithContext','Get','Post','Do','Request') and i>0 and ts[i-1][0]=='.' and i+1<len(ts) and ts[i+1][0]=='(':
    receiver=ts[i-2][0] if i>=2 else '';stop=endcall(ts,i+1);args=text[ts[i+1][2]:ts[stop][1]]
    if start not in declarations and (value in ('NewRequest','NewRequestWithContext') or (value in ('Get','Post') and receiver=='http') or (value in ('Do','Request') and re.search(r'client|transport|http|Client|Transport|^c$',receiver))):
     egress.append(dict(ref(start),callee=receiver+'.'+value,argument_expression=args[:450],expression_complete=len(args)<=450,argument_sha256=hashlib.sha256(args.encode()).hexdigest()))
   if value=='Queue' and i+1<len(ts) and ts[i+1][0]==':' and rel.startswith('controllers/message/'):
    tail=''.join(x[0] for x in ts[i+2:i+6]).split(',')[0];consumers.append(dict(ref(start),endpoint_expression=tail))
  for m in re.finditer(r'^\s*(EventType\w+|queue\w+)\s*(?:string\s*)?=\s*("(?:\\.|[^"\\])*")',text,re.M):constants.append(dict(ref(m.start()),name=m.group(1),value=json.loads(m.group(2))))
  if rel.startswith('controllers/httpapi/') and re.search(r'func .*?(?:CredentialPath|Path\(|requiresAuthenticated|serve.*Request)',text):
   for m in re.finditer(r'^func (?:\([^\n]*?\) )?((?:\w*CredentialPath|\w*Path|requiresAuthenticated\w*|serve\w*Request))\(',text,re.M):auth.append(dict(ref(m.start()),function=m.group(1)))
 for p in sorted((root/'docs/contracts/events/v1').glob('**/*.json')):
  rel=p.relative_to(root).as_posix();schema.append({'schema_key':'.'.join(p.relative_to(root/'docs/contracts/events/v1').with_suffix('').parts),'file':rel,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'classification':'nativequalification-only' if '/native_qualification/' in rel else 'event-schema'})
 return {'sources':sources,'http-routes':routes,'event-emissions':events,'event-schemas':schema,'event-and-queue-constants':constants,'rpc-consumers':consumers,'http-egress':egress,'authentication-dispatch':auth,'http-intercept-dispatch':intercepts,'provider-sdk-operations':sdk,'production-command-operations':commands}
def main():
 a=argparse.ArgumentParser();a.add_argument('--root',type=Path,required=True);a.add_argument('--out',type=Path,required=True);a.add_argument('--verify',action='store_true');x=a.parse_args();result=generate(x.root)
 if not x.verify:x.out.mkdir(parents=True,exist_ok=True)
 failures=[]
 for name,data in result.items():
  target=x.out/(name+'.json')
  # Keep the complete growing Source map within the published doctor's 128KiB bound.
  options={'separators':(',',':')} if name=='sources' else {'indent':2}
  raw=json.dumps({'schema':'core_source_interface_census_v1','scope':'source facts; no deployed endpoint or runtime authority claimed','records':data},sort_keys=True,**options)+'\n'
  if x.verify:
   if not target.is_file() or target.read_text()!=raw:failures.append(target.name)
  else:target.write_text(raw)
 if failures:raise SystemExit('source census drift: '+', '.join(failures))
 print(json.dumps({k:len(v) for k,v in result.items()}))
if __name__=='__main__':main()
