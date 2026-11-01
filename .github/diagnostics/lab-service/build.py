"""Build a sealed, disposable LAB rehearsal bundle; never installs or starts it."""
import argparse,hashlib,json,os,re,secrets,shutil,subprocess,tempfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
PREFIX='.github/diagnostics/controller-integration/'
LAB='i-0cb486ae31a45d15e'

def git(*args):
    return subprocess.run(['git',*args],cwd=REPO,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout

def build(commit,boot,output):
    if not re.fullmatch('[0-9a-f]{40}',commit) or git('rev-parse','HEAD').decode().strip()!=commit:
        raise ValueError('EXACT_CHECKED_OUT_COMMIT_REQUIRED')
    if git('status','--porcelain','--untracked-files=no').strip():raise ValueError('CLEAN_TRACKED_SOURCE_REQUIRED')
    if not re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot):raise ValueError('EXACT_LAB_BOOT_REQUIRED')
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    output.parent.mkdir(parents=True,exist_ok=True)
    stage=Path(tempfile.mkdtemp(prefix='.lab-bundle-',dir=output.parent))
    try:
        source=stage/'sources';source.mkdir();files={}
        rows=git('ls-tree','-r',commit,'--',PREFIX).decode().splitlines()
        for row in rows:
            meta,path=row.split('\t',1);mode,kind,_=meta.split()
            if mode!='100644' or kind!='blob' or not path.startswith(PREFIX):raise ValueError('ONLY_TRACKED_REGULAR_SOURCES')
            name=path[len(PREFIX):]
            if not name or '..' in Path(name).parts:raise ValueError('SAFE_SOURCE_PATH_REQUIRED')
            data=git('show',commit+':'+path);target=source/name
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);target.chmod(0o644)
            files[name]=hashlib.sha256(data).hexdigest()
        if not files or 'verify_controller_guardian.py' not in files:raise ValueError('COMPLETE_FIXTURE_REQUIRED')
        manifest={'schema':'lab_rehearsal_sources_v1','commit':commit,'files':files,'production_authority':False}
        raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode();(stage/'manifest.json').write_bytes(raw)
        short=commit[:12];nonce=secrets.token_hex(6)
        unit='dakasa-elastic-lab-'+nonce+'.service';slice_name='system-dakasa-elastic-lab-'+nonce+'.slice'
        runtime='dakasa-elastic-lab-'+nonce;install='/opt/dakasa/lab-only/'+runtime
        spec={'instance_id':LAB,'boot_id':boot,'unit':unit,'slice':slice_name,'nonce':nonce,'runtime_directory':runtime,
              'unit_path':'/etc/systemd/system/'+unit,'manifest_sha256':hashlib.sha256(raw).hexdigest()}
        cleanup=(HERE/'cleanup_template.py').read_text().replace('__SPEC_LITERAL__',repr(json.dumps(spec,sort_keys=True)))
        (stage/'cleanup.py').write_text(cleanup)
        spec['cleanup_sha256']=hashlib.sha256(cleanup.encode()).hexdigest()
        unit_text=('[Unit]\nDescription=DaKasa disposable LAB guarded rehearsal '+short+'\n'
            '[Service]\nType=exec\nRuntimeDirectory='+runtime+'\nRuntimeDirectoryMode=0700\n'
            'RuntimeMaxSec=150s\nTimeoutStopSec=60s\nKillMode=control-group\n'
            'ExecStart=/usr/bin/python3 -B '+install+'/entrypoint.py\n'
            'ExecStopPost=/usr/bin/python3 -B '+install+'/cleanup.py\n')
        spec['unit_sha256']=hashlib.sha256(unit_text.encode()).hexdigest()
        entry=(HERE/'entry_template.py').read_text().replace('__SPEC_LITERAL__',repr(json.dumps(spec,sort_keys=True)))
        if '__SPEC_LITERAL__' in entry or '__SPEC_LITERAL__' in cleanup:raise ValueError('UNRESOLVED_SPEC')
        (stage/'entrypoint.py').write_text(entry)
        (stage/unit).write_text(unit_text)
        for path in stage.rglob('*'):
            if path.is_file():path.chmod(0o644)
            elif path.is_dir():path.chmod(0o755)
        summary={'schema':'lab_rehearsal_bundle_v1','commit':commit,'instance_id':LAB,'boot_id':boot,
                 'unit':unit,'slice':slice_name,'install_path':install,'manifest_sha256':spec['manifest_sha256'],
                 'entrypoint_sha256':hashlib.sha256(entry.encode()).hexdigest(),
                 'unit_sha256':spec['unit_sha256'],'cleanup_sha256':spec['cleanup_sha256'],'nonce':nonce,
                 'operational_controller':False,'production_authority':False}
        (stage/'bundle-summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
        os.rename(stage,output);return summary
    except BaseException:
        shutil.rmtree(stage,ignore_errors=True);raise

def main():
    p=argparse.ArgumentParser();p.add_argument('--commit',required=True);p.add_argument('--boot-id',required=True);p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();print(json.dumps(build(a.commit,a.boot_id,a.output),sort_keys=True))
if __name__=='__main__':main()
