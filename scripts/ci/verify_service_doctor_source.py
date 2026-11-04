"""Verify private source in place; emit hashes only, never private source bytes."""
from pathlib import Path
import hashlib,re,subprocess,sys

def tree_digest(root):
 paths=subprocess.check_output(['git','ls-files','-z'],cwd=root).split(b'\0')
 h=hashlib.sha256()
 for raw in sorted(x for x in paths if x):
  path=root/raw.decode()
  if path.is_symlink() or not path.is_file():raise ValueError('checker tracked entry is not a regular file')
  h.update(raw+b'\0'+hashlib.sha256(path.read_bytes()).hexdigest().encode()+b'\n')
 return h.hexdigest()

def verify(root,commit,expected):
 if not re.fullmatch('[0-9a-f]{40}',commit) or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('exact checker identity required')
 if subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()!=commit:raise ValueError('checker commit mismatch')
 if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=root):raise ValueError('checker worktree is not clean')
 actual=tree_digest(root)
 if actual!=expected:raise ValueError('checker tree digest mismatch')
 print('reviewed_checker_source_sha256='+actual)

if __name__=='__main__':
 if len(sys.argv)!=4:raise SystemExit('usage: verify_service_doctor_source.py ROOT COMMIT TREE_SHA256')
 verify(Path(sys.argv[1]),sys.argv[2],sys.argv[3])
