"""Root-owned throwaway systemd peer used only by Linux CI."""
import os,socket,sys,time
from pathlib import Path
child_path=os.environ.get("CI_TERM_CHILD_PIDFILE")
if child_path:
    child=os.fork()
    if child==0:
        while True:time.sleep(60)
    Path(child_path).write_text(str(child))
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.recv(1)
