"""CI test child; reports whether the original flock inode survived exec."""
import os,sys,time
from pathlib import Path
pidfile,report,dev,ino,duration=sys.argv[1:]
found=False
for name in os.listdir('/proc/self/fd'):
    try:st=os.stat('/proc/self/fd/'+name)
    except FileNotFoundError:continue
    if (st.st_dev,st.st_ino)==(int(dev),int(ino)):found=True
Path(report).write_text('INHERITED' if found else 'ABSENT')
Path(pidfile).write_text(str(os.getpid()))
time.sleep(float(duration))
