"""Disposable kernel test: BPF enforces absolute TTL, not Reader revocation."""
import ctypes,os,socket,struct,time
import guarded_nl as nl

class TestAttr(ctypes.Structure):
    _fields_=[('prog_fd',ctypes.c_uint32),('retval',ctypes.c_uint32),('data_size_in',ctypes.c_uint32),
              ('data_size_out',ctypes.c_uint32),('data_in',ctypes.c_uint64),('data_out',ctypes.c_uint64),
              ('repeat',ctypes.c_uint32),('duration',ctypes.c_uint32),('ctx_size_in',ctypes.c_uint32),
              ('ctx_size_out',ctypes.c_uint32),('ctx_in',ctypes.c_uint64),('ctx_out',ctypes.c_uint64),
              ('flags',ctypes.c_uint32),('cpu',ctypes.c_uint32),('batch_size',ctypes.c_uint32)]

def test(fd,packet):
    inp=ctypes.create_string_buffer(packet);out=ctypes.create_string_buffer(len(packet)+128)
    a=TestAttr(prog_fd=fd,data_size_in=len(packet),data_size_out=len(out),
               data_in=ctypes.addressof(inp),data_out=ctypes.addressof(out),repeat=1)
    result=nl.LIB.syscall(321,10,ctypes.byref(a),ctypes.sizeof(a))
    if result<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return a.retval

def main():
    source=socket.inet_aton('10.201.24.17');dest=socket.inet_aton('172.18.1.3');port=5432
    key=source+dest+struct.pack('>H',port)+bytes(2)
    packet=bytearray(40);packet[0]=0x45;packet[9]=6;packet[12:16]=source;packet[16:20]=dest
    packet[20:22]=struct.pack('>H',45678);packet[22:24]=struct.pack('>H',port)
    deadline=time.monotonic_ns()+1_000_000_000
    r=nl.make_program([(key.hex(),deadline)])
    try:
        before=test(r['program_fd'],bytes(packet));assert before==0xffffffff, 'CI_BEFORE_RETVAL_%s'%before
        # A Reader failure alone does not mutate this frozen map.
        after_reader_failure=test(r['program_fd'],bytes(packet));assert after_reader_failure==0xffffffff
        while time.monotonic_ns()<=deadline+50_000_000:time.sleep(.01)
        expired=test(r['program_fd'],bytes(packet));assert expired==0
        print('PASS real BPF test-run: allow before deadline; Reader failure alone still allows; deny after expiry',flush=True)
        print('BOUNDARY: packet fixture only; no revocation bound or network continuity claim',flush=True)
    finally:os.close(r['program_fd']);os.close(r['map_fd'])
if __name__=='__main__':main()
