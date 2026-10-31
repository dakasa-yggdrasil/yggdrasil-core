"""LAB-only independent Guardian reference for the exact BPF program.

The embedded reviewed instruction template and all reference syscalls are
owned here, independent of the preparer and its helpers. A kernel-translated
byte-for-byte comparison normalizes only the single map ID. Different kernel
translation, unavailable introspection or unexpected shape must HOLD.
"""
import ctypes
import hashlib
import os
import platform
import struct

_TEMPLATE=bytes.fromhex('bf19000000000000b702000000000000bfa300000000000007030000e0ffffffb704000018000000850000001a000000550018000000000071a0e0ff00000000550016004500000071a0e9ff00000000550014000600000069a0e6ff00000000570000003fff0000550011000000000061a6ecff00000000636ad0ff0000000061a6f0ff00000000636ad4ff0000000069a6f6ff00000000636ad8ff0000000018110000000000000000000000000000bfa200000000000007020000d0ffffff85000000010000001500050000000000790700000000000085000000050000003d70020000000000b7000000ffffffff9500000000000000b7000000000000009500000000000000')
_TEMPLATE_SHA256='87adca8d9fedf603c7ec6c309794de7bc0118064283c81c7bb7edf949b7985cc'
_LIB=ctypes.CDLL(None,use_errno=True);_LIB.syscall.restype=ctypes.c_long

class Held(RuntimeError):pass

def need(value,reason):
    if not value:raise Held(reason)

def _bpf(op,raw):
    b=ctypes.create_string_buffer(raw+bytes(max(0,144-len(raw))));result=_LIB.syscall(321,op,ctypes.byref(b),ctypes.sizeof(b))
    if result<0:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return result

class _ProgInfo(ctypes.Structure):
    _fields_=[('type',ctypes.c_uint32),('id',ctypes.c_uint32),('tag',ctypes.c_ubyte*8),('jited_len',ctypes.c_uint32),('xlated_len',ctypes.c_uint32),('jited_insns',ctypes.c_uint64),('xlated_insns',ctypes.c_uint64),('load_time',ctypes.c_uint64),('created_by_uid',ctypes.c_uint32),('nr_map_ids',ctypes.c_uint32),('map_ids',ctypes.c_uint64)]
class _MapInfo(ctypes.Structure):
    _fields_=[('type',ctypes.c_uint32),('id',ctypes.c_uint32),('key_size',ctypes.c_uint32),('value_size',ctypes.c_uint32),('max_entries',ctypes.c_uint32),('map_flags',ctypes.c_uint32)]

def _info(fd,obj):_bpf(15,struct.pack('<IIQ',fd,ctypes.sizeof(obj),ctypes.addressof(obj)));return obj

def _dump(program_id,map_id):
    fd=_bpf(13,struct.pack('<I',program_id))
    try:
        first=_ProgInfo();ids=(ctypes.c_uint32*4)();first.nr_map_ids=4;first.map_ids=ctypes.addressof(ids);_info(fd,first)
        need(first.id==program_id and first.type==1 and first.nr_map_ids==1 and ids[0]==map_id
             and 0<first.xlated_len<=65536 and first.xlated_len%8==0,'EXACT_BOUNDED_TRANSLATED_PROGRAM_REQUIRED')
        raw=ctypes.create_string_buffer(first.xlated_len);second=_ProgInfo();ids2=(ctypes.c_uint32*4)()
        second.xlated_len=first.xlated_len;second.xlated_insns=ctypes.addressof(raw);second.nr_map_ids=4;second.map_ids=ctypes.addressof(ids2)
        _info(fd,second)
        need(second.id==program_id and second.type==1 and second.nr_map_ids==1 and ids2[0]==map_id
             and second.xlated_len==first.xlated_len,'SAME_PROGRAM_AND_TRANSLATED_LENGTH')
        data=bytearray(raw.raw[:second.xlated_len]);seen=0
        for pos in range(0,len(data),8):
            code,regs,off,imm=struct.unpack_from('<BBhi',data,pos)
            if code==0x18 and (regs>>4)==1:
                need(pos+16<=len(data) and off==0 and imm==map_id,'EXACT_SINGLE_MAP_REFERENCE')
                code2,regs2,off2,imm2=struct.unpack_from('<BBhi',data,pos+8)
                need(code2==0 and regs2==0 and off2==0 and imm2==0,'EXACT_MAP_REFERENCE_TAIL')
                data[pos+4:pos+8]=bytes(4);seen+=1
        need(seen==1,'ONE_NORMALIZED_MAP_ID_REQUIRED')
        return bytes(data)
    finally:os.close(fd)

class GuardianProgramReference:
    def __init__(self):
        need(platform.machine()=='x86_64' and hashlib.sha256(_TEMPLATE).hexdigest()==_TEMPLATE_SHA256,
             'PINNED_REVIEWED_LAB_TEMPLATE_REQUIRED')
        self.pid=os.getpid();self.closed=False;self.program_fd=None;self.map_fd=None
        try:
            self.map_fd=_bpf(0,struct.pack('<IIIII',1,12,8,256,128))
            key=ctypes.create_string_buffer(bytes.fromhex('01'*12));value=ctypes.c_uint64(1)
            _bpf(2,struct.pack('<IIQQQ',self.map_fd,0,ctypes.addressof(key),ctypes.addressof(value),0));_bpf(22,struct.pack('<I',self.map_fd))
            code=bytearray(_TEMPLATE);locations=[i for i in range(0,len(code),8) if code[i]==0x18 and (code[i+1]>>4)==1]
            need(len(locations)==1 and code[locations[0]+4:locations[0]+8]==bytes(4),'ONE_TEMPLATE_MAP_PLACEHOLDER')
            struct.pack_into('<i',code,locations[0]+4,self.map_fd)
            instructions=ctypes.create_string_buffer(bytes(code));license=ctypes.create_string_buffer(b'GPL');log=ctypes.create_string_buffer(65536)
            self.program_fd=_bpf(5,struct.pack('<IIQQIIQ',1,len(code)//8,ctypes.addressof(instructions),ctypes.addressof(license),1,len(log),ctypes.addressof(log)))
            info=_info(self.program_fd,_ProgInfo());mapinfo=_info(self.map_fd,_MapInfo())
            self.code=_dump(info.id,mapinfo.id)
        except BaseException:
            self.close();raise

    def verify(self,program_id,map_id):
        need(not self.closed and os.getpid()==self.pid and type(program_id) is int and type(map_id) is int,
             'LIVE_SAME_GUARDIAN_REFERENCE_REQUIRED')
        need(_dump(program_id,map_id)==self.code,'TRANSLATED_PROGRAM_DIFFERS_FROM_GUARDIAN_REFERENCE')
        return {'guardian_reference_program_equal':True,'external_effect_authorized':False,'production_authority':False}

    def close(self):
        if not self.closed:
            self.closed=True
            try:
                if self.program_fd is not None:os.close(self.program_fd)
            finally:
                if self.map_fd is not None:os.close(self.map_fd)
