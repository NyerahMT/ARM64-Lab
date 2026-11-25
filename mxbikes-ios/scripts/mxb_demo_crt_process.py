"""Bounded, deterministic CRT startup data and argument services; no licensing API."""
import struct

CRT_DATA=0x760000000
PAGE=4096
DATA_OFFSETS={"_acmdln":0,"_wcmdln":8,"_fmode":16,"_commode":20}
ARGV=CRT_DATA+0x40
ENVP=CRT_DATA+0x60
ARGV0=CRT_DATA+0x100
APIS=frozenset({"__set_app_type","_configthreadlocale","__getmainargs"})

def data_address(library,name):
    if library.lower()!="msvcr90.dll" or name not in DATA_OFFSETS:return None
    return CRT_DATA+DATA_OFFSETS[name]

def data_page(command_a,command_w,argv0):
    if not (0<command_a<2**64 and 0<command_w<2**64 and
            isinstance(argv0,bytes) and 1<len(argv0)<=256 and
            argv0.endswith(b"\0") and b"\0" not in argv0[:-1]):
        raise ValueError("invalid_crt_process_data")
    page=bytearray(PAGE)
    struct.pack_into("<QQII",page,0,command_a,command_w,0x4000,0)
    struct.pack_into("<QQ",page,ARGV-CRT_DATA,ARGV0,0)
    page[ARGV0-CRT_DATA:ARGV0-CRT_DATA+len(argv0)]=argv0
    return bytes(page)

class Process:
    def __init__(self):
        self.app_type=None
        self.locale_mode=2

    def dispatch(self,name,args,*,read,write,writable,rsp):
        """Return RAX or None for void; reject unsupported modes before writes."""
        a,b,c,d=args
        if name=="__set_app_type":
            kind=a&0xffffffff
            if kind not in (1,2):raise ValueError("invalid_app_type")
            self.app_type=kind
            return None
        if name=="_configthreadlocale":
            mode=a&0xffffffff
            if mode not in (0,1,2):raise ValueError("unsupported_locale_mode")
            old=self.locale_mode
            if mode:self.locale_mode=mode
            return old
        if name!="__getmainargs":raise ValueError("unsupported_crt_service")
        if d&0xffffffff:raise ValueError("wildcard_expansion_unsupported")
        if not 0<rsp<=2**64-48:raise ValueError("invalid_crt_stack")
        startup=struct.unpack("<Q",bytes(read(rsp+40,8)))[0]
        if not startup or startup>2**64-4 or bytes(read(startup,4))!=b"\0"*4:
            raise ValueError("unsupported_crt_startup_newmode")
        outputs=[(a,struct.pack("<I",1)),(b,struct.pack("<Q",ARGV)),(c,struct.pack("<Q",ENVP))]
        ranges=[]
        for ptr,data in outputs:
            end=ptr+len(data)
            if not (0<ptr<end<=2**64 and any(lo<=ptr and end<=hi for lo,hi in writable)):
                raise ValueError("invalid_crt_argument_output")
            if any(ptr<hi and lo<end for lo,hi in ranges):raise ValueError("overlapping_crt_outputs")
            ranges.append((ptr,end))
        for ptr,data in outputs:write(ptr,data)
        return 0
