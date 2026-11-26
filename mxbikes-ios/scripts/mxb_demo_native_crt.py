"""Native host bridge for the standalone reference runner's bounded CRT services.

The caller supplies a locally compiled trusted C library and guest memory
callbacks. This does not translate guest instructions or implement a full CRT.
"""
import ctypes as C
from pathlib import Path

PAGE=4096
APIS=frozenset({"__set_app_type","_configthreadlocale","__getmainargs",
                "_encode_pointer","_decode_pointer","_onexit","_ismbblead","_mktime64"})

class _Process(C.Structure):
    _fields_=[("app_type",C.c_uint32),("locale_mode",C.c_uint32),
              ("pointer_key",C.c_uint64),("exit_count",C.c_uint32),
              ("exit_callbacks",C.c_uint64*32)]

class _Regs(C.Structure):
    _fields_=[(k,C.c_uint64) for k in ("rcx","rdx","r8","r9","rsp","rax")]

_Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
_Check=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_size_t)
_Write=C.CFUNCTYPE(None,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
_Exec=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64)

class _Memory(C.Structure):
    _fields_=[("ctx",C.c_void_p),("read",_Read),("writable",_Check),
              ("write",_Write),("executable",_Exec)]

class NativeCRT:
    def __init__(self,path):
        self.lib=C.CDLL(str(Path(path).resolve(strict=True)))
        self.lib.mxb_crt_data_address.argtypes=[C.c_char_p,C.c_char_p]
        self.lib.mxb_crt_data_address.restype=C.c_uint64
        self.lib.mxb_crt_data_page.argtypes=[C.c_void_p,C.c_size_t,C.c_uint64,
            C.c_uint64,C.c_char_p,C.c_size_t]
        self.lib.mxb_crt_data_page.restype=C.c_int
        self.lib.mxb_crt_dispatch.argtypes=[C.POINTER(_Process),C.POINTER(_Memory),
            C.c_char_p,C.c_char_p,C.POINTER(_Regs)]
        self.lib.mxb_crt_dispatch.restype=C.c_int
        self.state=_Process(0,2,0x7d91ca346f289b15)

    @property
    def app_type(self):return self.state.app_type or None
    @property
    def locale_mode(self):return self.state.locale_mode
    @property
    def exit_count(self):return self.state.exit_count

    def data_address(self,library,name):
        return self.lib.mxb_crt_data_address(library.encode("ascii"),name.encode("ascii")) or None

    def data_page(self,a,w,argv0):
        buf=C.create_string_buffer(PAGE)
        if self.lib.mxb_crt_data_page(buf,PAGE,a,w,argv0,len(argv0))!=1:
            raise ValueError("native_crt_data_page_rejected")
        return buf.raw

    def dispatch(self,name,args,*,read,write,writable,rsp,executable,rax):
        if name not in APIS:raise ValueError("unsupported_native_crt_service")
        # Capture callback errors instead of letting ctypes swallow exceptions.
        # C output writes are staged here; only commit after successful dispatch.
        errors=[];pending=[]
        @_Read
        def get(_,ptr,out,n):
            try:
                data=bytes(read(ptr,n))
                if len(data)!=n:return 0
                C.memmove(out,data,n);return 1
            except Exception as exc:errors.append(exc);return 0
        @_Check
        def canwrite(_,ptr,n):
            return int(any(lo<=ptr and ptr+n<=hi for lo,hi in writable))
        @_Write
        def put(_,ptr,src,n):
            try:pending.append((ptr,C.string_at(src,n)))
            except Exception as exc:errors.append(exc)
        @_Exec
        def canexec(_,ptr):
            return int(any(lo<=ptr<hi for lo,hi in executable))
        mem=_Memory(None,get,canwrite,put,canexec)
        regs=_Regs(*args,rsp,rax)
        status=self.lib.mxb_crt_dispatch(C.byref(self.state),C.byref(mem),
            b"msvcr90.dll",name.encode("ascii"),C.byref(regs))
        if errors or status!=1:raise ValueError("native_crt_service_rejected")
        for ptr,data in pending:write(ptr,data)
        return regs.rax
