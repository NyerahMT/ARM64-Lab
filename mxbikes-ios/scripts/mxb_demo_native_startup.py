"""Unified native standalone startup service bridge (local trusted library only)."""
import ctypes as C
from mxb_demo_native_crt import NativeCRT, APIS, _Process, _Regs, _Memory, _Read, _Check, _Write, _Exec

CRT_APIS=APIS|{"strcpy","strrchr","malloc","calloc","free","memset","memcpy","memmove","memcmp"}
HEAP_BASE=0x770000000
HEAP_CAP=16*1024*1024
WIN_APIS=frozenset({"GetTickCount","GetTickCount64","GetLastError","SetLastError",
                   "SetCurrentDirectoryA","GetCurrentDirectoryA","GetModuleFileNameA",
                   "SetUnhandledExceptionFilter"})
MM_APIS=frozenset({"timeGetTime","timeBeginPeriod","timeEndPeriod"})
CLOCKS=frozenset({"GetTickCount","GetTickCount64","timeGetTime"})

class _Platform(C.Structure):
    _fields_=[("root",C.c_uint8*260),("cwd",C.c_uint8*260),("elapsed_ms",C.c_uint64),
              ("last_error",C.c_uint32),("timer_refs",C.c_uint32)]

class _Block(C.Structure):
    _fields_=[("address",C.c_uint64),("size",C.c_uint64)]

class _Heap(C.Structure):
    _fields_=[("blocks",_Block*256)]

class _Startup(C.Structure):
    _fields_=[("platform",_Platform),("crt",_Process),("module_path",C.c_uint8*260),
              ("image_base",C.c_uint64),("exception_filter",C.c_uint64),("heap",_Heap)]

class NativeStartup(NativeCRT):
    def __init__(self,path,image_base,root=b"C:\\MXBReference\0",
                 module=b"C:\\MXBReference\\mxbikes.exe\0",ticks=0x9abc):
        super().__init__(path)
        self.lib.mxb_startup_init.argtypes=[C.POINTER(_Startup),C.c_char_p,C.c_size_t,
                  C.c_char_p,C.c_size_t,C.c_uint64,C.c_uint64,C.c_uint64]
        self.lib.mxb_startup_init.restype=C.c_int
        self.lib.mxb_startup_dispatch.argtypes=[C.POINTER(_Startup),C.POINTER(_Memory),
                  C.c_char_p,C.c_char_p,C.POINTER(_Regs)]
        self.lib.mxb_startup_dispatch.restype=C.c_int
        self.lib.mxb_platform_advance.argtypes=[C.POINTER(_Platform),C.c_uint64]
        self.lib.mxb_platform_advance.restype=C.c_int
        self.startup=_Startup()
        if self.lib.mxb_startup_init(C.byref(self.startup),root,len(root),module,len(module),
                                    image_base,ticks,0x7d91ca346f289b15)!=1:
            raise ValueError("invalid_native_startup_context")
        self.state=self.startup.crt
        self.clock_instruction=0

    @staticmethod
    def supports(dll,name):
        dll=dll.lower()
        return (dll=="msvcr90.dll" and name in CRT_APIS or
                dll in ("kernel32.dll","kernelbase.dll") and name in WIN_APIS or
                dll=="winmm.dll" and name in MM_APIS)

    def advance_to_instruction(self,count):
        # Deterministic test clock; not a physical time or performance estimate.
        if not self.clock_instruction<=count<2**64:raise ValueError("invalid_clock_count")
        delta=(count-self.clock_instruction)//1000
        if self.lib.mxb_platform_advance(C.byref(self.startup.platform),delta)!=1:
            raise ValueError("clock_overflow")
        self.clock_instruction+=delta*1000

    def dispatch_import(self,dll,name,args,*,read,write,writable,rsp,executable,rax):
        if not self.supports(dll,name):raise ValueError("unsupported_native_startup_service")
        errors=[];pending=[]
        @_Read
        def get(_,ptr,out,n):
            try:
                data=bytes(read(ptr,n))
                if len(data)!=n:return 0
                C.memmove(out,data,n);return 1
            except Exception as exc:errors.append(exc);return 0
        @_Check
        def canwrite(_,ptr,n):return int(any(lo<=ptr and ptr+n<=hi for lo,hi in writable))
        @_Write
        def put(_,ptr,src,n):
            try:pending.append((ptr,C.string_at(src,n)))
            except Exception as exc:errors.append(exc)
        @_Exec
        def canexec(_,ptr):return int(any(lo<=ptr<hi for lo,hi in executable))
        mem=_Memory(None,get,canwrite,put,canexec);regs=_Regs(*args,rsp,rax)
        status=self.lib.mxb_startup_dispatch(C.byref(self.startup),C.byref(mem),
                  dll.encode("ascii"),name.encode("ascii"),C.byref(regs))
        if errors or status!=1:raise ValueError("native_startup_service_rejected")
        for ptr,data in pending:write(ptr,data)
        return regs.rax
