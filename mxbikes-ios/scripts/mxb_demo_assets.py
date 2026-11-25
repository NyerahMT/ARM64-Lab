"""Read-only asset mounts; caller selects paths, guest sees flat names only."""
import ctypes as C
import hashlib
import os
import stat
from pathlib import Path

MAX_SIZE=2**31-1
CHUNK=16384
DEMO_EXE_SHA="b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742"
CORE_SHA="92d455770a96575e75239b317408d0c5516fbf087d5f28b3a8646e22f06b07bf"
# Public beta21e package inventory, observed in the prior desktop reference run.
DEMO_ASSETS={"core.ini":179,"joysticks.cfg":72,"mxbikes.ini":253,
             "proxy_udp.ini":69,"series.pkz":1834,"bikes.pkz":450147044,
             "effects.pkz":16168244,"misc.pkz":43752024,"rider.pkz":105693432,
             "tracks.pkz":1751015009,"tyres.pkz":20741299,"ui.pkz":1178681}
ReadAt=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
class Mount(C.Structure):
    _fields_=[("name",C.c_char*128),("data",C.c_void_p),("size",C.c_uint64),
              ("read_at",ReadAt),("ctx",C.c_void_p)]
class Handle(C.Structure):
    _fields_=[("token",C.c_uint64),("pos",C.c_uint64),("mount",C.c_uint32),
              ("eof",C.c_uint32),("error",C.c_uint32)]
class Files(C.Structure):
    _fields_=[("mounts",Mount*16),("handles",Handle*32),("generation",C.c_uint64)]

def open_regular(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_BINARY",0))
    try:
        f=os.fdopen(fd,"rb",buffering=0)
    except BaseException:
        os.close(fd);raise
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
        f.close();raise ValueError("asset_not_regular")
    return f

def digest(f):
    f.seek(0);h=hashlib.sha256()
    while True:
        b=f.read(1024*1024)
        if not b:break
        h.update(b)
    f.seek(0);return h.hexdigest()

class AssetMounts:
    def __init__(self,lib,files):
        self.lib=lib;self.files=files;self._keep=[];self.closed=False
        lib.mxb_files_mount.argtypes=[C.POINTER(Files),C.c_char_p,C.c_void_p,C.c_uint64]
        lib.mxb_files_mount.restype=C.c_int
        lib.mxb_files_mount_source.argtypes=[C.POINTER(Files),C.c_char_p,C.c_uint64,ReadAt,C.c_void_p]
        lib.mxb_files_mount_source.restype=C.c_int
    @property
    def count(self):return len(self._keep)
    def mount_bytes(self,name,data):
        if self.closed or not isinstance(data,bytes) or len(data)>64*1024*1024:
            raise ValueError("invalid_asset_data")
        b=C.create_string_buffer(data)
        if self.lib.mxb_files_mount(C.byref(self.files),name.encode("ascii"),b,len(data))!=1:
            raise ValueError("invalid_asset_mount")
        self._keep.append((b,None))
    def mount_path(self,path,*,expected_size=None,expected_sha=None):
        if self.closed:raise ValueError("asset_mounts_closed")
        path=Path(path);f=open_regular(path)
        try:
            size=os.fstat(f.fileno()).st_size
            if not 0<=size<=MAX_SIZE or expected_size is not None and size!=expected_size:
                raise ValueError("asset_size_mismatch")
            if expected_sha is not None and digest(f)!=expected_sha:
                raise ValueError("asset_sha_mismatch")
            @ReadAt
            def read_at(_,offset,out,n):
                try:
                    if n>CHUNK or offset>size or n>size-offset:return 0
                    if hasattr(os,"pread"):data=os.pread(f.fileno(),n,offset)
                    else:f.seek(offset);data=f.read(n)
                    if len(data)!=n:return 0
                    C.memmove(out,data,n);return 1
                except (OSError,ValueError):return 0
            if self.lib.mxb_files_mount_source(C.byref(self.files),path.name.encode("ascii"),size,read_at,None)!=1:
                raise ValueError("invalid_asset_mount")
            self._keep.append((read_at,f))
        except BaseException:
            f.close();raise
    def mount_demo_directory(self,root):
        if self.closed or self.count:raise ValueError("demo_mount_requires_empty_session")
        root=Path(root)
        with open_regular(root/"mxbikes.exe") as f:
            if os.fstat(f.fileno()).st_size!=3878912 or digest(f)!=DEMO_EXE_SHA:
                raise ValueError("demo_executable_mismatch")
        try:
            for name,size in DEMO_ASSETS.items():
                self.mount_path(root/name,expected_size=size,expected_sha=CORE_SHA if name=="core.ini" else None)
        except BaseException:
            self.close();raise
    def close(self):
        if not self.closed:
            # Invalidate native handles before releasing callbacks/storage.
            C.memset(C.byref(self.files),0,C.sizeof(self.files));self.closed=True
            for _,f in self._keep:
                if f is not None:f.close()
            self._keep.clear()
