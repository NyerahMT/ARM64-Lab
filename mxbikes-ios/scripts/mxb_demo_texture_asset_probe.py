"""Bounded TGA-to-native-texture test bridge. No original game code is executed.

The independent decoder normalizes true-color 24/32-bit TGA to RGBA8 in
OpenGL's bottom-left row order. The upload goes through the existing Win64
texture adapter, not through a replacement renderer or a simulated result.
"""
import ctypes as C
import hashlib
import os
import struct
import zipfile
from pathlib import Path
from mxb_demo_pkz_audit import index

MAX_DIM=2048
MAX_INPUT=32*1024*1024
BASE=0x620000000
STACK=0x740000008
ID=0x750000000


def decode_tga(data):
    if not 18<=len(data)<=MAX_INPUT:
        raise ValueError('tga_size')
    ident,cmap,kind,_,_,_,_,_,w,h,bits,desc=struct.unpack_from('<BBBHHBHHHHBB',data)
    if cmap or kind not in (2,10) or bits not in (24,32) or desc&0xc0:
        raise ValueError('unsupported_tga')
    if not 1<=w<=MAX_DIM or not 1<=h<=MAX_DIM:
        raise ValueError('tga_dimensions')
    if (bits==24 and desc&15) or (bits==32 and desc&15 not in (0,8)):
        raise ValueError('tga_alpha_layout')
    n=w*h;bpp=bits//8;pos=18+ident
    if pos>len(data):raise ValueError('truncated_tga')
    out=bytearray(n*4)
    i=0
    def pixel():
        nonlocal pos
        if pos+bpp>len(data):raise ValueError('truncated_tga')
        b,g,r=data[pos:pos+3]
        a=data[pos+3] if bpp==4 and desc&15==8 else 255
        pos+=bpp
        return bytes((r,g,b,a))
    def emit(p):
        nonlocal i
        x=i%w;y=i//w
        if desc&0x10:x=w-1-x
        if desc&0x20:y=h-1-y
        offset=(y*w+x)*4
        out[offset:offset+4]=p
        i+=1
    while i<n:
        if kind==2:
            emit(pixel());continue
        if pos>=len(data):raise ValueError('truncated_tga')
        tag=data[pos];pos+=1;count=(tag&127)+1
        if count>n-i:raise ValueError('tga_packet_overflow')
        if tag&128:
            p=pixel()
            for _ in range(count):emit(p)
        else:
            for _ in range(count):emit(pixel())
    return w,h,bytes(out)


class Registers(C.Structure):
    _fields_=[('rcx',C.c_uint64),('rsp',C.c_uint64),('xmm',C.c_uint64*4),
              ('rdx',C.c_uint64),('r8',C.c_uint64),('r9',C.c_uint64)]


Read=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
Write=Read


def upload(library,w,h,rgba):
    if not 1<=w<=MAX_DIM or not 1<=h<=MAX_DIM or len(rgba)!=w*h*4:
        raise ValueError('invalid_rgba')
    lib=C.CDLL(str(Path(library).resolve()))
    lib.mxb_tex_create.argtypes=[];lib.mxb_tex_create.restype=C.c_void_p
    lib.mxb_tex_destroy.argtypes=[C.c_void_p];lib.mxb_tex_destroy.restype=None
    lib.mxb_tex_dispatch_win64.argtypes=[C.c_void_p,C.c_char_p,C.c_char_p,
        C.POINTER(Registers),Read,Write,C.c_void_p]
    lib.mxb_tex_dispatch_win64.restype=C.c_int
    lib.mxb_tex_current_rgba.argtypes=[C.c_void_p,C.POINTER(C.c_uint),C.POINTER(C.c_uint)]
    lib.mxb_tex_current_rgba.restype=C.c_void_p
    lib.mxb_tex_storage_bytes.argtypes=[C.c_void_p];lib.mxb_tex_storage_bytes.restype=C.c_size_t
    stack=bytearray(80);ids=bytearray(4)
    regions=((BASE,rgba),(STACK,stack),(ID,ids))
    @Read
    def read(_,address,out,n):
        for base,data in regions:
            if base<=address and n<=len(data)-(address-base):
                C.memmove(out,bytes(data[address-base:address-base+n]),n)
                return 1
        return 0
    @Write
    def write(_,address,src,n):
        if address==ID and n==4:
            ids[:]=C.string_at(src,n);return 1
        return 0
    texture=lib.mxb_tex_create()
    if not texture:raise RuntimeError('texture_create')
    def call(name,a=0,b=0,c=0,d=0):
        regs=Registers();regs.rsp=STACK;regs.rcx=a;regs.rdx=b;regs.r8=c;regs.r9=d
        status=lib.mxb_tex_dispatch_win64(texture,b'OPENGL32.dll',name.encode(),
                    C.byref(regs),read,write,None)
        if status:raise RuntimeError('texture_adapter:'+name+':'+str(status))
    try:
        call('glGenTextures',1,ID)
        texid=struct.unpack('<I',ids)[0]
        if not texid:raise RuntimeError('texture_id')
        call('glBindTexture',0xde1,texid)
        call('glPixelStorei',0xcf5,1)
        struct.pack_into('<5Q',stack,40,h,0,0x1908,0x1401,BASE)
        call('glTexImage2D',0xde1,0,0x1908,w)
        call('glEnable',0xde1)
        ow=C.c_uint();oh=C.c_uint()
        ptr=lib.mxb_tex_current_rgba(texture,C.byref(ow),C.byref(oh))
        if not ptr or (ow.value,oh.value)!=(w,h) or lib.mxb_tex_storage_bytes(texture)!=len(rgba):
            raise RuntimeError('texture_storage_mismatch')
        actual=C.string_at(ptr,len(rgba))
        if actual!=rgba:raise RuntimeError('texture_pixel_mismatch')
        call('glDeleteTextures',1,ID)
        if lib.mxb_tex_storage_bytes(texture)!=0:raise RuntimeError('texture_release')
        return {'width':w,'height':h,'rgba_bytes':len(actual),
                'rgba_sha256':hashlib.sha256(actual).hexdigest(),
                'native_texture_upload_verified':True,'original_game_frame':False}
    finally:
        lib.mxb_tex_destroy(texture)
        # Windows holds loaded DLL files open; release the temporary test DLL.
        if os.name=='nt':
            import _ctypes
            _ctypes.FreeLibrary(lib._handle)


def probe(archive,library,max_images=4):
    if not 1<=max_images<=16:raise ValueError('invalid_probe_budget')
    samples=[];rejected=0
    with zipfile.ZipFile(archive) as z:
        entries=index(z)
        candidates=[item for name,item in entries.items() if name.endswith('.tga')
                    and 18<=item.file_size<=MAX_INPUT]
        for item in sorted(candidates,key=lambda i:i.file_size):
            if len(samples)>=max_images:break
            # Bound total candidate attempts even if a format is unsupported.
            if rejected>=64:break
            try:w,h,rgba=decode_tga(z.read(item))
            except (ValueError,zipfile.BadZipFile):rejected+=1;continue
            samples.append(upload(library,w,h,rgba))
    return {'candidates':len(candidates),'rejected':rejected,
            'uploads':samples,'original_engine_calls_verified':False}
