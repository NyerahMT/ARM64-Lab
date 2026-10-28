#!/usr/bin/env python3
"""Run actual SYNTHETIC Win64 x64 client-array instructions against native C.

The guest executes real CALL/RET and passes owned test vertex/index memory.
No original MX Bikes game, Steamworks API, original game assets or DRM.
"""
import ctypes as C
from pathlib import Path
import subprocess
import tempfile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_XMM0,
 UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3)

ROOT=Path(__file__).resolve().parents[1]
BASE=0x10000000
STUBS=0x11000000
STACK=0x710000000
SP=STACK+0x8008
SENTINEL=0x12000000
GL_FLOAT=0x1406
GL_UBYTE=0x1401
GL_USHORT=0x1403
GL_TRIANGLES=4

ASM=r"""
.intel_syntax noprefix
.section .text
.global guest_entry
guest_entry:
 push rbp
 mov rbp,rsp
 sub rsp,32
 mov ecx,3
 mov edx,0x1406
 mov r8d,12
 lea r9,[rip+vertices]
 movabs rax,0x11000000
 call rax

 mov ecx,4
 mov edx,0x1401
 mov r8d,4
 lea r9,[rip+colors]
 movabs rax,0x11000010
 call rax

 mov ecx,0x8074
 movabs rax,0x11000020
 call rax
 mov ecx,0x8076
 movabs rax,0x11000020
 call rax

 mov ecx,4
 mov edx,6
 mov r8d,0x1403
 lea r9,[rip+indices]
 movabs rax,0x11000030
 call rax
 add rsp,32
 pop rbp
 ret
.balign 4
vertices:
.float -0.75,-0.5,0
.float 0.75,-0.5,0
.float 0,0.75,0
colors:
.byte 255,0,0,255,0,255,0,255,0,0,255,255
indices:
.short 0,1,2,2,1,0
"""

class Win64(C.Structure):
    _fields_=[("rcx",C.c_uint64),("rsp",C.c_uint64),
              ("xmm_low64",C.c_uint64*4),
              ("rdx",C.c_uint64),("r8",C.c_uint64),("r9",C.c_uint64)]

class Vertex(C.Structure):
    _fields_=[("position",C.c_float*4),("color",C.c_float*4),("uv",C.c_float*2)]

def run():
 with tempfile.TemporaryDirectory(prefix="mx-original-import-array-fixture-") as root:
  dst=Path(root)
  (dst/"guest.s").write_text(ASM)
  subprocess.run(["cc","-c",str(dst/"guest.s"),"-o",str(dst/"guest.o")],
                 check=True,capture_output=True)
  subprocess.run(["objcopy","-O","binary","-j",".text",
                  str(dst/"guest.o"),str(dst/"guest.bin")],check=True,capture_output=True)
  subprocess.run(["cc","-O2","-std=c11","-Wall","-Wextra","-Werror",
                  "-fPIC","-shared","-I"+str(ROOT/"runtime"),
                  str(ROOT/"runtime/mxb_gl_surface.c"),
                  str(ROOT/"runtime/mxb_gl_win64_abi.c"),
                  "-o",str(dst/"renderer.so")],check=True,capture_output=True)
  lib=C.CDLL(str(dst/"renderer.so"))
  lib.mxb_gl_create.restype=C.c_void_p
  lib.mxb_gl_destroy.argtypes=[C.c_void_p]
  lib.mxb_gl_vertex_count.argtypes=[C.c_void_p]
  lib.mxb_gl_vertex_count.restype=C.c_size_t
  lib.mxb_gl_vertices.argtypes=[C.c_void_p]
  lib.mxb_gl_vertices.restype=C.POINTER(Vertex)
  lib.mxb_gl_dispatch_win64.argtypes=[
      C.c_void_p,C.c_char_p,C.c_char_p,C.POINTER(Win64),C.c_void_p,C.c_void_p
  ]
  lib.mxb_gl_dispatch_win64.restype=C.c_int
  surface=lib.mxb_gl_create()
  if not surface:raise AssertionError("No native render context")
  try:
   cpu=Uc(UC_ARCH_X86,UC_MODE_64)
   cpu.mem_map(BASE,0x20000)
   cpu.mem_write(BASE,(dst/"guest.bin").read_bytes())
   cpu.mem_map(STUBS,0x1000)
   for i in range(4):cpu.mem_write(STUBS+i*16,b"\xc3")
   cpu.mem_map(STACK,0x10000)
   cpu.mem_write(SP,SENTINEL.to_bytes(8,"little"))
   cpu.reg_write(UC_X86_REG_RIP,BASE)
   cpu.reg_write(UC_X86_REG_RSP,SP)
   imported={
    STUBS:b"glVertexPointer",
    STUBS+16:b"glColorPointer",
    STUBS+32:b"glEnableClientState",
    STUBS+48:b"glDrawElements"
   }
   READ=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
   read_count=[0]
   def read(ctx,ptr,target,length):
    if not (BASE<=ptr and ptr+length<=BASE+0x20000 and 0<length<=128):
     return 0
    try:buf=cpu.mem_read(ptr,length)
    except UcError:return 0
    C.memmove(target,bytes(buf),length)
    read_count[0]+=1
    return 1
   reader=READ(read)
   seen=[]
   xregs=(UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3)
   def on_call(u,pc,length,_):
    name=imported.get(pc)
    if name is None:return
    regs=Win64()
    regs.rcx=u.reg_read(UC_X86_REG_RCX)
    regs.rdx=u.reg_read(UC_X86_REG_RDX)
    regs.r8=u.reg_read(UC_X86_REG_R8)
    regs.r9=u.reg_read(UC_X86_REG_R9)
    regs.rsp=u.reg_read(UC_X86_REG_RSP)
    regs.xmm_low64[:]=[u.reg_read(r)&((1<<64)-1) for r in xregs]
    if regs.rsp%16!=8:raise AssertionError("Bad real guest Win64 CALL stack")
    status=lib.mxb_gl_dispatch_win64(
      surface,b"OPENGL32.dll",name,C.byref(regs),
      C.cast(reader,C.c_void_p),None)
    if status:raise AssertionError(f"Host import {name!r} blocked {status}")
    seen.append(name.decode())
   cpu.hook_add(UC_HOOK_CODE,on_call)
   cpu.emu_start(BASE,SENTINEL,timeout=3_000_000,count=400)
   if cpu.reg_read(UC_X86_REG_RIP)!=SENTINEL or cpu.reg_read(UC_X86_REG_RSP)!=SP+8:
    raise AssertionError("Guest code failed to return from real Win64 calls")
   if seen!=["glVertexPointer","glColorPointer","glEnableClientState",
             "glEnableClientState","glDrawElements"]:
    raise AssertionError(f"Original named import path did not execute: {seen}")
   if lib.mxb_gl_vertex_count(surface)!=6:raise AssertionError("No indexed output")
   vertices=lib.mxb_gl_vertices(surface)
   assert abs(vertices[0].position[0]+.75)<.001
   assert abs(vertices[1].position[0]-.75)<.001
   assert abs(vertices[3].position[1]-.75)<.001
   assert vertices[0].color[0]>.99 and vertices[0].color[1]<.01
   assert vertices[1].color[1]>.99 and vertices[2].color[2]>.99
   assert read_count[0]>=12
   print("PASS: 5 synthetic guest Win64 imported x64 CALL/RET events, "+
         "6 indexed native triangle vertices, mapped guest pointer reads:",read_count[0])
   print("Actual original game engine, assets, Steam and frame booted: NO")
  finally:lib.mxb_gl_destroy(surface)

if __name__=="__main__":run()
