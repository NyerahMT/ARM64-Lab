#!/usr/bin/env python3
"""Execute a SYNTHETIC Win64 OpenGL guest CALL chain into native renderer C.

This validates actual guest XMM state, guest CALL stack alignment, real RET
instruction return handling, Win64 -> host ABI decoding and produced vertices.
Not one instruction or asset is from the commercial MX Bikes executable.
"""
from __future__ import annotations
import ctypes as C
from pathlib import Path
import subprocess
import tempfile

from unicorn import UC_ARCH_X86,UC_HOOK_CODE,UC_MODE_64,Uc
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,
    UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3
)

ROOT=Path(__file__).resolve().parents[1]
BASE=0x10000000
STUBS=0x11000000
STACK=0x710000000
ENTRY_SP=STACK+0x8008
SENTINEL=0x12000000
LOW_MASK=(1<<64)-1

ASM=r"""
.intel_syntax noprefix
.section .text
.global guest_entry
guest_entry:
 push rbp
 mov rbp, rsp
 sub rsp, 32
 mov ecx, 4
 movabs rax, 0x11000000
 call rax

 lea rax, [rip + test_color]
 movss xmm0, dword ptr [rax]
 movss xmm1, dword ptr [rax+4]
 movss xmm2, dword ptr [rax+8]
 movss xmm3, dword ptr [rax+12]
 movabs rax, 0x11000010
 call rax

 lea rbx, [rip + vertices]
 movss xmm0, dword ptr [rbx]
 movss xmm1, dword ptr [rbx+4]
 movss xmm2, dword ptr [rbx+8]
 movabs rax, 0x11000020
 call rax

 movss xmm0, dword ptr [rbx+12]
 movss xmm1, dword ptr [rbx+16]
 movss xmm2, dword ptr [rbx+20]
 movabs rax, 0x11000020
 call rax

 movss xmm0, dword ptr [rbx+24]
 movss xmm1, dword ptr [rbx+28]
 movss xmm2, dword ptr [rbx+32]
 movabs rax, 0x11000020
 call rax

 movabs rax, 0x11000030
 call rax
 add rsp, 32
 pop rbp
 ret

.balign 4
test_color:
.float 1.0, 0.25, 0.10, 1.0
vertices:
.float -0.65, -0.6, 0.0
.float 0.65, -0.6, 0.0
.float 0.0, 0.7, 0.0
"""

class Win64(C.Structure):
    _fields_=[("rcx",C.c_uint64),("rsp",C.c_uint64),
              ("xmm_low64",C.c_uint64*4),
              ("rdx",C.c_uint64),("r8",C.c_uint64),("r9",C.c_uint64)]

class Vertex(C.Structure):
    _fields_=[("position",C.c_float*4),("color",C.c_float*4),("uv",C.c_float*2)]

def run():
    with tempfile.TemporaryDirectory(prefix="mxb-synthetic-win64-gl-") as td:
        dst=Path(td)
        (dst/"guest.s").write_text(ASM)
        subprocess.run(["cc","-c",str(dst/"guest.s"),"-o",str(dst/"guest.o")],
                       check=True,capture_output=True)
        subprocess.run(["objcopy","-O","binary","-j",".text",
                        str(dst/"guest.o"),str(dst/"guest.bin")],
                       check=True,capture_output=True)
        subprocess.run([
            "cc","-O2","-std=c11","-Wall","-Wextra","-Werror",
            "-fPIC","-shared","-I"+str(ROOT/"runtime"),
            str(ROOT/"runtime/mxb_gl_surface.c"),
            str(ROOT/"runtime/mxb_gl_win64_abi.c"),
            "-o",str(dst/"libguestgl.so")],
            check=True,capture_output=True)
        guest_code=(dst/"guest.bin").read_bytes()
        lib=C.CDLL(str(dst/"libguestgl.so"))
        lib.mxb_gl_create.restype=C.c_void_p
        lib.mxb_gl_destroy.argtypes=[C.c_void_p]
        lib.mxb_gl_vertex_count.argtypes=[C.c_void_p]
        lib.mxb_gl_vertex_count.restype=C.c_size_t
        lib.mxb_gl_vertices.argtypes=[C.c_void_p]
        lib.mxb_gl_vertices.restype=C.POINTER(Vertex)
        lib.mxb_gl_dispatch_win64.argtypes=[
            C.c_void_p,C.c_char_p,C.c_char_p,C.POINTER(Win64),
            C.c_void_p,C.c_void_p
        ]
        lib.mxb_gl_dispatch_win64.restype=C.c_int
        surface=lib.mxb_gl_create()
        if not surface:
            raise AssertionError("Native GL context allocation failed")
        try:
            emu=Uc(UC_ARCH_X86,UC_MODE_64)
            emu.mem_map(BASE,0x20000)
            emu.mem_write(BASE,guest_code)
            emu.mem_map(STUBS,0x1000)
            for i in range(4):
                emu.mem_write(STUBS+0x10*i,b"\xc3")  # genuine x64 RET
            emu.mem_map(STACK,0x10000)
            emu.mem_write(ENTRY_SP,SENTINEL.to_bytes(8,"little"))
            emu.reg_write(UC_X86_REG_RIP,BASE)
            emu.reg_write(UC_X86_REG_RSP,ENTRY_SP)
            symbol_by_pc={
                STUBS:b"glBegin",
                STUBS+0x10:b"glColor4f",
                STUBS+0x20:b"glVertex3f",
                STUBS+0x30:b"glEnd",
            }
            xmm_regs=(UC_X86_REG_XMM0,UC_X86_REG_XMM1,
                      UC_X86_REG_XMM2,UC_X86_REG_XMM3)
            observed=[]
            def at_import(cpu,pc,size,user):
                sym=symbol_by_pc.get(pc)
                if sym is None:return
                regs=Win64()
                regs.rcx=cpu.reg_read(UC_X86_REG_RCX)
                regs.rsp=cpu.reg_read(UC_X86_REG_RSP)
                regs.xmm_low64[:]=[(cpu.reg_read(r)&LOW_MASK) for r in xmm_regs]
                if regs.rsp%16!=8:
                    raise AssertionError("Real guest Win64 callee stack misaligned")
                status=lib.mxb_gl_dispatch_win64(
                    surface,b"OPENGL32.dll",sym,C.byref(regs),None,None)
                if status!=0:
                    raise AssertionError(f"Guest import {sym!r} refused: {status}")
                observed.append(sym.decode())
            emu.hook_add(UC_HOOK_CODE,at_import)
            emu.emu_start(BASE,SENTINEL,timeout=3_000_000,count=400)
            if emu.reg_read(UC_X86_REG_RIP)!=SENTINEL:
                raise AssertionError("Guest synthetic x64 code did not RET")
            if emu.reg_read(UC_X86_REG_RSP)!=ENTRY_SP+8:
                raise AssertionError("Win64 CALL/RET stack restore mismatch")
            if observed!=["glBegin","glColor4f"]+["glVertex3f"]*3+["glEnd"]:
                raise AssertionError(f"Unexpected genuine guest import order: {observed}")
            if lib.mxb_gl_vertex_count(surface)!=3:
                raise AssertionError("Native renderer did not emit guest's triangle")
            v=lib.mxb_gl_vertices(surface)
            if not (abs(v[0].position[0]+.65)<.001 and
                    abs(v[1].position[0]-.65)<.001 and
                    abs(v[2].position[1]-.7)<.001 and
                    abs(v[0].color[0]-1.0)<.001 and
                    abs(v[0].color[1]-.25)<.001):
                raise AssertionError("Decoded x64 XMM vertices/color do not match")
            print("PASS: six actual synthetic x64 CALL/RET import events -> "
                  "native C guest ABI adapter -> three vertices")
            print("NO original game code, Steam, authorization or real game frame executed")
        finally:
            lib.mxb_gl_destroy(surface)

if __name__=="__main__":
    run()
