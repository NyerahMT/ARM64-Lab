#!/usr/bin/env python3
"""Run original rendering-state helpers and glyph draws into one native context.

Original PE bytes stay private. This uses explicit isolated render-cache and
font-metric fixtures, not a booted game or recovered game session.
"""
import argparse
import ctypes as C
import json
import math
from pathlib import Path
import struct
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as X
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots
from mxbikes_original_game_graphics_handoff import VerifiedGameGL
from mxbikes_isolated_original_glyph import qualify, run_case, fbits, ROOT, BASE

STUB, RETURN = 0x760000000, 0x760000f00
STACK, SP = 0x770000000, 0x770000808
CACHE = 0x780000000
CACHE_PTR, EXT_FLAG = BASE+0x5843b0, BASE+0x5847c4
WINDOWS = ((0x228820,0x228940),(0x228a20,0x228c90))
HELPERS = {"texture":0x228820,"bind":0x228a20,"blend":0x228a80,
           "alpha":0x228af0,"depth":0x228bd0,"lighting":0x228c30}
ALLOWED = {"glEnable","glDisable","glBindTexture","glBlendFunc","glAlphaFunc"}


class Batch(C.Structure):
    _fields_ = [(n,C.c_uint32) for n in
                ("first_vertex","vertex_count","depth_test","depth_write","depth_func",
                 "blend_enabled","blend_src","blend_dst","alpha_test","alpha_func")] + [
                ("alpha_ref",C.c_float)]


class StateHarness:
    def __init__(self, pe, bridge):
        self.bridge=bridge
        self.cpu=Uc(UC_ARCH_X86,UC_MODE_64)
        u=self.cpu
        d=Cs(CS_ARCH_X86,CS_MODE_64);d.detail=True
        # Verify the known cache pointer and extension flag against original
        # RIP-relative instructions, rather than accepting a guessed global.
        for rva,va in ((0x228bd4,CACHE_PTR),(0x22882a,EXT_FLAG)):
            ins=next(d.disasm(pe.read_rva(rva,7),BASE+rva,count=1))
            mem=[op for op in ins.operands if op.type==X86_OP_MEM]
            if len(mem)!=1 or ins.reg_name(mem[0].mem.base)!="rip" or ins.address+ins.size+mem[0].mem.disp!=va:
                raise ValueError("Original render-state global identity changed")
        page=BASE+0x228000
        u.mem_map(page,4096)
        for a,b in WINDOWS:
            u.mem_write(BASE+a,pe.read_rva(a,b-a))
        u.mem_protect(page,4096,UC_PROT_READ|UC_PROT_EXEC)
        u.mem_map(STUB,4096)
        u.mem_map(STACK,4096)
        u.mem_map(CACHE,4096)
        u.mem_map(CACHE_PTR&~4095,4096)
        u.mem_write(CACHE_PTR,struct.pack("<Q",CACHE))
        u.mem_write(EXT_FLAG,struct.pack("<I",0))
        u.mem_protect(CACHE_PTR&~4095,4096,UC_PROT_READ)
        # Start with authored cache values that force genuine API transitions.
        for offset,value in ((0x10,1),(0x24,1),(0x2c,0),(0x30,0),(0x50,0),(0x58,0)):
            u.mem_write(CACHE+offset,struct.pack("<I",value))
        slots={}; pages=set()
        for rva,lib,name in import_slots(pe):
            if lib.lower()!="opengl32.dll" or name not in ALLOWED:continue
            va=BASE+rva
            p=va&~4095
            if p not in pages:u.mem_map(p,4096);pages.add(p)
            target=STUB+16*len(slots)
            slots[target]=(lib,name)
            u.mem_write(target,b"\xc3")
            u.mem_write(va,struct.pack("<Q",target))
        if {n for _,n in slots.values()}!=ALLOWED:
            raise ValueError("Original render-state import inventory changed")
        for p in pages:u.mem_protect(p,4096,UC_PROT_READ)
        u.mem_protect(STUB,4096,UC_PROT_READ|UC_PROT_EXEC)
        self.calls=[]
        self.instructions=0
        def hook(cpu,pc,size,_):
            if pc in slots:
                lib,name=slots[pc]
                if not bridge(cpu,lib,name):
                    raise ValueError("Native adapter rejected original state call "+name)
                self.calls.append((name,cpu.reg_read(X.UC_X86_REG_RCX)&0xffffffff,
                                   cpu.reg_read(X.UC_X86_REG_RDX)&0xffffffff))
                return
            if not any(BASE+a<=pc and pc+size<=BASE+b for a,b in WINDOWS):
                raise ValueError("Original state helper escaped approved executable ranges")
            self.instructions+=1
        u.hook_add(UC_HOOK_CODE,hook)

    def call(self,name,arg,expected,ref=0.0):
        u=self.cpu
        prior=len(self.calls)
        u.mem_write(SP,struct.pack("<Q",RETURN))
        saved={X.UC_X86_REG_RBX:0x123456789,X.UC_X86_REG_RBP:0x76543210,
               X.UC_X86_REG_RSI:0x98989898,X.UC_X86_REG_XMM6:fbits(.75)}
        for r,v in saved.items():u.reg_write(r,v)
        u.reg_write(X.UC_X86_REG_RSP,SP)
        u.reg_write(X.UC_X86_REG_RCX,arg)
        u.reg_write(X.UC_X86_REG_XMM1,fbits(ref))
        u.emu_start(BASE+HELPERS[name],RETURN,count=256,timeout=2_000_000)
        if (u.reg_read(X.UC_X86_REG_RIP)!=RETURN or
            u.reg_read(X.UC_X86_REG_RSP)!=SP+8 or
            any(u.reg_read(r)!=v for r,v in saved.items())):
            raise ValueError("Original render-state helper did not return: "+name)
        observed=[(n,a) for n,a,b in self.calls[prior:]]
        if observed!=expected:
            raise ValueError("Unexpected original state imports for "+name+": "+str(observed))
        return u.reg_read(X.UC_X86_REG_RAX)&0xffffffff

    def cache(self,offset):
        return struct.unpack("<I",self.cpu.mem_read(CACHE+offset,4))[0]


def run(exe):
    pe=PE(exe)
    qualified=qualify(pe)
    with tempfile.TemporaryDirectory(prefix="mxb-state-native-") as folder:
        so=Path(folder)/"renderer.so"
        subprocess.run(["cc","-std=c11","-O2","-fPIC","-shared","-Wall","-Wextra","-Werror",
                        "-I"+str(ROOT/"runtime"),
                        *[str(ROOT/"runtime"/n) for n in
                          ("mxb_gl_surface.c","mxb_gl_win64_abi.c","mxb_gl_texture.c")],
                        "-lm","-o",str(so)],check=True)
        bridge=VerifiedGameGL(pe,so)
        try:
            s=StateHarness(pe,bridge)
            s.call("depth",0,[("glEnable",0xb71)])
            s.call("alpha",1,[("glEnable",0xbc0),("glAlphaFunc",0x206)],.25)
            # The real text parent issues these six state helper calls in order.
            s.call("lighting",0,[("glDisable",0xb50)])
            s.call("depth",1,[("glDisable",0xb71)])
            s.call("blend",1,[("glEnable",0xbe2),("glBlendFunc",0x302)])
            if s.calls[-1][2]!=0x303:raise ValueError("Original blend destination changed")
            s.call("alpha",0,[("glDisable",0xbc0)])
            s.call("texture",1,[("glEnable",0xde1)])
            s.call("bind",7,[("glBindTexture",0xde1)])
            if s.calls[-1][2]!=7:raise ValueError("Original texture name changed")
            s.call("bind",7,[])
            s.call("blend",1,[])
            if tuple(s.cache(x) for x in (0x10,0x24,0x2c,0x30,0x50,0x58))!=(0,1,1,0,1,7):
                raise ValueError("Original render-state cache mismatch before glyphs")
            glyph=run_case(pe,so,qualified,(65,True,-.875,.0625,4,1,.5,.5,0.0,(255,255,255,255)),
                           text=b"AB",kerning=(66,-2),renderer=bridge)
            s.call("depth",0,[("glEnable",0xb71)])
            bridge.lib.mxb_gl_batch_count.argtypes=[C.c_void_p]
            bridge.lib.mxb_gl_batch_count.restype=C.c_size_t
            bridge.lib.mxb_gl_batches.argtypes=[C.c_void_p]
            bridge.lib.mxb_gl_batches.restype=C.POINTER(Batch)
            bridge.lib.mxb_tex_enabled.argtypes=[C.c_void_p]
            bridge.lib.mxb_tex_enabled.restype=C.c_int
            batches=bridge.lib.mxb_gl_batches(bridge.surface)
            if bridge.lib.mxb_gl_batch_count(bridge.surface)!=2 or not bridge.lib.mxb_tex_enabled(bridge.textures):
                raise ValueError("Missing original glyph draw batches or texture state")
            for i in range(2):
                b=batches[i]
                if (b.first_vertex,b.vertex_count,b.depth_test,b.depth_write,b.depth_func,
                    b.blend_enabled,b.blend_src,b.blend_dst,b.alpha_test,b.alpha_func)!=(i*6,6,0,1,0x201,1,0x302,0x303,0,0x206):
                    raise ValueError("Native batch did not retain original text render state")
                if not math.isclose(b.alpha_ref,.25,abs_tol=1e-6):
                    raise ValueError("Native alpha argument lane mismatch")
            if s.cache(0x24)!=0:raise ValueError("Original depth restoration failed")
            result={"original_state_helper_instructions":s.instructions,
                    "original_state_helper_gl_calls":len(s.calls),
                    "original_glyph_instructions":glyph["original_x64_instructions"],
                    "original_glyph_gl_calls":glyph["verified_original_gl_calls"],
                    "native_glyph_vertices":glyph["native_triangle_vertices"],
                    "native_draw_batches":2,
                    "original_cache_and_native_batch_states_match":True,
                    "original_texture_name_bound":True,
                    "original_texture_pixels_loaded":False,
                    "actual_game_menu_rendered":False}
            print(json.dumps(result,indent=2))
            return result
        finally:bridge.close()


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owned-exe",type=Path,required=True)
    run(p.parse_args().owned_exe)
