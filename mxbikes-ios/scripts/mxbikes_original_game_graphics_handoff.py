#!/usr/bin/env python3
"""Genuine original MX Bikes -> native C OpenGL live-import execution gate.

Unlike the viewport demo, this NEVER submits synthetic geometry.
It runs original SHA-pinned game x64 in the existing bounded CRT/startup
harness and calls the same C renderer used by the iOS application ONLY
if actual original guest instructions reach a proven original OpenGL IAT CALL.

Steamworks is NOT impersonated, licensing is NOT bypassed, and inaccessible
services fail closed. Original binaries/assets stay in the private runner.
"""
from __future__ import annotations
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from unicorn.x86_const import (
 UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
 UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM2,UC_X86_REG_XMM3
)
from mxbikes_first_callee_emu import import_slots
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_startup_fast_blocks import execute as run_original_startup
from mxbikes_main_joined_callee_native import BASE
from tools.pe_probe import PE

ROOT=Path(__file__).resolve().parents[1]
LIBRARY=b"OPENGL32.dll"
MASK=(1<<64)-1
TEXTURE_NAMES={
    "glBindTexture","glGenTextures","glDeleteTextures","glTexImage2D",
    "glTexParameteri","glPixelStorei","glEnable","glDisable"
}

class Registers(C.Structure):
    _fields_=[("rcx",C.c_uint64),("rsp",C.c_uint64),
              ("xmm_low64",C.c_uint64*4),
              ("rdx",C.c_uint64),("r8",C.c_uint64),("r9",C.c_uint64)]

class VerifiedGameGL:
    def __init__(self,pe,so):
        if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
            raise ValueError("Game identity not verified")
        self.pe=pe
        self.iat={rva:(lib.lower(),sym) for rva,lib,sym in import_slots(pe)}
        self.lib=C.CDLL(str(so))
        self.lib.mxb_gl_create.restype=C.c_void_p
        self.lib.mxb_tex_create.restype=C.c_void_p
        self.lib.mxb_gl_destroy.argtypes=[C.c_void_p]
        self.lib.mxb_tex_destroy.argtypes=[C.c_void_p]
        self.lib.mxb_gl_vertex_count.argtypes=[C.c_void_p]
        self.lib.mxb_gl_vertex_count.restype=C.c_size_t
        self.lib.mxb_gl_dispatch_win64.argtypes=[
            C.c_void_p,C.c_char_p,C.c_char_p,C.POINTER(Registers),
            C.c_void_p,C.c_void_p]
        self.lib.mxb_gl_dispatch_win64.restype=C.c_int
        self.lib.mxb_tex_dispatch_win64.argtypes=[
            C.c_void_p,C.c_char_p,C.c_char_p,C.POINTER(Registers),
            C.c_void_p,C.c_void_p,C.c_void_p]
        self.lib.mxb_tex_dispatch_win64.restype=C.c_int
        self.surface=self.lib.mxb_gl_create()
        self.textures=self.lib.mxb_tex_create()
        if not self.surface or not self.textures:
            raise RuntimeError("Could not initialize host-native renderer")
        self.confirmed_calls=[]
        self.unsupported_real_calls=[]
        self.last_source=None
        self.read_count=0
        self.write_count=0
        READ=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
        WRITE=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t)
        def read(_context,address,target,length):
            if not length or length>128:
                return 0
            try:
                raw=self.machine.mem_read(address,length)
            except Exception:
                return 0
            C.memmove(target,bytes(raw),length)
            self.read_count+=1
            return 1
        def write(_context,address,src,length):
            if not length or length>128:
                return 0
            try:
                self.machine.mem_write(address,C.string_at(src,length))
            except Exception:
                return 0
            self.write_count+=1
            return 1
        self.reader=READ(read)
        self.writer=WRITE(write)
        self.reader_ptr=C.cast(self.reader,C.c_void_p)
        self.writer_ptr=C.cast(self.writer,C.c_void_p)

    def close(self):
        if self.surface:
            self.lib.mxb_gl_destroy(self.surface)
            self.surface=None
        if self.textures:
            self.lib.mxb_tex_destroy(self.textures)
            self.textures=None

    def prove_original_callsite(self,return_va,library,symbol):
        """Prove a real 6-byte RIP-relative Win64 IAT CALL ended at return VA."""
        if not BASE+6<=return_va<BASE+len(self.pe.b)+0x100000:
            return None
        rva=return_va-BASE-6
        try:
            code=self.pe.read_rva(rva,6)
        except (ValueError,struct.error):
            return None
        if code[:2]!=b"\xff\x15":
            return None
        disp=struct.unpack_from("<i",code,2)[0]
        slot=rva+6+disp
        actual=self.iat.get(slot)
        if not actual or actual!=(library.lower(),symbol):
            return None
        return {"original_call_rva":hex(rva),"original_iat_rva":hex(slot),
                "import":library+"!"+symbol}

    def __call__(self,u,library,symbol):
        if library.lower()!="opengl32.dll":
            return False
        self.machine=u
        guest_rsp=u.reg_read(UC_X86_REG_RSP)
        if guest_rsp%16!=8:
            raise ValueError("Original guest imported CALL entry violated Win64 stack ABI")
        try:
            return_va=struct.unpack("<Q",u.mem_read(guest_rsp,8))[0]
        except Exception as exc:
            raise ValueError("Cannot inspect original x64 import return address") from exc
        evidence=self.prove_original_callsite(return_va,library,symbol)
        if evidence is None:
            raise ValueError("Import callsite is not exact SHA-verified original x64 CALL")
        regs=Registers()
        regs.rcx=u.reg_read(UC_X86_REG_RCX)
        regs.rdx=u.reg_read(UC_X86_REG_RDX)
        regs.r8=u.reg_read(UC_X86_REG_R8)
        regs.r9=u.reg_read(UC_X86_REG_R9)
        regs.rsp=guest_rsp
        for i,register in enumerate((UC_X86_REG_XMM0,UC_X86_REG_XMM1,
                                     UC_X86_REG_XMM2,UC_X86_REG_XMM3)):
            regs.xmm_low64[i]=u.reg_read(register)&MASK
        if symbol in TEXTURE_NAMES:
            status=self.lib.mxb_tex_dispatch_win64(
                self.textures,LIBRARY,symbol.encode(),C.byref(regs),
                self.reader_ptr,self.writer_ptr,None)
        else:
            status=self.lib.mxb_gl_dispatch_win64(
                self.surface,LIBRARY,symbol.encode(),C.byref(regs),
                self.reader_ptr,None)
        if status:
            self.unsupported_real_calls.append(dict(evidence,status=status))
            return False
        self.confirmed_calls.append(evidence)
        return True

    def summary(self):
        return {
            "actual_original_game_opengl_imports_dispatched":len(self.confirmed_calls),
            "original_verified_opengl_calls":self.confirmed_calls[:30],
            "genuine_guest_opengl_import_failures":self.unsupported_real_calls[:30],
            "genuine_guest_memory_reads":self.read_count,
            "genuine_guest_memory_writes":self.write_count,
            "actual_original_game_vertex_count":(
                self.lib.mxb_gl_vertex_count(self.surface) if self.surface else 0),
            "synthetic_geometry_submitted":False,
            "fake_original_game_frame_claimed":False
        }


def run(executable,dll,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("SHA of owned original game binary drifted")
    with tempfile.TemporaryDirectory(prefix="mxb-real-guest-gl-") as folder:
        lib=Path(folder)/"libmxb_real_gl.so"
        cmd=["cc","-std=c11","-O2","-fPIC","-shared",
             "-Wall","-Wextra","-Werror","-I"+str(ROOT/"runtime"),
             str(ROOT/"runtime/mxb_gl_surface.c"),
             str(ROOT/"runtime/mxb_gl_win64_abi.c"),
             str(ROOT/"runtime/mxb_gl_texture.c"),
             "-o",str(lib)]
        subprocess.run(cmd,check=True,capture_output=True)
        bridge=VerifiedGameGL(pe,lib)
        try:
            runtime=run_original_startup(executable,dll,out,graphics_handler=bridge)
            summary=bridge.summary()
        finally:
            bridge.close()
    # The engine's *actual output* is the only possible game-render signal.
    if summary["actual_original_game_opengl_imports_dispatched"] != runtime["actual_original_gl_import_events"]:
        # An original but unsupported GL call is an explicit stop, not a draw.
        if not summary["genuine_guest_opengl_import_failures"]:
            raise RuntimeError("Original GL event/provenance instrumentation diverged")
    provenance={
        "input_sha256":INPUT_SHA,
        "original_game_code_executed":runtime["original_guest_basic_block_executions"]>0,
        "guest_execution_start_rva":"0x1305c0",
        "guest_initialized_by_original_fopen_branch":True,
        "guest_uses_real_owned_steam_dll_bytes":runtime["actual_owned_file_bytes"]>0,
        "original_guest_blocks":runtime["original_guest_basic_block_executions"],
        "original_guest_instruction_estimate":runtime["estimated_original_instructions_in_completed_blocks"],
        "original_guest_import_calls":runtime["total_guest_import_calls"],
        "original_opengl_import_events":runtime["actual_original_gl_import_events"],
        "actual_original_engine_reached_gl":runtime["actual_original_gl_import_events"]>0,
        "runtime_stop":runtime["stop"],
        "host_original_import_adapter_compiled":True,
        "actual_windows_steam_client_initialized":False,
        "authored_ios_game_frame_count":0,
        "game_frame_eligible_only_from_original_provenance":True,
        **summary
    }
    out.mkdir(exist_ok=True,parents=True)
    (out/"original-game-to-metal-provenance.json").write_text(
        json.dumps(provenance,indent=2)+"\n")
    lines=["# MX Bikes: original-game-code-only rendering gate","",
           "- Verified SHA-owned original x64 code executed: **"+str(provenance["original_game_code_executed"])+"**",
           "- Original x64 basic blocks executed: **"+str(provenance["original_guest_blocks"])+"**",
           "- Completed-block instruction estimate: **"+str(provenance["original_guest_instruction_estimate"])+"**",
           "- **Original (non-fixture) OpenGL import calls: "+str(provenance["original_opengl_import_events"])+"**",
           "- Original guest graphics vertices produced: **"+str(provenance["actual_original_game_vertex_count"])+"**",
           "- Native graphics dispatcher compiled and installed: **YES**",
           "- Original Steamworks initialized: **NO**",
           "- Guest stopped at: **"+str(provenance["runtime_stop"])+"**",
           "- Actual game frame rendered on iPhone: **NO**",
           "",
           "Never confuse a fully functioning fixture renderer with actual original executable graphics.",
           "This test dispatches only original game x64 imported OpenGL CALLs with verified Win64",
           "stack return locations; no generated geometry or caller fake return state is used.",""]
    (out/"original-game-to-metal-provenance.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return provenance

if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage: original_handoff.py original.exe owned-steam.dll report_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
