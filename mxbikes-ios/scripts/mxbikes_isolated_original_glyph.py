#!/usr/bin/env python3
"""Run an isolated ORIGINAL MX Bikes glyph draw fragment into native C.

The PE is SHA-pinned and remains private. Only the known chained unwind
fragment and its OpenGL import slots are mapped. All caller-side state is
explicitly authored test input, not a recovered game session. No startup,
Steam, entitlement, or game asset is executed or simulated here.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as X

from mxbikes_first_callee_emu import import_slots
from mxbikes_original_game_graphics_handoff import VerifiedGameGL
from mxbikes_whole_game_map import INPUT_SHA
from tools.pe_probe import PE

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x140000000
FIRST, END, PARENT = 0x2098A5, 0x209B4E, 0x2097E0
MATCH, MATCH_END = 0x209BB4, 0x209BBC
STUB = 0x750000000
STACK, SP = 0x720000000, 0x720000800
OBJECT, TEXT = 0x730000000, 0x740000000
EXPECTED = ["glBegin"] + ["glColor4ubv", "glTexCoord2fv", "glVertex3fv"] * 4 + ["glEnd"]


class Vertex(C.Structure):
    _fields_ = [("position", C.c_float * 4), ("color", C.c_float * 4),
                ("uv", C.c_float * 2)]


def qualify(pe):
    if hashlib.sha256(pe.b).hexdigest() != INPUT_SHA:
        raise ValueError("Original executable SHA mismatch")
    pd, n = pe.directory(3)
    if not pd or n % 12 or n > 8 * 1024 * 1024:
        raise ValueError("Invalid unwind directory")
    records = [r for r in struct.iter_unpack("<III", pe.read_rva(pd, n))
               if r[:2] == (FIRST, END)]
    if len(records) != 1:
        raise ValueError("Original glyph fragment boundary changed")
    unwind = records[0][2]
    header = pe.read_rva(unwind, 4)
    if header[0] & 7 != 1 or not (header[0] >> 3 & 4):
        raise ValueError("Expected chained unwind fragment, not function entry")
    chain = struct.unpack("<III", pe.read_rva(unwind + 4 + ((header[2] + 1) & ~1) * 2, 12))
    if chain[:2] != (PARENT, FIRST):
        raise ValueError("Original parent fragment changed")
    d = Cs(CS_ARCH_X86, CS_MODE_64)
    d.detail = True
    code = pe.read_rva(FIRST, END-FIRST)
    rows = list(d.disasm(code, BASE+FIRST))
    if sum(i.size for i in rows) != len(code):
        raise ValueError("Incomplete original fragment decode")
    slots = {r: (lib, name) for r, lib, name in import_slots(pe)}
    calls = []
    for ins in rows:
        if ins.mnemonic != "call":
            continue
        if len(ins.operands) != 1 or ins.size != 6:
            raise ValueError("Unexpected original call form")
        op = ins.operands[0]
        if op.type != X86_OP_MEM or ins.reg_name(op.mem.base) != "rip" or op.mem.index:
            raise ValueError("Unexpected indirect call")
        rva = ins.address + ins.size + op.mem.disp - BASE
        lib, name = slots.get(rva, ("", ""))
        if lib.lower() != "opengl32.dll":
            raise ValueError("Non-graphics import in isolated fragment")
        calls.append((rva, lib, name))
    if [n for _, _, n in calls] != EXPECTED:
        raise ValueError("Original glyph OpenGL call sequence changed")
    match = pe.read_rva(MATCH,MATCH_END-MATCH)
    match_rows = list(d.disasm(match,BASE+MATCH))
    if (len(match_rows)!=2 or sum(i.size for i in match_rows)!=len(match)
        or match_rows[0].mnemonic!="mov" or match_rows[0].op_str!="eax, dword ptr [rdx + 4]"
        or match_rows[1].mnemonic!="jmp" or match_rows[1].operands[0].imm!=BASE+0x209B10):
        raise ValueError("Original matched kerning successor changed")
    return (code,match), {i.address for i in rows+match_rows}, calls


def map_code(uc, code, calls):
    page = (BASE+FIRST) & ~4095
    length = ((BASE+END+4095) & ~4095) - page
    uc.mem_map(page, length)
    uc.mem_write(BASE+FIRST, code[0])
    uc.mem_write(BASE+MATCH, code[1])
    uc.mem_protect(page, length, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(STUB, 4096)
    targets = {}
    pages = set()
    for slot, lib, name in calls:
        va = BASE+slot
        if va & ~4095 not in pages:
            uc.mem_map(va & ~4095, 4096)
            pages.add(va & ~4095)
        key = (lib, name)
        if key not in targets:
            address = STUB+16*len(targets)
            targets[key] = address
            uc.mem_write(address, b"\xc3")
        uc.mem_write(va, struct.pack("<Q", targets[key]))
    for p in pages:
        uc.mem_protect(p, 4096, UC_PROT_READ)
    uc.mem_protect(STUB, 4096, UC_PROT_READ | UC_PROT_EXEC)
    return {v:k for k,v in targets.items()}


def fbits(f):
    return struct.unpack("<I", struct.pack("<f", f))[0]


def run_case(pe, so, qualified, fixture, *, text=None, disabled=(), kerning_probe=False, kerning=None):
    """Execute the genuine loop with explicit caller fixtures; no patched guest instructions."""
    code, valid_pcs, calls = qualified
    glyph, enabled, origin, scale, width, offset, top, height, z, rgba = fixture
    text = bytes([glyph]) if text is None else bytes(text)
    if not 1 <= len(text) <= 32:
        raise ValueError("Isolated text fixture exceeds budget")
    disabled = set(disabled) | ({glyph} if not enabled else set())
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    targets = map_code(u, code, calls)
    u.mem_map(STACK, 4096)
    u.mem_map(OBJECT, 0x6000)
    u.mem_map(TEXT, 4096)
    u.mem_write(TEXT, text)
    uv = [(0.125,0.25),(0.125,0.75),(0.875,0.75),(0.875,0.25)]
    if kerning is not None:
        key, adjust = kerning
        if not -128<=key<=127 or not -16<=adjust<=16:
            raise ValueError("Kerning fixture outside bounded signed range")
        kerning_probe = True
    else:
        key, adjust = 127,9
    for index in set(text):
        item = OBJECT + 72*index
        u.mem_write(item+0x210, struct.pack("<4i", int(index not in disabled), offset, width, 1))
        for (a,b),(s,t) in zip(((0x230,0x240),(0x23c,0x24c),(0x238,0x248),(0x234,0x244)),uv):
            u.mem_write(item+a, struct.pack("<f",s))
            u.mem_write(item+b, struct.pack("<f",t))
        u.mem_write(item+0x250, struct.pack("<2i",0,int(kerning_probe)))
    # Explicit caller-owned test record; the original comparison and adjustment execute.
    u.mem_write(OBJECT+0x4a30,struct.pack("<Q",OBJECT+0x5000))
    u.mem_write(OBJECT+0x5000,struct.pack("<2i",key,adjust))
    u.mem_write(SP+0x120, struct.pack("<f",1.0))
    u.mem_write(SP+0x128, bytes(rgba))
    saved = {X.UC_X86_REG_RBP:0x123456789, X.UC_X86_REG_XMM6:fbits(11.0),
             X.UC_X86_REG_XMM7:fbits(12.0), X.UC_X86_REG_XMM13:fbits(13.0)}
    registers = {X.UC_X86_REG_RBX:OBJECT, X.UC_X86_REG_RSI:TEXT,
                 X.UC_X86_REG_R13:0, X.UC_X86_REG_R14:TEXT+len(text),
                 X.UC_X86_REG_R12:0, X.UC_X86_REG_R15:len(text), X.UC_X86_REG_RSP:SP,
                 X.UC_X86_REG_XMM8:fbits(origin), X.UC_X86_REG_XMM9:fbits(scale),
                 X.UC_X86_REG_XMM10:fbits(height), X.UC_X86_REG_XMM11:fbits(z),
                 X.UC_X86_REG_XMM12:fbits(top), **saved}
    for reg,value in registers.items():
        u.reg_write(reg,value)
    bridge = VerifiedGameGL(pe,so)
    bridge.lib.mxb_gl_vertices.argtypes = [C.c_void_p]
    bridge.lib.mxb_gl_vertices.restype = C.POINTER(Vertex)
    instructions = 0
    names = []
    expected_names = EXPECTED * sum(index not in disabled for index in text)
    visited = set()
    def hook(cpu, pc, size, _):
        nonlocal instructions
        if pc in targets:
            lib,name = targets[pc]
            if len(names) >= len(expected_names) or name != expected_names[len(names)]:
                raise ValueError("Unexpected original dynamic GL sequence")
            if not bridge(cpu,lib,name):
                raise ValueError("Native adapter rejected verified GL import " + name)
            names.append(name)
            return
        if pc not in valid_pcs:
            raise ValueError("Execution escaped the isolated original fragment")
        instructions += 1
        visited.add(pc-BASE)
    try:
        u.hook_add(UC_HOOK_CODE,hook)
        u.emu_start(BASE+FIRST,BASE+END,count=512*len(text),timeout=2_000_000)
        if (u.reg_read(X.UC_X86_REG_RIP) != BASE+END or
            u.reg_read(X.UC_X86_REG_RSP) != SP or
            u.reg_read(X.UC_X86_REG_RSI) != TEXT+len(text) or
            u.reg_read(X.UC_X86_REG_R12) != len(text) or
            any(u.reg_read(r)!=v for r,v in saved.items())):
            raise ValueError("Original fragment did not reach exact continuation with restored state")
        result = bridge.summary()
        count = result["actual_original_game_vertex_count"]
        if names != expected_names or count != 6*sum(index not in disabled for index in text):
            raise ValueError("Unexpected original glyph draw count")
        if result["verified_opengl_import_failure_count"] or result["unproven_opengl_import_event_count"]:
            raise ValueError("Unverified call in isolated draw")
        if kerning_probe and 0x209af2 not in visited:
            raise ValueError("Original kerning lookup was not executed")
        vertices = bridge.lib.mxb_gl_vertices(bridge.surface)
        cursor = origin
        emitted = []
        matched = False
        for ordinal,index in enumerate(text):
            if index in disabled:
                continue
            left = cursor+offset*scale
            right = left+width*scale
            corners = [(left,top,z,1),(left,top-height,z,1),
                       (right,top-height,z,1),(right,top,z,1)]
            for k in (0,1,2,0,2,3):
                expected = list(corners[k])+[v/255 for v in rgba]+list(uv[k])
                v = vertices[len(emitted)]
                actual = list(v.position)+list(v.color)+list(v.uv)
                if not all(math.isclose(a,b,rel_tol=0,abs_tol=1e-6) for a,b in zip(actual,expected)):
                    raise ValueError("Native glyph vertex mismatch at index " + str(len(emitted)))
                emitted.append({"position":list(v.position),"color":list(v.color),"uv":list(v.uv)})
            cursor = right + scale
            if kerning_probe and ordinal+1<len(text):
                next_byte = text[ordinal+1]
                signed = next_byte if next_byte<128 else next_byte-256
                if signed == key:
                    matched = True
                    cursor += adjust*scale
        if (MATCH in visited) != matched:
            raise ValueError("Original matched kerning branch differs from expected lookup")
        final_x = struct.unpack("<f",struct.pack("<I",u.reg_read(X.UC_X86_REG_XMM8)&0xffffffff))[0]
        if not math.isclose(final_x,cursor,rel_tol=0,abs_tol=1e-6):
            raise ValueError("Original final text cursor mismatch")
        return {"glyph_fixture_index":glyph,"enabled":enabled,"fixture_text":list(text),
                "disabled_fixture_indices":sorted(disabled),
                "original_x64_instructions":instructions,
                "verified_original_gl_calls":len(names),
                "native_triangle_vertices":count,
                "native_vertex_data":emitted,
                "original_final_cursor_x":final_x,
                "original_kerning_lookup_executed":0x209af2 in visited,
                "original_matched_kerning_executed":MATCH in visited,
                "all_vertex_attributes_match":True,
                "exact_fragment_continuation":True}
    finally:
        bridge.close()

def run(exe):
    pe = PE(exe)
    qualified = qualify(pe)
    fixtures = [
        (0,True,-0.75,0.25,4,1,0.5,1.0,0.125,(64,128,192,255)),
        (65,True,-1.0,0.125,8,2,0.25,0.5,-0.25,(255,16,32,128)),
        (255,True,0.0,0.125,2,0,0.75,0.25,0.0,(0,255,128,64)),
        (65,False,-1.0,0.125,8,2,0.25,0.5,-0.25,(255,16,32,128)),
    ]
    with tempfile.TemporaryDirectory(prefix="mxb-isolated-glyph-") as folder:
        so = Path(folder)/"renderer.so"
        subprocess.run(["cc","-std=c11","-O2","-fPIC","-shared","-Wall","-Wextra","-Werror",
                        "-I"+str(ROOT/"runtime"),
                        *[str(ROOT/"runtime"/n) for n in
                          ("mxb_gl_surface.c","mxb_gl_win64_abi.c","mxb_gl_texture.c")],
                        "-lm","-o",str(so)],check=True)
        cases = [run_case(pe,so,qualified,f) for f in fixtures]
        cases += [
            run_case(pe,so,qualified,(65,True,-0.875,0.0625,4,1,0.5,0.5,0.0,(255,255,255,255)),
                     text=b"AAA",kerning_probe=True),
            run_case(pe,so,qualified,(65,True,-0.875,0.0625,4,1,0.5,0.5,0.0,(192,128,64,255)),
                     text=b"ABA",disabled=(66,),kerning_probe=True),
            run_case(pe,so,qualified,(65,True,-0.875,0.0625,4,1,0.5,0.5,0.0,(64,128,192,255)),
                     text=b"ABBA",disabled=(65,66)),
            run_case(pe,so,qualified,(65,True,-0.875,0.0625,4,1,0.5,0.5,0.0,(255,255,255,255)),
                     text=b"AB",kerning=(66,-2)),
            run_case(pe,so,qualified,(65,True,-0.875,0.0625,4,1,0.5,0.5,0.0,(255,255,255,255)),
                     text=bytes([65,255]),kerning=(-1,3)),
        ]
    report = {"mode":"isolated_original_glyph_fragment_with_authored_caller_state",
              "cases":cases,"original_gl_calls":sum(r["verified_original_gl_calls"] for r in cases),
              "native_vertices":sum(r["native_triangle_vertices"] for r in cases),
              "game_startup_executed":False,"steam_initialized":False,
              "actual_game_menu_rendered":False,"original_game_assets_used":False}
    print(json.dumps(report,indent=2))
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owned-exe",type=Path,required=True)
    run(p.parse_args().owned_exe)
