#!/usr/bin/env python3
"""Bitwise differential tests for THREE genuine MX Bikes SSE functions.

Require exact unwind intervals, strict instruction-to-C automatic translation,
x64 original-code execution, native host execution and AArch64 ELF execution.
All original bytes and generated native C/objects remain private and ephemeral.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_ARCH_ARM64, UC_MODE_64, UC_MODE_ARM
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8
from unicorn.arm64_const import UC_ARM64_REG_PC,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2
from elftools.elf.elffile import ELFFile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_sse_lift import lift

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
FUNCTIONS={0x266d80:0x266e15,0x266e20:0x266ea6,0x266eb0:0x266f36}
# 35 instructions x64 across first function; verify these *exact* range sizes.
CODE=0x100000; DATA=0x200000; STACK=0x300000; RETURN=0x400000
FLOATS=16
BYTES=FLOATS*4


def guest(code, a, b):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    for addr,sz in ((CODE,0x1000),(DATA,0x10000),(STACK,0x10000),(RETURN,0x1000)):
        uc.mem_map(addr,sz)
    uc.mem_write(CODE,code)
    uc.mem_write(DATA+0x1000,struct.pack("<16f",*a))
    uc.mem_write(DATA+0x2000,struct.pack("<16f",*b))
    rsp=STACK+0x8008
    uc.mem_write(rsp,struct.pack("<Q",RETURN))
    uc.reg_write(UC_X86_REG_RIP,CODE)
    uc.reg_write(UC_X86_REG_RSP,rsp)
    uc.reg_write(UC_X86_REG_RCX,DATA)
    uc.reg_write(UC_X86_REG_RDX,DATA+0x1000)
    uc.reg_write(UC_X86_REG_R8,DATA+0x2000)
    uc.emu_start(CODE,RETURN,timeout=1_000_000,count=200)
    if uc.reg_read(UC_X86_REG_RIP)!=RETURN or uc.reg_read(UC_X86_REG_RSP)!=rsp+8:
        raise RuntimeError("Original x64 function did not return with correct Win64 stack")
    return bytes(uc.mem_read(DATA,BYTES))


def arm64(code,entry,a,b):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for addr,sz in ((CODE,0x1000),(DATA,0x10000),(STACK,0x10000),(RETURN,0x1000)):
        uc.mem_map(addr,sz)
    uc.mem_write(CODE,code)
    uc.mem_write(DATA+0x1000,struct.pack("<16f",*a))
    uc.mem_write(DATA+0x2000,struct.pack("<16f",*b))
    uc.reg_write(UC_ARM64_REG_PC,CODE+entry)
    uc.reg_write(UC_ARM64_REG_LR,RETURN)
    uc.reg_write(UC_ARM64_REG_SP,STACK+0x8000)
    uc.reg_write(UC_ARM64_REG_X0,DATA)
    uc.reg_write(UC_ARM64_REG_X1,DATA+0x1000)
    uc.reg_write(UC_ARM64_REG_X2,DATA+0x2000)
    uc.emu_start(CODE+entry,RETURN,timeout=1_000_000,count=250)
    if uc.reg_read(UC_ARM64_REG_PC)!=RETURN:
        raise RuntimeError("AArch64 generated function failed to return")
    return bytes(uc.mem_read(DATA,BYTES))


def arm_object(path):
    with path.open("rb") as fp:
        elf=ELFFile(fp)
        if elf["e_machine"]!="EM_AARCH64":
            raise RuntimeError("Compiled native object is not AArch64")
        sec=elf.get_section_by_name(".text")
        symtab=elf.get_section_by_name(".symtab")
        if sec is None or symtab is None:raise RuntimeError("No native code symbols")
        sym=symtab.get_symbol_by_name("lifted")
        if not sym or len(sym)!=1:raise RuntimeError("No standalone generated function")
        reloc=elf.get_section_by_name(".rela.text")
        if reloc and list(reloc.iter_relocations()):
            raise RuntimeError("Unresolved native code relocations")
        start=int(sym[0]["st_value"]);length=int(sym[0]["st_size"])
        data=sec.data()
        if not (0<length and start+length<=len(data)<=4096):
            raise RuntimeError("Invalid generated native function extent")
        return data,start,length


def main():
    if len(sys.argv)!=3:raise SystemExit("usage: python mxbikes_batch_sse_differential.py game.exe report_dir")
    p=Path(sys.argv[1])
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    pe=PE(p)
    if pe.inventory()["sha256"]!=SHA:raise RuntimeError("Unexpected original executable")
    exc,sz=pe.directory(3)
    starts={b:e for b,e,u in struct.iter_unpack("<III",pe.read_rva(exc,sz)) if b in FUNCTIONS}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    rng=random.Random(55262026)
    zero=(0.,)*FLOATS
    unit_a=(1.,0.,0.)+(0.,)*(FLOATS-3)
    unit_b=(0.,1.,0.)+(0.,)*(FLOATS-3)
    samples=[(zero,zero),(unit_a,unit_b),
             (tuple(float(x) for x in range(FLOATS)),tuple(float(-x) for x in range(FLOATS)))]
    samples.extend(
        (tuple(rng.uniform(-32.,32.) for _ in range(FLOATS)),
         tuple(rng.uniform(-32.,32.) for _ in range(FLOATS)))
        for _ in range(197))
    count=len(samples)
    results=[]
    scratch=out.parent/"mxbikes-sse-differential-private"
    scratch.mkdir(exist_ok=True)
    for begin,end in FUNCTIONS.items():
        if starts.get(begin)!=end:
            raise RuntimeError(f"Unwind interval changed for {begin:#x}: {starts.get(begin)} != {end}")
        body=pe.read_rva(begin,end-begin)
        inst=list(decoder.disasm(body,begin))
        if not inst or sum(i.size for i in inst)!=len(body):
            raise RuntimeError("Function's original x64 body incomplete")
        generated,translated=lift(body,begin)
        if translated!=len(inst):raise RuntimeError("Lifter skipped original instructions")
        temp=scratch/f"{begin:x}"
        temp.mkdir(exist_ok=True)
        source=temp/"original-function-derived.c"
        source.write_text(generated)
        so=temp/"generated-host.so"
        obj=temp/"generated-aarch64.o"
        common=["clang","-O2","-ffp-contract=off","-fno-fast-math"]
        subprocess.run(common+["-shared","-fPIC",str(source),"-o",str(so)],check=True)
        subprocess.run(common+["--target=aarch64-unknown-linux-gnu","-ffreestanding","-c",str(source),"-o",str(obj)],check=True)
        elf,entry,arm_size=arm_object(obj)
        host=ctypes.CDLL(str(so))
        fn=host.lifted
        fptr=ctypes.POINTER(ctypes.c_float)
        fn.argtypes=[fptr,fptr,fptr]
        fn.restype=None
        Array=ctypes.c_float*FLOATS
        host_mismatch=0
        arm_mismatch=0
        for index,(a,b) in enumerate(samples):
            va,vb=Array(*a),Array(*b)
            ref=guest(body,a,b)
            output=Array(*zero)
            fn(output,va,vb)
            host_bytes=ctypes.string_at(ctypes.addressof(output),BYTES)
            arm_bytes=arm64(elf,entry,a,b)
            if host_bytes!=ref:host_mismatch+=1
            if arm_bytes!=ref:arm_mismatch+=1
            if host_mismatch or arm_mismatch:
                raise AssertionError(f"Mismatch in original {begin:#x} at test {index}; host={host_mismatch}, aarch64={arm_mismatch}")
        results.append({
            "start_rva":hex(begin),"end_rva":hex(end),
            "bytes":len(body),"original_instruction_count":len(inst),
            "generated_arm64_function_bytes":arm_size,
            "differential_cases":count,
            "original_x64_emulated":True,
            "native_generated_c_executed":True,
            "generated_arm64_executed":True,
            "bitwise_host_mismatches":host_mismatch,
            "bitwise_arm64_mismatches":arm_mismatch,
            "original_body_sha256":hashlib.sha256(body).hexdigest()
        })
    report={
        "verified_original_function_count":len(results),
        "test_cases_per_function":count,
        "results":results,
        "original_game_code_exported":False,
        "native_ios_executed":False,
        "entire_game_recompiled":False,
        "note":"Original unwind-backed branch-free SSE functions automatically lifted into isolated native C and ARM64 objects; this does not cover control flow, game startup, graphics, or iOS."
    }
    (out/"batch-sse-differential.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes verified original full-function batch differential","",
           f"- Original complete unwind intervals tested: {len(results)}",
           f"- Bitwise x64 vs ARM64 test cases per function: {count}",""]
    for rec in results:
        lines.append(f"- {rec['start_rva']}: {rec['original_instruction_count']} x64 instructions, {rec['differential_cases']} test cases, **{rec['bitwise_arm64_mismatches']} ARM64 mismatches**, {rec['generated_arm64_function_bytes']} ARM64 code bytes")
    lines += ["","Real original game functions, automatically generated translations; private inputs and C code not redistributed.","",
              "**No branches or Windows imports in these math routines; no iOS game or original startup path executed on ARM64.**",""]
    md="\n".join(lines)
    (out/"batch-sse-differential.md").write_text(md)
    print(md)

if __name__=="__main__":main()
