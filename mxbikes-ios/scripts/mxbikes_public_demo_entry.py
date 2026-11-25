#!/usr/bin/env python3
"""Bounded x64 reference execution of the publisher's unmodified beta21e demo.

This does not unlock the demo, change any licensing decision, start a game
session, or translate x64 instructions to ARM64. Only basic Windows clock
and process identity APIs are modeled. Everything else stops before return.
No executable bytes, memory contents or modified binaries are emitted.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots
from mxb_gl_callsite import prove_callsite
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX

DEMO_SHA="b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742"
PAGE=4096
STACK=0x700000000
STACK_SIZE=0x100000
STUB=0x710000000
END=0x720000000
MAX_IMAGE=128*1024*1024
MAX_INSTRUCTIONS=250000
ENVIRONMENT={"getsystemtimeasfiletime","getcurrentthreadid","getcurrentprocessid",
             "queryperformancecounter","queryperformancefrequency","gettickcount","gettickcount64"}


def align(n):
    return (n+PAGE-1)&~(PAGE-1)


def execute(pe, limit=MAX_INSTRUCTIONS):
    if not 1<=limit<=MAX_INSTRUCTIONS:raise ValueError("invalid_instruction_budget")
    if hashlib.sha256(pe.b).hexdigest()!=DEMO_SHA:raise ValueError("public_demo_SHA_mismatch")
    metadata=pe.inventory()
    if any(lib.lower() in ("steam_api.dll","steam_api64.dll") for lib in metadata["imports"]):
        raise ValueError("unexpected_Steam_import")
    base=int(metadata["image_base"],16)
    entry=int(metadata["entry_rva"],16)
    image_size=pe.u32(pe.opt+56)
    header_size=pe.u32(pe.opt+60)
    if not 0<header_size<=len(pe.b) or not 0<image_size<=MAX_IMAGE or base%PAGE:
        raise ValueError("invalid_PE_mapping")
    u=Uc(UC_ARCH_X86,UC_MODE_64)
    u.mem_map(base,align(image_size),UC_PROT_READ|UC_PROT_WRITE)
    u.mem_write(base,pe.b[:header_size])
    permissions={}
    executable=[]
    writable=[]
    for _,vsize,rva,raw,off,flags in pe.sections:
        end=rva+max(vsize,raw)
        if end>image_size or raw and off+raw>len(pe.b) or rva<header_size:
            raise ValueError("invalid_PE_section")
        if raw:u.mem_write(base+rva,pe.b[off:off+raw])
        prot=0
        if flags&0x40000000:prot|=UC_PROT_READ
        if flags&0x80000000:prot|=UC_PROT_WRITE;writable.append((base+rva,base+end))
        if flags&0x20000000:prot|=UC_PROT_EXEC;executable.append((base+rva,base+rva+raw))
        for p in range(rva&~(PAGE-1),align(end),PAGE):
            permissions[p]=permissions.get(p,0)|prot
    if not any(lo<=base+entry<hi for lo,hi in executable):raise ValueError("entry_not_executable")
    slots=import_slots(pe)
    if not 0<len(slots)<=4096 or len({r for r,_,_ in slots})!=len(slots):
        raise ValueError("invalid_import_slots")
    u.mem_map(STUB,align(16*len(slots)),UC_PROT_READ|UC_PROT_WRITE)
    targets={}
    iat={rva:(lib.lower(),name) for rva,lib,name in slots}
    for i,(rva,lib,name) in enumerate(slots):
        if rva+8>image_size:raise ValueError("invalid_IAT_RVA")
        addr=STUB+16*i
        targets[addr]=(lib,name)
        u.mem_write(addr,b"\xc3")
        u.mem_write(base+rva,struct.pack("<Q",addr))
    u.mem_protect(STUB,align(16*len(slots)),UC_PROT_READ|UC_PROT_EXEC)
    for p in range(0,align(image_size),PAGE):
        prot=permissions.get(p,UC_PROT_READ)
        if prot&UC_PROT_EXEC and prot&UC_PROT_WRITE:raise ValueError("writable_executable_page")
        u.mem_protect(base+p,PAGE,prot)
    u.mem_map(STACK,STACK_SIZE,UC_PROT_READ|UC_PROT_WRITE)
    writable.append((STACK,STACK+STACK_SIZE))
    sp=STACK+STACK_SIZE-0x108
    u.mem_write(sp,struct.pack("<Q",END))
    u.reg_write(UC_X86_REG_RSP,sp)
    counts=Counter()
    visits=set()
    original=0
    stop={}
    serviced=Counter()
    recent=[]
    memory_fault={}
    def halt(status,**details):
        stop.update(status=status,**details)
        u.emu_stop()
    def write_qword(ptr,value):
        if not any(lo<=ptr and ptr+8<=hi for lo,hi in writable):
            raise ValueError("unmapped_or_read_only_output_pointer")
        u.mem_write(ptr,struct.pack("<Q",value))
    def hook(cpu,pc,size,_):
        nonlocal original
        if pc in targets:
            lib,name=targets[pc]
            low=name.lower()
            key=lib+"!"+name
            counts[key]+=1
            if lib.lower() not in ("kernel32.dll","kernelbase.dll") or low not in ENVIRONMENT:
                halt("unsupported_import",import_name=key)
                return
            if cpu.reg_read(UC_X86_REG_RSP)&15!=8:
                halt("invalid_Win64_import_stack",import_name=key)
                return
            try:
                rsp=cpu.reg_read(UC_X86_REG_RSP)
                return_va=struct.unpack("<Q",cpu.mem_read(rsp,8))[0]
                evidence=prove_callsite(pe,iat,base,cpu.mem_read,return_va,pc,lib,name)
                if evidence is None:
                    halt("unverified_environment_import_callsite",import_name=key)
                    return
                ptr=cpu.reg_read(UC_X86_REG_RCX)
                if low=="getsystemtimeasfiletime":write_qword(ptr,116444736012345678)
                elif low=="queryperformancecounter":write_qword(ptr,1234567890);cpu.reg_write(UC_X86_REG_RAX,1)
                elif low=="queryperformancefrequency":write_qword(ptr,10000000);cpu.reg_write(UC_X86_REG_RAX,1)
                else:cpu.reg_write(UC_X86_REG_RAX,{"getcurrentthreadid":0x5678,
                    "getcurrentprocessid":0x1234,"gettickcount":0x9abc,"gettickcount64":0x9abc}[low])
                serviced[key]+=1
            except (ValueError,UcError,struct.error):
                halt("rejected_environment_output",import_name=key)
            return
        if not any(lo<=pc and pc+size<=hi for lo,hi in executable):
            halt("outside_original_executable_sections")
            return
        original+=1
        visits.add(pc-base)
        recent.append(hex(pc-base))
        if len(recent)>16:del recent[0]
    def fault(cpu,access,address,size,value,_):
        pc=cpu.reg_read(UC_X86_REG_RIP)
        memory_fault.update(access=access,address=hex(address),size=size,
                            instruction_rva=hex(pc-base) if base<=pc<base+image_size else None)
        return False
    u.hook_add(UC_HOOK_CODE,hook)
    u.hook_add(UC_HOOK_MEM_INVALID,fault)
    try:u.emu_start(base+entry,END,count=limit,timeout=5_000_000)
    except UcError as exc:
        if not stop:stop.update(status="guest_emulation_fault",reason=str(exc))
    pc=u.reg_read(UC_X86_REG_RIP)
    if not stop:stop.update(status="entry_returned" if pc==END else "execution_budget_or_timeout")
    stop["original_rva"]=hex(pc-base) if base<=pc<base+image_size else None
    tls_rva,tls_size=pe.directory(9)
    return {"target":"publisher_distributed_beta21e_demo","verified_sha256":DEMO_SHA,
            "entry_rva":hex(entry),"original_x64_instruction_executions":original,
            "unique_original_instruction_addresses":len(visits),"observed_import_calls":dict(counts),
            "serviced_environment_calls":dict(serviced),
            "recent_original_instruction_rvas":recent,
            "memory_fault":memory_fault or None,
            "tls_directory_present":bool(tls_rva and tls_size),
            "tls_callbacks_executed":False,
            "stop":stop,"environment_mode":"bounded_clock_and_process_identity_only",
            "demo_restrictions_modified":False,"native_arm64_engine_executed":False,
            "actual_game_menu_rendered":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--demo-exe",type=Path,required=True)
    args=p.parse_args()
    if not args.demo_exe.is_file() or not 0<args.demo_exe.stat().st_size<=MAX_IMAGE:
        p.error("missing_or_oversized_demo")
    result=execute(PE(args.demo_exe))
    print(json.dumps(result,indent=2))
    if result["original_x64_instruction_executions"]<=0:
        raise SystemExit("No genuine demo instructions executed")


if __name__=="__main__":main()
