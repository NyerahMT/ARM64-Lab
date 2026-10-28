#!/usr/bin/env python3
"""Execute MX Bikes' real first CRT initializer under bounded x64 emulation.

Maps original PE sections privately and injects deterministic Win32 import
return stubs in emulator memory. The initializer itself is original machine
code; Windows APIs and subsequent main/CRT startup are NOT executed. No
original code bytes, machine images or modified runtime state are exported.
"""
import collections
import json
import os
from pathlib import Path
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RIP, UC_X86_REG_RSP

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import decode_entry_wrapper

EXE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
IMAGE_BASE=0x140000000
STUB_BASE=0x600000000
STACK_BASE=0x700000000
STACK_SIZE=0x10000
MAX_IMAGE_SIZE=128*1024*1024
APIS_RECOGNIZED={
    "getsystemtimeasfiletime", "getcurrentthreadid", "getcurrentprocessid",
    "queryperformancecounter", "gettickcount",
}


def round4k(size):
    return (size+0xfff)&~0xfff


def import_slots(pe):
    imp,_=pe.directory(1)
    if not imp:
        raise ValueError("No PE import descriptor directory")
    slots=[]
    for i in range(500):
        table,stamp,fwd,name,iat=struct.unpack("<IIIII",pe.read_rva(imp+20*i,20))
        if not (table or stamp or fwd or name or iat):
            break
        lib=pe.string(name)
        for j in range(10000):
            value=struct.unpack("<Q",pe.read_rva((table or iat)+8*j,8))[0]
            if not value:
                break
            fn=("#"+str(value&0xffff)) if value>>63 else pe.string(value+2)
            slots.append((iat+8*j,lib,fn))
        else:
            raise ValueError("Excessive import slots")
    else:
        raise ValueError("Excessive descriptors")
    return slots


def emulate(executable):
    pe=PE(executable)
    meta=pe.inventory()
    if meta["sha256"]!=EXE_SHA:
        raise ValueError("Unexpected MX Bikes executable revision")
    base=int(meta["image_base"],16)
    if base!=IMAGE_BASE:
        raise ValueError("Unexpected PE preferred image base")
    entry=int(meta["entry_rva"],16)
    wrapper=decode_entry_wrapper(pe.read_rva(entry,18),entry)
    first=int(wrapper["direct_call_rva"],16)
    tail=int(wrapper["tail_jmp_rva"],16)

    pdata,length=pe.directory(3)
    unwind={begin:end for begin,end,_ in struct.iter_unpack("<III",pe.read_rva(pdata,length))
            if begin and end>begin}
    if first not in unwind or unwind[first]-first > 2048:
        raise RuntimeError("Original first-callee boundary changed")
    end_first=unwind[first]
    size=max(int(rva)+max(int(vsize),int(raw)) for _,vsize,rva,raw,_,_ in pe.sections)
    if size>MAX_IMAGE_SIZE:
        raise ValueError("PE image too large for bounded emulator")
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    uc.mem_map(IMAGE_BASE,round4k(size))
    for _name,_vsize,rva,rawsize,rawptr,_flags in pe.sections:
        if rawsize:
            uc.mem_write(IMAGE_BASE+rva,pe.b[rawptr:rawptr+rawsize])
    uc.mem_map(STUB_BASE,0x10000)
    uc.mem_map(STACK_BASE,STACK_SIZE)
    import_map={}
    slots=import_slots(pe)
    if len(slots)>2048:
        raise ValueError("Import count exceeds stub storage")
    for index,(rva,lib,fn) in enumerate(slots):
        guest_addr=STUB_BASE+index*16
        import_map[guest_addr]=(lib,fn)
        uc.mem_write(guest_addr,b"\xc3")  # injected synthetic Win64 return
        uc.mem_write(IMAGE_BASE+rva,struct.pack("<Q",guest_addr))

    calls=collections.Counter()
    trace={"original_instruction_count":0,"original_first_callee_instructions":0,
           "synthetic_windows_return_instructions":0,"global_write_count":0,
           "error":None}
    initial_rsp=STACK_BASE+STACK_SIZE-0x108
    uc.mem_write(initial_rsp,struct.pack("<Q",0x12345678))
    uc.reg_write(UC_X86_REG_RSP,initial_rsp)
    uc.reg_write(UC_X86_REG_RIP,IMAGE_BASE+entry)

    def code_hook(emu,address,insn_size,_ctx):
        if address in import_map:
            lib,name=import_map[address]
            low=name.lower()
            calls[lib+"::"+name]+=1
            trace["synthetic_windows_return_instructions"]+=1
            if low not in APIS_RECOGNIZED:
                trace["error"]="Unimplemented external stub: "+lib+"::"+name
                emu.emu_stop()
                return
            if low=="getsystemtimeasfiletime":
                ptr=emu.reg_read(UC_X86_REG_RCX)
                emu.mem_write(ptr,struct.pack("<Q",116444736012345678))
            elif low=="queryperformancecounter":
                ptr=emu.reg_read(UC_X86_REG_RCX)
                emu.mem_write(ptr,struct.pack("<Q",1234567890))
                emu.reg_write(UC_X86_REG_RAX,1)
            elif low=="getcurrentprocessid":
                emu.reg_write(UC_X86_REG_RAX,0x1234)
            elif low=="getcurrentthreadid":
                emu.reg_write(UC_X86_REG_RAX,0x5678)
            elif low=="gettickcount":
                emu.reg_write(UC_X86_REG_RAX,0x9abc)
            return

        rva=address-IMAGE_BASE
        is_wrapper=entry<=rva<entry+18
        is_first=first<=rva<end_first
        if not (is_wrapper or is_first):
            trace["error"]="Execution escaped first initializer at RVA "+hex(rva)
            emu.emu_stop()
            return
        trace["original_instruction_count"]+=1
        if is_first:
            trace["original_first_callee_instructions"]+=1

    def write_hook(emu,access,address,size,value,_ctx):
        if IMAGE_BASE<=address<IMAGE_BASE+round4k(size_image):
            trace["global_write_count"]+=1

    size_image=size
    uc.hook_add(UC_HOOK_CODE,code_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    try:
        uc.emu_start(IMAGE_BASE+entry,IMAGE_BASE+tail,timeout=2_000_000,count=5000)
    except Exception as e:
        trace["error"]=trace["error"] or (type(e).__name__+": "+str(e)[:200])
    trace["original_init_rva"]=hex(first)
    trace["original_init_interval_bytes"]=end_first-first
    trace["windows_api_stubs_called"]=dict(calls)
    trace["total_imports_mapped"]=len(slots)
    trace["tail_target_reached"]=uc.reg_read(UC_X86_REG_RIP)==IMAGE_BASE+tail
    trace["stack_pointer_restored"]=uc.reg_read(UC_X86_REG_RSP)==initial_rsp
    trace["original_win32_apis_executed"]=False
    trace["real_engine_initialized"]=False
    trace["real_tail_target_executed"]=False
    trace["original_first_initializer_executed"]=trace["original_first_callee_instructions"]>0
    if not (trace["tail_target_reached"] and trace["stack_pointer_restored"]
            and trace["original_first_initializer_executed"] and not trace["error"]):
        raise RuntimeError("Initializer emulation did not reach controlled tail: "+
                           json.dumps(trace,sort_keys=True)[:1500])
    return trace


def main():
    if len(sys.argv)!=3:
        raise SystemExit("Usage: mxbikes_first_callee_emu.py ORIGINAL_EXE REPORT_DIR")
    reports=Path(sys.argv[2]);reports.mkdir(parents=True,exist_ok=True)
    result=emulate(sys.argv[1])
    (reports/"original-crt-emulation.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes original security-cookie initializer emulation","",
           "- Original x64 initializer instructions executed: "+str(result["original_first_callee_instructions"]),
           "- Original entry-wrapper instructions executed: "+str(result["original_instruction_count"]-result["original_first_callee_instructions"]),
           "- Synthetic Windows import stubs executed: "+str(result["synthetic_windows_return_instructions"]),
           "- Original image global writes observed: "+str(result["global_write_count"]),
           "- Returned to tail transfer: "+str(result["tail_target_reached"]),
           "- Stack restored: "+str(result["stack_pointer_restored"]),
           "","## Windows calls answered with synthetic results",""]
    lines += ["- "+name+": "+str(count) for name,count in result["windows_api_stubs_called"].items()]
    lines += ["","Original Windows API code, second CRT startup target, game engine, and iOS runtime did NOT execute.",""]
    summary="\n".join(lines)
    (reports/"original-crt-emulation.md").write_text(summary)
    print(summary)


if __name__=="__main__":
    main()
