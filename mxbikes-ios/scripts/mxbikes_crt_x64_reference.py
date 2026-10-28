#!/usr/bin/env python3
"""Pinned original MX Bikes CRT early-branch x64 reference fixture.

Executes the original initializer in private Unicorn x64 with a deliberately
nondefault security cookie. No Windows import or commercial bytes are exported.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_RIP, UC_X86_REG_RSP,
                                UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RDI)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
ENTRY=0x2ab954
SIZE=179
COOKIE_RVA=ENTRY+0xe6f4c
STACK=0x500000000
SP=STACK+0xff08
RETURN_PC=0x12345678

def run(executable,output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original executable SHA mismatch")
    code=pe.read_rva(ENTRY,SIZE)
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    instructions=list(md.disasm(code,ENTRY))
    if len(instructions)!=39 or sum(x.size for x in instructions)!=SIZE:
        raise RuntimeError("Unexpected first CRT instruction boundary")
    if struct.unpack("<Q",pe.read_rva(COOKIE_RVA,8))[0]!=0x2b992ddfa232:
        raise RuntimeError("Unexpected original security-cookie location")
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    maximum=max(rva+max(vsize,rawsize) for _,vsize,rva,rawsize,_,_ in pe.sections)
    if maximum>128*1024*1024:
        raise RuntimeError("Unsupported original image size")
    uc.mem_map(BASE,(maximum+4095)&~4095)
    for name,vsize,rva,rawsize,rawptr,flags in pe.sections:
        if rawsize:
            uc.mem_write(BASE+rva,pe.b[rawptr:rawptr+rawsize])
    uc.mem_map(STACK,0x10000)
    seeds=[0x0,0x1,0x100000000,0x1111111111111111,0xabcdef98765432,0xffffffff00000000,0x2b992ddfa231]
    allowed={BASE+i.address for i in instructions}
    visited=[]
    writes=[]
    def on_code(emu,pc,size,data):
        if pc not in allowed:
            raise RuntimeError("CRT control flow left the pinned initializer")
        visited.append(pc-BASE)
    def on_write(emu,access,addr,size,value,data):
        if size!=8:
            raise RuntimeError("Unexpected x64 write width")
        writes.append((addr,value & 0xffffffffffffffff))
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE,on_write)
    cases=[]
    for seed in seeds:
        uc.mem_write(BASE+COOKIE_RVA,struct.pack("<Q",seed))
        uc.mem_write(BASE+COOKIE_RVA+8,struct.pack("<Q",0))
        uc.mem_write(SP,struct.pack("<Q",RETURN_PC))
        uc.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
        uc.reg_write(UC_X86_REG_RSP,SP)
        uc.reg_write(UC_X86_REG_RAX,0)
        uc.reg_write(UC_X86_REG_RBX,0)
        uc.reg_write(UC_X86_REG_RDI,0)
        visited.clear()
        writes.clear()
        uc.emu_start(BASE+ENTRY,RETURN_PC,timeout=2_000_000,count=100)
        cookie=struct.unpack("<Q",uc.mem_read(BASE+COOKIE_RVA,8))[0]
        complement=struct.unpack("<Q",uc.mem_read(BASE+COOKIE_RVA+8,8))[0]
        good=(len(visited)==15 and len(writes)==4 and cookie==seed
              and complement==((~seed)&0xffffffffffffffff)
              and uc.reg_read(UC_X86_REG_RBX)==0
              and uc.reg_read(UC_X86_REG_RDI)==0
              and uc.reg_read(UC_X86_REG_RIP)==RETURN_PC
              and uc.reg_read(UC_X86_REG_RSP)==SP+8)
        if not good:
            raise RuntimeError("Original CRT early-path reference mismatch for seed "+hex(seed))
        cases.append({"seed":seed,"complement":complement,
                      "instructions_executed":len(visited),"memory_writes":len(writes)})
    result={
        "original_x64_executed":True,
        "initializer_rva":hex(ENTRY),
        "source_instructions_decoded":39,
        "case_count":len(cases),
        "fixture_cookies":seeds,
        "dynamic_instruction_count_per_case":15,
        "guest_64bit_memory_write_count_per_case":4,
        "all_cases_passed":True,
        "import_calls_executed":0,
        "cases":cases,
        "window_api_branch_executed":False,
    }
    output.mkdir(parents=True,exist_ok=True)
    (output/"crt-x64-reference.json").write_text(json.dumps(result,indent=2)+"\n")
    print("PASS original CRT x64 early branch: "+str(len(cases))+
          " cookie fixtures, 15 instructions and 4 writes each; return PC/SP verified")

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: script.py /private/exe REPORT_DIR")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
