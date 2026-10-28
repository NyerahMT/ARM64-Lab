#!/usr/bin/env python3
"""Real Win64 fopen import and both x64 result branches; synthetic ABI service.

Authentic original call 0x1305A9 -> 0x2AAEBC -> MSVCR90!fopen.
Two bounded service outcomes (NULL vs opaque guest FILE*) are reference
fixtures ONLY: neither authorizes a fabricated Steam client or license.
"""
import hashlib,json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RBX,
 UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RSI,UC_X86_REG_RDI,
 UC_X86_REG_R12,UC_X86_REG_EFLAGS
)
import mxbikes_init_nested_wave as static
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_boot_next_call_native as initial
import mxbikes_init_child_successors_native as child
import mxbikes_init_child_return_native as returned
import mxbikes_next_outer_init_native as parent
from mxbikes_whole_game_map import INPUT_SHA
BASE=joined.BASE
CALL=parent.BOUNDARY
THUNK=parent.NESTED
SLOT=0x321228
JNE=0x1305b4
STUB=0x730040000
HANDLE=0x730050000
FILE_ARG=0x342e40
MODE_ARG=0x3422f0

def validate(pe):
    parent.verify_original(pe)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    rows=list(decoder.disasm(pe.read_rva(0x1305ae,JNE+6-0x1305ae),0x1305ae))
    if (len(rows)!=3 or
        [(r.mnemonic,r.op_str) for r in rows[:2]]!=
          [("mov","r12, rax"),("test","rax, rax")] or
        rows[-1].address!=JNE or rows[-1].mnemonic!="jne" or
        len(rows[-1].operands)!=1 or rows[-1].operands[0].type!=X86_OP_IMM):
        raise ValueError("Original fopen result MOV/TEST/JNE changed")
    taken=rows[-1].operands[0].imm
    fall=rows[-1].address+rows[-1].size
    if not 0x1000<=taken<0x800000 or taken==fall:
        raise ValueError("Original result JNE target malformed")
    for rva,raw in ((FILE_ARG,b"steam_api64.dll\x00"),(MODE_ARG,b"rb\x00")):
        if pe.read_rva(rva,len(raw))!=raw:
            raise ValueError("Original binary's Win64 fopen args changed")
    return taken,fall

def original_case(pe,value,handle,taken,fall,*,return_cpu=False,rbx=0x123456789ABC,rsi=0x111122223333,rdi=0x444455556666):
    uc=joined.new_cpu(pe)
    main_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+initial.GLOBAL_RVA,value.to_bytes(4,"little"))
    for reg,v in ((UC_X86_REG_RIP,BASE+initial.CALLSITE),
      (UC_X86_REG_RSP,main_rsp),(UC_X86_REG_RAX,1),
      (UC_X86_REG_RBX,rbx),
      (UC_X86_REG_RSI,rsi),
      (UC_X86_REG_RDI,rdi),
      (UC_X86_REG_RCX,value),(UC_X86_REG_RDX,BASE+initial.CONSTANT_RVA)):
        uc.reg_write(reg,v)
    uc.emu_start(BASE+initial.CALLSITE,BASE+child.parent.CALL,
                 timeout=3000000,count=35)
    uc.emu_start(BASE+child.parent.CALL,0,timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+child.TAKEN:
        raise ValueError("Original guest x64 did not take child early JLE")
    uc.emu_start(BASE+child.TAKEN,0,timeout=3000000,count=3)
    uc.emu_start(BASE+returned.x64.CHECK_CALL,0,timeout=3000000,count=12)
    uc.emu_start(BASE+parent.CALL,0,timeout=3000000,count=8)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+CALL:
        raise ValueError("Original guest did not reach Win64 fopen CALL")
    uc.mem_map(STUB,4096)
    uc.mem_write(STUB,b"\xc3")
    uc.mem_write(BASE+SLOT,STUB.to_bytes(8,"little"))
    if handle:uc.mem_map(HANDLE,4096)
    services=[]
    original_rsp=uc.reg_read(UC_X86_REG_RSP)
    def service(u,pc,size,ctx):
        if pc!=STUB:return
        if (u.reg_read(UC_X86_REG_RCX)!=BASE+FILE_ARG or
            u.reg_read(UC_X86_REG_RDX)!=BASE+MODE_ARG or
            bytes(u.mem_read(BASE+FILE_ARG,16))!=b"steam_api64.dll\x00" or
            bytes(u.mem_read(BASE+MODE_ARG,3))!=b"rb\x00"):
            raise ValueError("Original Win64 fopen ABI arguments changed")
        services.append(pc)
        u.reg_write(UC_X86_REG_RAX,handle)
    uc.hook_add(UC_HOOK_CODE,service)
    uc.emu_start(BASE+CALL,BASE+JNE,timeout=3000000,count=20)
    if (uc.reg_read(UC_X86_REG_RIP)!=BASE+JNE or len(services)!=1 or
        uc.reg_read(UC_X86_REG_RSP)!=original_rsp or
        uc.reg_read(UC_X86_REG_R12)!=handle or
        uc.reg_read(UC_X86_REG_RAX)!=handle):
        raise ValueError("Original guest Win64 fopen CALL/JMP/RET/MOV/TEST changed")
    flags=uc.reg_read(UC_X86_REG_EFLAGS)
    if bool(flags&64)!=bool(handle==0):
        raise ValueError("Original guest TEST RAX,ZF mismatch")
    uc.emu_start(BASE+JNE,0,timeout=3000000,count=1)
    result=uc.reg_read(UC_X86_REG_RIP)-BASE
    if result!=(taken if handle else fall):
        raise ValueError("Original actual x64 JNE successor changed")
    result={"original_parser_dword":value,
      "modeled_external_result":"opaque_nonnull_handle" if handle else "NULL",
      "executed_original_win64_import_call":True,
      "executed_original_r12_test_jne":True,
      "original_successor_rva":hex(result),
      "authentic_guest_stack_restored":True,
      "actual_steam_client_initialized":False}
    return (result,uc) if return_cpu else result

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned executable SHA changed")
    taken,fall=validate(pe)
    samples=[original_case(pe,dword,handle,taken,fall)
             for dword in (0,1,0x80000000) for handle in (0,HANDLE)]
    groups=[static.scan_first_block(pe,addr) for addr in (taken,fall)]
    out.mkdir(parents=True,exist_ok=True)
    report={
      "original_sha256":INPUT_SHA,
      "authentic_import":"MSVCR90.dll!fopen",
      "original_filename":"steam_api64.dll","original_mode":"rb",
      "original_fopen_conditional_rva":hex(JNE),
      "nonnull_branch_rva":hex(taken),"null_branch_rva":hex(fall),
      "original_x64_import_and_two_outcome_cases":samples,
      "both_original_result_blocks":groups,
      "native_steam_or_license_checks_passed":False,
      "native_arm64_fopen_executed":False
    }
    (out/"steam-fopen-result-branches.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes original CRT fopen result and two x64 branches","",
      "- Original file/mode: steam_api64.dll / rb",
      "- Original Win64 import thunk/RET/MOV R12/TEST/JNE: **6/6 x64 cases**",
      "- Modeled opaque non-null FILE*: **"+hex(taken)+"**",
      "- Modeled NULL FILE*: **"+hex(fall)+"**",
      "- No Steam client or license status was faked",""]
    for group in groups:
        lines.extend(["## Original successor "+group["entry_rva"],
           "- First control: "+str(group.get("control_rva"))+" "+str(group.get("control_kind"))+
             " "+str(group.get("control_operands"))])
        lines.extend("- "+i["rva"]+" "+i["mnemonic"]+" "+i["operands"]
                     for i in group.get("precontrol_instruction_forms",[]))
    lines.extend(["","No iOS, engine, frame or interactive menu running.",""])
    (out/"steam-fopen-result-branches.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: fopen_branch.py owned.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
