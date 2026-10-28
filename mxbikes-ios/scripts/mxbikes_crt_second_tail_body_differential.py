#!/usr/bin/env python3
"""Authentic six-instruction CRT callback with CALL then tail JMP, x64/C/AArch64.

Original owned executable and generated derivatives stay in PRIVATE transient
CI. Two direct original callees receive controlled explicit test responses;
their *own* bodies are not claimed to run here. This is the callback body,
not a complete _initterm table, Windows loader/CRT or native game startup.
"""
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_REG,X86_OP_MEM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
    UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R11,UC_X86_REG_RDI,
    UC_X86_REG_RSI,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS,
)

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_crt_exception_callback_differential import BASE,SHA,STACK,SP,STOP

ENTRY=0x320770
END=0x320790
LOCAL=0x2d2a70
WRAPPER=0x2ab7e4
REGS=(
    ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
    ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
    ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
    ("r11",UC_X86_REG_R11),("rdi",UC_X86_REG_RDI),
    ("rsi",UC_X86_REG_RSI),("rsp",UC_X86_REG_RSP),
    ("rip",UC_X86_REG_RIP),
)

def hash_bytes(raw):
    h=0xcbf29ce484222325
    for value in raw:
        h=((h^value)*0x100000001b3)&((1<<64)-1)
    return h

def inspect(pe):
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original owned MX Bikes executable SHA changed")
    body=pe.read_rva(ENTRY,END-ENTRY)
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    forms=list(decoder.disasm(body,ENTRY))
    if (len(forms)!=6 or sum(x.size for x in forms)!=len(body) or
        [x.mnemonic for x in forms]!=[
            "sub","lea","call","lea","add","jmp"]):
        raise RuntimeError("Original callback bounded forms differ: "+repr([(hex(x.address),x.mnemonic,x.op_str) for x in forms]))
    if (forms[2].operands[0].type!=X86_OP_IMM or
        forms[2].operands[0].imm!=LOCAL or
        forms[5].operands[0].type!=X86_OP_IMM or
        forms[5].operands[0].imm!=WRAPPER):
        raise RuntimeError("Original callback call/tail targets changed")
    argument_targets=[]
    for ins in (forms[1],forms[3]):
        if (ins.operands[0].type!=X86_OP_REG or
            ins.reg_name(ins.operands[0].reg)!="rcx" or
            ins.operands[1].type!=X86_OP_MEM or
            ins.reg_name(ins.operands[1].mem.base)!="rip" or
            ins.operands[1].mem.index):
            raise RuntimeError("Original callback uses unexpected LEA form")
        argument_targets.append(
            BASE+ins.address+ins.size+ins.operands[1].mem.disp)
    native,meta=lift_crt_import_cluster(
        body,ENTRY,{}, {},BASE,
        local_targets={LOCAL,WRAPPER},
        function_name="native_second_initializer"
    )
    if (meta["decoded_instructions"]!=6 or
        meta["local_call_sites"]!=1 or
        meta["verified_terminal_tail_jumps"]!=1 or
        meta["import_calls"]!=0):
        raise RuntimeError("Original callback native call-graph changed")
    return body,native,argument_targets

def reference(body,index,arguments):
    machine=Uc(UC_ARCH_X86,UC_MODE_64)
    for page in {((BASE+rva)&~4095) for rva in (ENTRY,LOCAL,WRAPPER)}:
        machine.mem_map(page,4096)
    machine.mem_map(STACK,0x10000)
    machine.mem_write(BASE+ENTRY,body)
    machine.mem_write(BASE+LOCAL,b"\xc3")
    machine.mem_write(BASE+WRAPPER,b"\xc3")
    machine.mem_write(SP,struct.pack("<Q",STOP))
    initial_rcx=0x10101010+index*0x1111
    initial_rbx=0x220000+index*0x112
    machine.reg_write(UC_X86_REG_RCX,initial_rcx)
    machine.reg_write(UC_X86_REG_RBX,initial_rbx)
    machine.reg_write(UC_X86_REG_RIP,BASE+ENTRY)
    machine.reg_write(UC_X86_REG_RSP,SP)
    machine.reg_write(UC_X86_REG_EFLAGS,0x202|((index%2)<<6))
    visited=set()
    calls=[]
    decoded=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(body,ENTRY))
    codepcs={BASE+ins.address:ins.address for ins in decoded}
    def hook(cpu,pc,size,ctx):
        if pc in codepcs:
            visited.add(codepcs[pc])
            return
        if pc==BASE+LOCAL:
            if (cpu.reg_read(UC_X86_REG_RSP)!=SP-0x30 or
                cpu.reg_read(UC_X86_REG_RCX)!=arguments[0]):
                raise RuntimeError("Original x64 direct-call Win64 ABI changed")
            calls.append(1)
            cpu.reg_write(UC_X86_REG_RAX,0x1170+index)
        elif pc==BASE+WRAPPER:
            if (cpu.reg_read(UC_X86_REG_RSP)!=SP or
                cpu.reg_read(UC_X86_REG_RCX)!=arguments[1]):
                raise RuntimeError("Original x64 tail-jump stack/argument ABI changed")
            calls.append(2)
            cpu.reg_write(UC_X86_REG_RAX,0 if index%2 else 0xffffffff)
    machine.hook_add(UC_HOOK_CODE,hook)
    machine.emu_start(BASE+ENTRY,STOP,timeout=2500000,count=90)
    if (machine.reg_read(UC_X86_REG_RIP)!=STOP or
        machine.reg_read(UC_X86_REG_RSP)!=SP+8 or
        visited!={ins.address for ins in decoded} or
        calls!=[1,2]):
        raise RuntimeError("Original callback did not traverse all six instructions")
    flags=machine.reg_read(UC_X86_REG_EFLAGS)
    return {
        "rcx":initial_rcx,"rbx":initial_rbx,
        "expected":[machine.reg_read(r) for _,r in REGS]+[
            int(bool(flags&64)),int(bool(flags&128)),int(bool(flags&1))],
        "stack_hash":hash_bytes(bytes(machine.mem_read(SP-128,256))),
        "call_types":calls,
    }

C=r"""
#include <stdint.h>
#include "mx_crt_cluster_guest.h"
#define SP UINT64_C(__SP__)
#define WIN UINT64_C(__WIN__)
#define EXIT_PC UINT64_C(__EXIT__)
#define ENTRY_PC UINT64_C(__ENTRY__)
#define LOCAL_PC UINT64_C(__LOCAL__)
#define WRAPPER_PC UINT64_C(__WRAPPER__)
#define FIRST_ARGUMENT UINT64_C(__FIRST_ARG__)
#define SECOND_ARGUMENT UINT64_C(__SECOND_ARG__)
typedef struct {
 uint64_t rcx,rbx,registers[14],stack_hash;
} sample;
static const sample cases[]={__CASES__};
static uint8_t guest_stack[256];
typedef struct {uint32_t i,events;uint8_t order[2];} context;
static uint64_t fnv(const uint8_t *v,uint32_t size){
 uint64_t h=UINT64_C(0xcbf29ce484222325);
 for(uint32_t i=0;i<size;i++)
    h=(h^(uint64_t)v[i])*UINT64_C(0x100000001b3);
 return h;
}
static int impossible_import(void*c,mx_crt_service_id svc,
                             mx_crt_cluster_state*s,mx_cfg_memory*m,
                             uint64_t rsp){
 (void)c;(void)svc;(void)s;(void)m;(void)rsp;
 return 0;
}
static int direct(void*opaque,uint64_t dest,mx_crt_cluster_state*s,
                  mx_cfg_memory*m){
 context*c=(context*)opaque;
 if(!c||s->local_depth!=1U||c->events>=2U)
    return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 if(dest==LOCAL_PC){
    if(c->events!=0U||s->rsp!=SP-0x30U||s->rcx!=FIRST_ARGUMENT)
       return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    c->order[c->events++]=1U;
    s->rax=0x1170U+c->i;
 }else if(dest==WRAPPER_PC){
    if(c->events!=1U||s->rsp!=SP||s->rcx!=SECOND_ARGUMENT)
       return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
    c->order[c->events++]=2U;
    s->rax=(c->i%2U)?0U:UINT64_C(0xffffffff);
 }else return MX_CRT_CLUSTER_IMPORT_UNSUPPORTED;
 const uint64_t ret=mx_crt_cluster_read(s,m,s->rsp,8);
 if(s->fault)return MX_CRT_CLUSTER_MEMORY_FAULT;
 s->rsp+=8U;
 s->rip=ret;
 return MX_CRT_CLUSTER_RETURNED;
}
int native_second_initializer(mx_crt_cluster_state*,mx_cfg_memory*,
                             mx_crt_cluster_import_fn,
                             mx_crt_cluster_direct_fn,void*);
int smoke(void){
 mx_cfg_region range={WIN,guest_stack,256};
 mx_cfg_memory mem={&range,1};
 for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
    const sample*f=&cases[k];
    for(uint32_t j=0;j<256;j++)guest_stack[j]=0U;
    uint64_t ret=EXIT_PC;
    if(!mx_cfg_transfer(&mem,SP,&ret,8,1))return 1;
    mx_crt_cluster_state s={0};
    s.rcx=f->rcx;s.rbx=f->rbx;s.rsp=SP;s.rip=ENTRY_PC;
    s.zf=(uint8_t)(k%2U);
    context c={k,0U,{0,0}};
    if(native_second_initializer(&s,&mem,impossible_import,direct,&c)!=
       MX_CRT_CLUSTER_RETURNED ||
       s.local_depth!=0U||s.local_calls!=2U||s.imports!=0U||
       c.events!=2U||c.order[0]!=1U||c.order[1]!=2U)
       return 10+k;
    const uint64_t actual[14]={
        s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.r9,s.r11,
        s.rdi,s.rsi,s.rsp,s.rip,s.zf,s.sf,s.cf
    };
    for(uint32_t j=0;j<14;j++)
       if(actual[j]!=f->registers[j])return 40+k;
    if(fnv(guest_stack,256)!=f->stack_hash)return 80+k;
 }
 /* Never return success for an unimplemented original direct callee. */
 for(uint32_t j=0;j<256;j++)guest_stack[j]=0U;
 uint64_t ret=EXIT_PC;
 if(!mx_cfg_transfer(&mem,SP,&ret,8,1))return 100;
 mx_crt_cluster_state blocked={0};
 blocked.rcx=cases[0].rcx;blocked.rsp=SP;blocked.rip=ENTRY_PC;
 if(native_second_initializer(&blocked,&mem,impossible_import,0,0)!=
    MX_CRT_CLUSTER_IMPORT_UNSUPPORTED)return 101;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
"""

def fixtures_c(rows):
    return ",\n".join(
        "{UINT64_C("+str(r["rcx"])+"),UINT64_C("+str(r["rbx"])+"),{"+
        ",".join("UINT64_C("+str(v)+")" for v in r["expected"])+
        "},UINT64_C("+str(r["stack_hash"])+")}" for r in rows)

def run(exe,output):
    pe=PE(exe)
    body,translated,arguments=inspect(pe)
    rows=[reference(body,i,arguments) for i in range(8)]
    native=C
    for key,value in {
        "__SP__":str(SP),"__WIN__":str(SP-128),
        "__EXIT__":str(STOP),"__ENTRY__":str(BASE+ENTRY),
        "__LOCAL__":str(BASE+LOCAL),"__WRAPPER__":str(BASE+WRAPPER),
        "__FIRST_ARG__":str(arguments[0]),
        "__SECOND_ARG__":str(arguments[1]),
        "__CASES__":fixtures_c(rows)
    }.items():
        if key not in native:
            raise RuntimeError("Tail callback native fixture placeholder missing")
        native=native.replace(key,value)
    with tempfile.TemporaryDirectory(prefix="mx-original-second-callback-") as td:
        work=Path(td)
        original=work/"private-generated-tail.c"
        harness=work/"private-tail-fixtures.c"
        original.write_text(translated)
        harness.write_text(native)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        def checked(cmd):
            result=subprocess.run(cmd,capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError("Private original tail x64/ARM64 parity gate failed: "+
                                   (result.stderr or result.stdout)[-2200:])
        host=work/"host"
        checked(["cc",*flags,"-DHOST",str(original),str(harness),"-o",str(host)])
        checked([str(host)])
        arm=work/"tail-arm64.elf"
        checked(["clang","--target=aarch64-unknown-linux-gnu",
                 "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                 "-fno-builtin","-fno-stack-protector",*flags,
                 "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                 "-Wl,--build-id=none",str(original),str(harness),"-o",str(arm)])
        status=execute_arm64_elf(arm,instruction_budget=600000,
                                 timeout_us=7000000)
    output.mkdir(parents=True,exist_ok=True)
    report={
        "original_rva":hex(ENTRY),
        "original_instruction_count":6,
        "original_native_x64_host_c_executed_arm64_fixtures":len(rows),
        "original_local_callees_stubbed":True,
        "original_direct_call_target":hex(LOCAL),
        "original_terminal_tail_target":hex(WRAPPER),
        "original_callees_executed":False,
        "full_initterm_executed":False,
        "native_engine_or_ios_executed":False,
        "arm64_exit":status["arm64_smoke_exit"],
    }
    (output/"crt-original-second-tail-body-arm64.json").write_text(
        json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# Original MX Bikes six-instruction _initterm slot-2 tail callback","",
        "- RVA **"+hex(ENTRY)+"**, 6/6 original instructions exercised",
        "- Original x64 versus native C versus executed AArch64: **"+
          str(len(rows))+"/"+str(len(rows))+" fixtures matched**",
        "- Normal Win64 local CALL and terminal JMP tail into shared wrapper",
        "- Stack/return slots, registers/flags and control order verified",
        "- Imported service stubs were NOT used; both local callee bodies",
        "  remain controlled test responses rather than real original execution",
        "- AArch64 guest status: **"+str(status["arm64_smoke_exit"])+"**","",
        "**This is an isolated original initializer callback BODY,",
        "not a completed initializer table, genuine Windows CRT, engine,",
        "renderer or iOS game launch.**",""
    ])
    (output/"crt-original-second-tail-body-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py owned-original.exe private-report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
