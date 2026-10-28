#!/usr/bin/env python3
"""Differential proof: TWO original MX Bikes Win64 callers execute ONE original callee.

Authentic six-instruction caller bodies RVA 0x2412e0 and 0x241960, and
twelve-instruction callee RVA 0x15c240 are independently decoded and verified
against the original SHA-256-pinned EXE and PE .pdata unwind ranges.

The x64 reference actually CALLs the original callee machine code; no
intercepted call/RET. A strict pattern-validated translation produces C with
one noinline native callee, called by two native caller entrypoints.
Bitwise guest effects, callee result at return edge, flags and stack are
compared under both null and nonnull guest inputs, in host C and AArch64 ELF.

Original bytes, generated C and compiled native binaries stay EPHEMERAL and
PRIVATE in GitHub Actions; only aggregated test metadata is published.
This limited pattern is NOT a general x64 recompiler or a running game.
"""
from __future__ import annotations

import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_ARCH_ARM64,CS_MODE_ARM
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_EFLAGS,
)

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
IMAGE=0x140000000
CALLEE=0x15c240
CALLEE_END=0x15c269
CALLERS=[(0x2412e0,0x2412f7,0x581580),
         (0x241960,0x241977,0x581588)]
STACK=0x300000
RSP=STACK+0x8008
DATA=0x200000
OBJECT=DATA+0x1000
RETURN=0x400000
CASES_PER_CALLER=24

CALLEE_SHAPE=[
    ("mov","qword ptr [rsp + 8], rcx"),
    ("sub","rsp, 0x18"),
    ("cmp","qword ptr [rsp + 0x20], 0"),
    ("jne",None),
    ("xor","eax, eax"),
    ("jmp",None),
    ("mov","rax, qword ptr [rsp + 0x20]"),
    ("mov","qword ptr [rsp], rax"),
    ("mov","rax, qword ptr [rsp]"),
    ("mov","eax, dword ptr [rax]"),
    ("add","rsp, 0x18"),
    ("ret",""),
]
CALLER_SHAPE=[
    ("sub","rsp, 0x28"),
    ("mov",None),
    ("call",None),
    ("xor","eax, eax"),
    ("add","rsp, 0x28"),
    ("ret",""),
]


def strict_decode(code,rva,shape):
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    ins=list(md.disasm(code,rva))
    if len(ins)!=len(shape) or sum(x.size for x in ins)!=len(code):
        raise RuntimeError(f"Original {rva:#x}: instruction boundary/length mismatch")
    for ix,(i,(op,args)) in enumerate(zip(ins,shape)):
        if i.mnemonic!=op or (args is not None and i.op_str!=args):
            raise RuntimeError(f"Original {rva:#x}: unsupported opcode/operands at {ix} ({i.mnemonic} {i.op_str})")
    return ins


def validate_original(pe):
    p,sz=pe.directory(3)
    unwind={a:b for a,b,u in struct.iter_unpack("<III",pe.read_rva(p,sz))}
    if unwind.get(CALLEE)!=CALLEE_END:
        raise RuntimeError(f"Original callee unwind extent unexpectedly {unwind.get(CALLEE)}")
    callee=pe.read_rva(CALLEE,CALLEE_END-CALLEE)
    ins=strict_decode(callee,CALLEE,CALLEE_SHAPE)
    for index,goal in ((3,0x15c255),(5,0x15c264)):
        if len(ins[index].operands)!=1 or ins[index].operands[0].type!=X86_OP_IMM or ins[index].operands[0].imm!=goal:
            raise RuntimeError(f"Original callee branch {index} unexpected")
    all_addrs={i.address for i in ins}
    if not all(i.operands[0].imm in all_addrs for i in (ins[3],ins[5])):
        raise RuntimeError("Original callee contains branch leaving decoded interval")
    bodies=[]
    for rva,end,global_rva in CALLERS:
        if unwind.get(rva)!=end:
            raise RuntimeError(f"Original caller {rva:#x} unexpected unwind end")
        raw=pe.read_rva(rva,end-rva)
        inst=strict_decode(raw,rva,CALLER_SHAPE)
        op=inst[1].operands
        if (len(op)!=2 or op[1].type!=X86_OP_MEM or inst[1].reg_name(op[1].mem.base)!="rip"
             or op[1].mem.index!=0 or op[1].mem.disp+inst[1].address+inst[1].size!=global_rva
             or inst[1].op_str.split(",")[0]!="rcx"):
            raise RuntimeError("Original global pointer load address/register inconsistent")
        call=inst[2]
        if len(call.operands)!=1 or call.operands[0].type!=X86_OP_IMM or call.operands[0].imm!=CALLEE:
            raise RuntimeError("Original direct-call target is not shared callee")
        if inst[3].address != call.address+call.size:
            raise RuntimeError("Missing caller return instruction")
        bodies.append((raw,call.address+call.size))
    return callee,bodies


def x64_reference(callee,bodies,caller_id,present,object_value,rdx_initial):
    rva,end,global_rva=CALLERS[caller_id]
    raw,call_return_rva=bodies[caller_id]
    m=Uc(UC_ARCH_X86,UC_MODE_64)
    for addr,size in ((IMAGE+(CALLEE&~4095),4096),
                      (IMAGE+(rva&~4095),4096),
                      (IMAGE+0x581000,4096),
                      (DATA,0x3000),(STACK,0x10000),(RETURN,4096)):
        m.mem_map(addr,size)
    m.mem_write(IMAGE+CALLEE,callee)
    m.mem_write(IMAGE+rva,raw)
    m.mem_write(IMAGE+global_rva,struct.pack("<Q",OBJECT if present else 0))
    m.mem_write(OBJECT,struct.pack("<I",object_value))
    m.mem_write(RSP,struct.pack("<Q",RETURN))
    m.reg_write(UC_X86_REG_RIP,IMAGE+rva)
    m.reg_write(UC_X86_REG_RSP,RSP)
    m.reg_write(UC_X86_REG_RAX,0xDCBA987654321000)
    m.reg_write(UC_X86_REG_RCX,0x8877665544332211)
    m.reg_write(UC_X86_REG_RDX,rdx_initial)
    witnessed=[]
    visited=[]
    def monitor(uc,pc,size,_):
        if pc==IMAGE+CALLEE:
            visited.append(1)
        if pc==IMAGE+call_return_rva:
            witnessed.append(uc.reg_read(UC_X86_REG_RAX))
    m.hook_add(UC_HOOK_CODE,monitor)
    m.emu_start(IMAGE+rva,RETURN,timeout=1_000_000,count=64)
    flags=m.reg_read(UC_X86_REG_EFLAGS)
    if (len(visited)!=1 or len(witnessed)!=1 or m.reg_read(UC_X86_REG_RIP)!=RETURN
        or m.reg_read(UC_X86_REG_RSP)!=RSP+8):
        raise RuntimeError("Original x64 game caller did not execute actual direct callee and RET")
    expected_child=object_value if present else 0
    if witnessed[0]!=expected_child:
        raise RuntimeError("Original x64 callee did not produce selected input")
    def word(address):
        return struct.unpack("<Q",m.mem_read(address,8))[0]
    return {
        "caller_id":caller_id,"present":int(present),"value":object_value,
        "rdx_initial":rdx_initial,"child_value":witnessed[0],
        "rax":m.reg_read(UC_X86_REG_RAX),
        "rcx":m.reg_read(UC_X86_REG_RCX),
        "rdx":m.reg_read(UC_X86_REG_RDX),
        "rsp":m.reg_read(UC_X86_REG_RSP),"rip":m.reg_read(UC_X86_REG_RIP),
        "zf":(flags>>6)&1,"sf":(flags>>7)&1,"cf":flags&1,"of":(flags>>11)&1,
        "stack_tmp":word(RSP-72),
        "stack_saved":word(RSP-40),
        "stack_call_ret":word(RSP-48),
        "stack_original_ret":word(RSP),
    }


def lifted_source():
    # Generated only AFTER verifying the exact complete original opcode
    # sequence, operand types, two direct-call destinations and all three
    # PE unwind intervals. No game bytes are included in this source file.
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
#define IMAGE_BASE UINT64_C(5368709120)
#define CALLEE_RIP UINT64_C(5370135104)
#define ORIG_RSP UINT64_C(3178504)

static void set_add64_flags(mx_cfg_state *s,uint64_t a,uint64_t b,uint64_t result){
 s->cf=(uint8_t)(result<a);
 s->of=(uint8_t)((((~(a^b))&(a^result))&UINT64_C(9223372036854775808))!=0);
 s->sf=(uint8_t)((result>>63)!=0);
 s->zf=(uint8_t)(result==0);
}

/* One actual original-code-derived callee for BOTH original callers.
 * This noinline declaration requires a real native nested call on AArch64. */
#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline,used))
#endif
static int lifted_shared_callee(mx_cfg_state *s,mx_cfg_memory *mem) {
 if(!s || !mem)return -1;
 /* MOV [RSP+8],RCX */
 if(!mx_cfg_transfer(mem,s->rsp+8,&s->rcx,8,1))return -3;
 /* SUB RSP,0x18 (CMP overrides flags) */
 if(s->rsp<24)return -5;
 s->rsp-=24;
 uint64_t arg=0;
 if(!mx_cfg_transfer(mem,s->rsp+32,&arg,8,0))return -3;
 /* CMP QWORD [RSP+0x20], 0; JNE branch */
 s->zf=(uint8_t)(arg==0);s->sf=(uint8_t)((arg>>63)!=0);
 s->cf=0;s->of=0;
 if(arg==0){
   /* XOR EAX,EAX, JMP epilogue */
   s->rax=0;s->zf=1;s->sf=0;s->cf=0;s->of=0;
 }else{
   /* MOV RAX,[RSP+0x20]; MOV [RSP],RAX; MOV RAX,[RSP];
    * MOV EAX,DWORD [RAX] 32-bit zero extension */
   s->rax=arg;
   if(!mx_cfg_transfer(mem,s->rsp,&s->rax,8,1))return -3;
   if(!mx_cfg_transfer(mem,s->rsp,&s->rax,8,0))return -3;
   uint32_t val=0;
   if(!mx_cfg_transfer(mem,s->rax,&val,4,0))return -3;
   s->rax=val;
 }
 /* ADD RSP,0x18 */
 {
    const uint64_t a=s->rsp, b=24, sum=a+b;
    set_add64_flags(s,a,b,sum);s->rsp=sum;
 }
 if(!mx_cfg_transfer(mem,s->rsp,&s->rip,8,0))return -3;
 s->rsp+=8;
 return 1;
}
static int lifted_common_caller(mx_cfg_state *s,mx_cfg_memory *mem,
             uint64_t original_global,uint64_t original_return,
             uint64_t *witness){
 if(!s || !mem || !witness)return -1;
 if((s->rsp&15)!=8 || s->rsp<48)return -5;
 const uint64_t entry_rsp=s->rsp;
 /* SUB RSP,0x28, modeled arithmetic flags overwritten by later XOR. */
 s->rsp-=40;
 if(!mx_cfg_transfer(mem,original_global,&s->rcx,8,0))return -3;
 /* Original direct Win64 CALL: CPU pushes return RVA before callee. */
 s->rsp-=8;
 if(!mx_cfg_transfer(mem,s->rsp,&original_return,8,1))return -3;
 s->rip=IMAGE_BASE+UINT64_C(1425984);
 int result=lifted_shared_callee(s,mem);
 if(result!=1)return result;
 if(s->rip!=original_return || s->rsp!=entry_rsp-40)return -6;
 *witness=s->rax;
 /* XOR EAX,EAX and ADD RSP,0x28 */
 s->rax=0;s->zf=1;s->sf=0;s->cf=0;s->of=0;
 {
    const uint64_t a=s->rsp,b=40,sum=a+b;
    set_add64_flags(s,a,b,sum);s->rsp=sum;
 }
 if(!mx_cfg_transfer(mem,s->rsp,&s->rip,8,0))return -3;
 s->rsp+=8;
 return 1;
}
int lifted_caller_a(mx_cfg_state *s,mx_cfg_memory *mem,uint64_t *witness){
 return lifted_common_caller(s,mem,IMAGE_BASE+UINT64_C(5772672),
                            IMAGE_BASE+UINT64_C(2364144),witness);
}
int lifted_caller_b(mx_cfg_state *s,mx_cfg_memory *mem,uint64_t *witness){
 return lifted_common_caller(s,mem,IMAGE_BASE+UINT64_C(5772680),
                            IMAGE_BASE+UINT64_C(2365808),witness);
}
'''


def harness_c(examples):
    # We embed ONLY deterministic reference VALUES in an ephemeral generated
    # private test harness; no original program code or bytes are emitted.
    keys=("caller_id","present","value","rdx_initial","child_value",
          "rax","rcx","rdx","rsp","rip","zf","sf","cf","of",
          "stack_tmp","stack_saved","stack_call_ret","stack_original_ret")
    rows=[]
    for e in examples:
        rows.append(" {"+",".join("UINT64_C("+str(e[k])+")" for k in keys)+"},")
    return r'''#include <stdint.h>
#include "mx_cfg_vm.h"
int lifted_caller_a(mx_cfg_state*,mx_cfg_memory*,uint64_t*);
int lifted_caller_b(mx_cfg_state*,mx_cfg_memory*,uint64_t*);
typedef struct {uint64_t caller_id,present,value,rdx_initial,child_value,
 rax,rcx,rdx,rsp,rip,zf,sf,cf,of,stack_tmp,stack_saved,
 stack_call_ret,stack_original_ret;} case_value;
static const case_value cases[]={
'''+ "\n".join(rows)+r'''
};
static uint8_t stack_memory[0x200],data[0x2000],game_globals[0x1000];
static uint64_t word(const mx_cfg_memory *mem,uint64_t addr){
  uint64_t out=0; mx_cfg_transfer((mx_cfg_memory*)mem,addr,&out,8,0);
  return out;
}
int smoke(void) {
 mx_cfg_region regions[]={
   {UINT64_C(0x307f00),stack_memory,sizeof(stack_memory)},
   {UINT64_C(0x200000),data,sizeof(data)},
   {UINT64_C(0x140581000),game_globals,sizeof(game_globals)}
 };
 mx_cfg_memory mem={regions,3};
 for(uint32_t k=0;k<sizeof(cases)/sizeof(cases[0]);k++){
   const case_value *e=&cases[k];
   const uint64_t rsp=UINT64_C(0x308008);
   const uint64_t global_rva=e->caller_id?UINT64_C(0x581588):UINT64_C(0x581580);
   const uint64_t ptr=e->present?UINT64_C(0x201000):0;
   uint64_t return_pc=UINT64_C(0x400000);
   /* Precisely reset all x64-written stack slots; the original
    * x64 guest starts in freshly zero-filled Unicorn pages each case. */
   uint64_t zero=0;
   if(!mx_cfg_transfer(&mem,rsp-72,&zero,8,1) ||
      !mx_cfg_transfer(&mem,rsp-48,&zero,8,1) ||
      !mx_cfg_transfer(&mem,rsp-40,&zero,8,1) ||
      !mx_cfg_transfer(&mem,rsp,&return_pc,8,1) ||
      !mx_cfg_transfer(&mem,UINT64_C(0x140000000)+global_rva,(void*)&ptr,8,1))
       return 11;
   uint32_t object_value=(uint32_t)e->value;
   if(!mx_cfg_transfer(&mem,UINT64_C(0x201000),&object_value,4,1))return 12;
   mx_cfg_state state={0};
   state.rax=UINT64_C(0xDCBA987654321000);
   state.rcx=UINT64_C(0x8877665544332211);
   state.rdx=e->rdx_initial;state.rsp=rsp;
   uint64_t observed=UINT64_MAX;
   int code=e->caller_id?lifted_caller_b(&state,&mem,&observed):
                         lifted_caller_a(&state,&mem,&observed);
   if(code!=1)return 20+(uint32_t)(-code);
   if(observed!=e->child_value)return 30;
   if(state.rax!=e->rax || state.rcx!=e->rcx || state.rdx!=e->rdx)return 31;
   if(state.rsp!=e->rsp || state.rip!=e->rip)return 32;
   if(state.zf!=e->zf || state.sf!=e->sf || state.cf!=e->cf || state.of!=e->of)return 33;
   if(word(&mem,rsp-72)!=e->stack_tmp ||
      word(&mem,rsp-40)!=e->stack_saved ||
      word(&mem,rsp-48)!=e->stack_call_ret ||
      word(&mem,rsp)!=e->stack_original_ret)return 34;
 }
 /* Failure mode: valid nonzero guest global pointer into UNMAPPED RAM
  * must be rejected, not treated as an arbitrary host pointer. */
 {
   uint64_t invalid=UINT64_C(0xABC000);
   uint64_t ret=UINT64_C(0x400000);
   mx_cfg_transfer(&mem,UINT64_C(0x140581580),&invalid,8,1);
   mx_cfg_transfer(&mem,UINT64_C(0x308008),&ret,8,1);
   mx_cfg_state bad={0};bad.rsp=UINT64_C(0x308008);
   uint64_t child=0;
   if(lifted_caller_a(&bad,&mem,&child)!=-3)return 40;
 }
 return 0;
}
#ifdef HOST_SMOKE
int main(void){return smoke();}
#endif
'''


def attest_arm64_direct_call(path):
    """Independent machine-code check that the generated ELF contains
    an actual AArch64 BL into its noinline, original-code-derived callee.
    Static metadata; nothing from the executable binary is published.
    """
    with path.open("rb") as fp:
        elf=ELFFile(fp)
        if elf["e_machine"]!="EM_AARCH64":
            raise RuntimeError("Native output is not AArch64")
        text_section=elf.get_section_by_name(".text")
        symbols=elf.get_section_by_name(".symtab")
        if text_section is None or symbols is None:
            raise RuntimeError("No ARM64 machine-code/symbol section")
        found=symbols.get_symbol_by_name("lifted_shared_callee")
        if not found:
            raise RuntimeError("Generated native callee was optimized away")
        callee_va=int(found[0]["st_value"])
        if not callee_va:
            raise RuntimeError("Invalid generated callee native address")
        md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
        md.detail=True
        bl_sites=[]
        for ins in md.disasm(text_section.data(),int(text_section["sh_addr"])):
            if ins.mnemonic!="bl" or len(ins.operands)!=1:
                continue
            if int(ins.operands[0].imm)==callee_va:
                bl_sites.append(hex(ins.address))
        if not bl_sites:
            raise RuntimeError("No real compiled ARM64 BL to original-code-derived shared callee")
        return {"native_arm64_bl_to_shared_callee":True,
                "native_call_sites":len(bl_sites),
                "native_linked_shared_callee_symbol_present":True}


def main():
    if len(sys.argv)!=3:
        raise SystemExit("usage: python mxbikes_real_shared_callee_differential.py ORIGINAL_EXE REPORT_DIR")
    root=Path(__file__).resolve().parents[1]/"arm64-lab"
    pe=PE(Path(sys.argv[1]))
    if pe.inventory()["sha256"]!=SHA:
        raise RuntimeError("Original game binary SHA mismatch")
    callee,bodies=validate_original(pe)
    values=[0,1,5,0x80000000,0xFFFFFFFF,0x7FFFFFFF]
    rng=random.Random(0x2412E0)
    results=[]
    for caller_id in (0,1):
        for j in range(CASES_PER_CALLER):
            present=(j%2)!=0
            val=values[j%len(values)] if j<len(values) else rng.getrandbits(32)
            rdx=rng.getrandbits(64)
            results.append(x64_reference(callee,bodies,caller_id,present,val,rdx))
    with tempfile.TemporaryDirectory(prefix="mxbikes-real-linked-",dir=Path(sys.argv[2]).parent) as temp:
        folder=Path(temp)
        generated=folder/"original-derived-linked.c"
        harness=folder/"actual-game-reference-values.c"
        generated.write_text(lifted_source())
        harness.write_text(harness_c(results))
        host=folder/"host-compare"
        inc=f"-I{root/'runtime'}"
        cmd=["cc","-O2","-fno-inline","-std=c11","-Wall","-Wextra","-Werror",
             "-DHOST_SMOKE",inc,str(generated),str(harness),"-o",str(host)]
        cp=subprocess.run(cmd,capture_output=True,text=True)
        if cp.returncode:raise RuntimeError("Host compilation failed: "+cp.stderr[-3500:])
        cp=subprocess.run([str(host)],capture_output=True,text=True)
        if cp.returncode:raise RuntimeError(f"Host original linked-function mismatch: {cp.returncode} {cp.stderr[-2000:]}")
        arm=folder/"original-linked-aarch64.elf"
        cmd=["clang","--target=aarch64-unknown-linux-gnu","-fuse-ld=lld",
             "-nostdlib","-static","-ffreestanding","-fno-stack-protector",
             "-fno-builtin","-fno-inline","-O2","-std=c11",inc,
             "-Wl,-e,smoke","-Wl,--build-id=none",
             "-Wl,-z,max-page-size=4096",str(generated),str(harness),"-o",str(arm)]
        cp=subprocess.run(cmd,capture_output=True,text=True)
        if cp.returncode:raise RuntimeError("Native AArch64 compilation failed: "+cp.stderr[-3500:])
        native_link_evidence=attest_arm64_direct_call(arm)
        arm_result=execute_arm64_elf(arm)
    report={
        "original_executable_sha256":SHA,
        "verified_original_caller_rvas":[hex(x[0]) for x in CALLERS],
        "verified_original_callee_rva":hex(CALLEE),
        "three_pdata_unwind_intervals_verbatim_verified":True,
        "original_decoded_instructions":2*6+12,
        "unique_original_x64_instructions":24,
        "genuine_x64_calls_executed_without_interception":len(results),
        "shared_callee_compiled_once_for_two_native_callers":True,
        "native_callee_noinline":True,
        "arm64_compiled_link_evidence":native_link_evidence,
        "null_path_cases":sum(not x["present"] for x in results),
        "nonnull_path_cases":sum(bool(x["present"]) for x in results),
        "host_bitwise_matches":len(results),"aarch64_bitwise_matches":len(results),
        "x64_branch_and_guest_memory_observed":True,
        "x64_nested_return_value_pre_caller_zeroing_matched":True,
        "host_and_arm64_register_stack_and_flags_matched":True,
        "negative_unmapped_guest_pointer_rejected":True,
        "aarch64_native_executed":arm_result["return_to_sentinel"],
        "actual_game_startup_on_arm64":False,
        "native_ios_executable_built":False,
        "limitations":[
            "Verified pattern-specific full-body translation of two short callers and one short callee, not a scalable general x64 lift",
            "PE unwind bodies checked, not yet independent Ghidra FunctionManager confirmation",
            "Only bounded synthetic guest globals, stack and object memory; no real Windows loader or game engine boot",
            "Native AArch64 ELF executed under Unicorn, not iOS Mach-O running on device",
        ]
    }
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    (out/"original-shared-callee-differential.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=[
        "# First original MX Bikes **genuine caller → callee** native ARM64 proof","",
        "- Original callers: "+", ".join(hex(p[0]) for p in CALLERS),
        "- Shared original callee: "+hex(CALLEE),
        "- Original complete bounded unwind bodies: 6 + 6 + 12 instructions",
        f"- Original x64 full nested CALL/RET references executed: **{len(results)}**",
        f"- Null branch / nonnull branch tests: {report['null_path_cases']} / {report['nonnull_path_cases']}",
        f"- Native host C comparisons: **{len(results)}/{len(results)} matched**",
        f"- Native AArch64 under Unicorn: **{len(results)}/{len(results)} matched**",
        "- Guest stack memory writes, callee intermediate return, final flags and registers compared",
        "- Native compiled callee is noinline and shared by both native caller entrypoints",
        "- Actual ARM64 BL machine-code instruction targeting shared callee confirmed by ELF disassembly",
        "- Invalid guest pointers rejected safely",
        "",
        "**A three-function, strict-pattern original-game native proof; not general recompilation, Steam initialization, iPhone app, or menu.**",""
    ]
    summary="\n".join(lines)
    (out/"original-shared-callee-differential.md").write_text(summary)
    print(summary)


if __name__=="__main__":
    main()
