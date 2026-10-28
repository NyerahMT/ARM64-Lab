#!/usr/bin/env python3
"""Verified memory-aware native ARM64 guest-link pilot for MX Bikes call targets.

Requires SHA-verified original PE; only two-instruction MOV/LEA + RET
straight-line entry paths with bounded memory access are accepted.
Original x64 executes in Unicorn, emitted native code runs on host and
executed AArch64, with guest registers/flags and memory bytes compared.
Without .pdata, this proves a closed entry path, NOT an entire game function.
"""
from __future__ import annotations
from pathlib import Path
from collections import Counter
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import (
 UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,
 UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_RDI,UC_X86_REG_RSI,
 UC_X86_REG_R11,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS)
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_whole_game_map import map_executable

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
BASE=0x140000000
MEM=0x600010000
RCX=MEM+0x40
STACK=0x710000000
PARENT_SP=STACK+0x8000
RET=BASE+0x151515
CALLSITE=BASE+0x1eeee0
CASES=8
MAX=32
GP=[("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),
    ("rcx",UC_X86_REG_RCX),("rdx",UC_X86_REG_RDX),
    ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),
    ("rdi",UC_X86_REG_RDI),("rsi",UC_X86_REG_RSI),
    ("r11",UC_X86_REG_R11)]
GP_MAP={"rax":"rax","eax":"rax","rbx":"rbx","ebx":"rbx",
        "rcx":"rcx","ecx":"rcx","rdx":"rdx","edx":"rdx",
        "r8":"r8","r8d":"r8","r9":"r9","r9d":"r9",
        "rdi":"rdi","edi":"rdi","rsi":"rsi","esi":"rsi",
        "r11":"r11","r11d":"r11"}
FIELDS=[x for x,_ in GP]+["rsp","rip","cf","zf","sf"]

def _rip(ins,mem):
    return BASE+ins.address+ins.size+mem.disp

def parse(ins):
    if ins.mnemonic not in ("mov","lea") or len(ins.operands)!=2:
        return None
    dst,src=ins.operands
    if ins.mnemonic=="lea":
        if (dst.type!=X86_OP_REG or ins.reg_name(dst.reg)!="rax" or
            src.type!=X86_OP_MEM or
            ins.reg_name(src.mem.base)!="rip" or src.mem.index):
            return None
        return {"kind":"lea_rip","size":8,"rip":_rip(ins,src.mem)}
    if dst.type==X86_OP_MEM:
        mem=dst.mem
        base=ins.reg_name(mem.base)
        if mem.index or dst.size not in (4,8) or base not in ("rip","rcx"):
            return None
        if base=="rcx" and not 0<=mem.disp<=192:
            return None
        if src.type==X86_OP_REG:
            source=ins.reg_name(src.reg)
            if source not in GP_MAP or src.size!=dst.size:return None
            value={"type":"register","name":GP_MAP[source]}
        elif src.type==X86_OP_IMM and dst.size==4:
            value={"type":"immediate","value":src.imm&0xffffffff}
        else:return None
        return {"kind":"store","size":dst.size,"base":base,
                "offset":mem.disp if base=="rcx" else 0,
                "rip":_rip(ins,mem) if base=="rip" else None,
                "value":value}
    if dst.type==X86_OP_REG:
        target=ins.reg_name(dst.reg)
        if target not in GP_MAP or dst.size not in (4,8):return None
        if src.type==X86_OP_REG:
            source=ins.reg_name(src.reg)
            if source not in GP_MAP or src.size!=dst.size:return None
            return {"kind":"move_register","size":dst.size,"target":GP_MAP[target],
                    "source":GP_MAP[source]}
        if (src.type==X86_OP_MEM and src.size==dst.size and
            not src.mem.index and ins.reg_name(src.mem.base)=="rip"):
            return {"kind":"load_rip","size":dst.size,"target":GP_MAP[target],
                    "rip":_rip(ins,src.mem)}
    return None

def discover(exe):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:raise RuntimeError("Wrong original PE")
    catalog=map_executable(exe)
    targets=Counter(int(x,16) for links in catalog["direct_call_graph"].values()
                    for x in links)
    unwind={int(row["rva"],16):row for row in catalog["interval_map"]}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    eligible=[]
    rejected=Counter()
    for rva,refs in targets.most_common():
        rec=unwind.get(rva)
        if rec and (rec["status"]!="decoded_linear" or
                    rec["bytes"]>32):
            rejected["unwind_out_of_scope"]+=1;continue
        try:blob=pe.read_rva(rva,32 if rec is None else rec["bytes"])
        except ValueError:
            rejected["outside_pe"]+=1;continue
        instructions=list(decoder.disasm(blob,rva))
        if len(instructions)<2 or instructions[1].mnemonic!="ret":
            rejected["not_two_instruction_leaf"]+=1;continue
        if rec and (len(instructions)!=2 or
                    sum(i.size for i in instructions)!=len(blob)):
            rejected["unwind_not_exact"]+=1;continue
        op=parse(instructions[0])
        if not op:
            rejected["unsupported_operand_pattern"]+=1;continue
        end=instructions[1].address+instructions[1].size
        if end-rva>32 or not end>rva:
            continue
        kind=op["kind"]
        body=pe.read_rva(rva,end-rva)
        eligible.append({"rva":rva,"operation":op,"raw":body,"kind":kind,
                         "evidence":"exact_unwind_interval" if rec else
                         "closed_direct_call_entry_path_no_unwind",
                         "refs":refs})
        if len(eligible)>=MAX:break
    return eligible,len(targets),rejected

def _input(index):
    return {name:((0x1122334455667788+j*0x101012351+index*0x101fffac)&((1<<64)-1))
            for j,(name,_) in enumerate(GP)}

def _scratch(case):
    return bytes((i*23+case*17+7)&255 for i in range(256))

def _rip_seed(case):
    return bytes((i*19+case*31+9)&255 for i in range(8))

def x64_original(candidate,case):
    op=candidate["operation"]
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    mapped=set()
    def page(addr):
        p=addr&~4095
        if p not in mapped:
            cpu.mem_map(p,4096);mapped.add(p)
    va=BASE+candidate["rva"]
    page(va);page(va+len(candidate["raw"])-1)
    cpu.mem_write(va,candidate["raw"])
    page(MEM)
    cpu.mem_map(STACK,0x10000)
    scratch=_scratch(case)
    cpu.mem_write(MEM,scratch)
    rip=op.get("rip")
    if rip is not None and op["kind"]!="lea_rip":
        page(rip);page(rip+op["size"]-1)
        cpu.mem_write(rip,_rip_seed(case)[:op["size"]])
    cpu.mem_write(PARENT_SP-8,struct.pack("<Q",RET))
    inp=_input(case);inp["rcx"]=RCX
    for name,reg in GP:cpu.reg_write(reg,inp[name])
    flags=0x202|([0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case])
    cpu.reg_write(UC_X86_REG_EFLAGS,flags)
    cpu.reg_write(UC_X86_REG_RSP,PARENT_SP-8)
    cpu.reg_write(UC_X86_REG_RIP,va)
    cpu.emu_start(va,RET,timeout=1000000,count=8)
    f=cpu.reg_read(UC_X86_REG_EFLAGS)
    out={name:cpu.reg_read(reg) for name,reg in GP}
    out.update({"rsp":cpu.reg_read(UC_X86_REG_RSP),
                "rip":cpu.reg_read(UC_X86_REG_RIP),
                "cf":int(bool(f&1)),"zf":int(bool(f&64)),"sf":int(bool(f&128))})
    if out["rsp"]!=PARENT_SP or out["rip"]!=RET:
        raise RuntimeError("Original memory leaf didn't return")
    final_scratch=bytes(cpu.mem_read(MEM,256))
    rip_before=_rip_seed(case)
    rip_after=(bytes(cpu.mem_read(rip,op["size"])) if
               rip is not None and op["kind"]!="lea_rip" else rip_before[:8])
    return inp,flags,out,final_scratch,rip_after

def native_body(item):
    rva=item["rva"];op=item["operation"];size=op["size"]
    kind=op["kind"]
    if kind=="lea_rip":
        statement=f"s->rax=UINT64_C({op['rip']});"
    elif kind=="move_register":
        src="s->"+op["source"]
        val=src if size==8 else "(uint32_t)"+src
        statement=f"s->{op['target']}={val};"
    elif kind in ("load_rip","store"):
        if kind=="load_rip":
            addr=f"UINT64_C({op['rip']})"
            statement=(f"uint64_t tmp=0U;"
                f"if(!mx_cfg_transfer(m,{addr},&tmp,{size}U,0))"
                f"return MX_NATIVE_LINK_STACK;"
                f"s->{op['target']}="+("tmp;" if size==8 else "(uint32_t)tmp;"))
        else:
            addr=(f"UINT64_C({op['rip']})" if op["base"]=="rip" else
                  f"s->rcx+UINT64_C({op['offset']})")
            value=(f"s->{op['value']['name']}" if op["value"]["type"]=="register"
                   else f"UINT64_C({op['value']['value']})")
            statement=(f"uint64_t tmp={value};"
                f"if(!mx_cfg_transfer(m,{addr},&tmp,{size}U,1))"
                f"return MX_NATIVE_LINK_STACK;")
    else:raise RuntimeError("No native lift for "+kind)
    symbol=f"mx_verified_mem_{rva:08x}"
    return symbol,f'''
static int {symbol}(mx_crt_cluster_state*s,mx_cfg_memory*m,void*ctx){{
 (void)ctx;
 if(!s||!m||s->rip!=BASE+UINT64_C({rva})||(s->rsp&15U)!=8U)
   return MX_NATIVE_LINK_INVALID;
 uint64_t ret=0;
 if(!mx_cfg_transfer(m,s->rsp,&ret,8U,0))return MX_NATIVE_LINK_STACK;
 {statement}
 s->rip=ret;s->rsp+=8U;
 return MX_NATIVE_LINK_OK;
}}
'''

def emit(candidates,references):
    rows=[];defs=[];regs=[]
    for item in sorted(candidates,key=lambda x:x["rva"]):
        symbol,body=native_body(item);defs.append(body)
        regs.append(f"{{BASE+UINT64_C({item['rva']}),{symbol},0}}")
        cols=[]
        for inp,flags,out,scratch,rip in references[item["rva"]]:
            expected=[out[k] for k in FIELDS]
            inputs=[inp[k] for k,_ in GP]
            cols.append("{{"+",".join(f"UINT64_C({x})" for x in inputs)+"},"
              +str(flags)+",{"+",".join(f"UINT64_C({x})" for x in expected)+"},{"
              +",".join(str(x) for x in scratch)+"},{"
              +",".join(str(x) for x in rip)+"}}")
        rows.append("{"+",\n".join(cols)+"}")
    # Preserve original RIP target for memory access; each input case maps
    # only its own current original guest RVA, avoiding overlapping regions.
    ripaddrs=[int(item["operation"].get("rip") or 0) if
              item["kind"] not in ("lea_rip",) else 0 for item in sorted(candidates,key=lambda x:x["rva"])]
    ripsizes=[item["operation"]["size"] if item["kind"] in ("load_rip","store")
              and item["operation"].get("rip") else 0
              for item in sorted(candidates,key=lambda x:x["rva"])]
    text=r'''#include <stdint.h>
#include "mx_native_guest_linker.h"
#define BASE UINT64_C(0x140000000)
#define STACK UINT64_C(0x710000000)
#define MEM UINT64_C(0x600010000)
#define PARENT_SP (STACK+0x8000U)
#define RET (BASE+0x151515U)
#define CALLSITE (BASE+0x1eeee0U)
#define COUNT __COUNT__
#define CASES 8U
typedef struct {
 uint64_t initial[9];uint32_t flags;
 uint64_t expected[14];
 uint8_t scratch[256];uint8_t rip[8];
} fixture;
static const fixture fixtures[COUNT][CASES]={__FIXTURES__};
static const uint64_t rip_addresses[COUNT]={__RIPADDRS__};
static const uint32_t rip_sizes[COUNT]={__RIPSIZES__};
static uint8_t stackbytes[65536],scratchbytes[4096],ripbytes[8];
__DEFINITIONS__
static const mx_native_link_entry links[COUNT]={__ENTRIES__};
static int equal64(mx_crt_cluster_state*s,fixture const*f){
 const uint64_t actual[14]={
  s->rax,s->rbx,s->rcx,s->rdx,s->r8,s->r9,s->rdi,s->rsi,s->r11,
  s->rsp,s->rip,s->cf,s->zf,s->sf
 };
 for(unsigned j=0;j<14U;j++)if(actual[j]!=f->expected[j])return 0;
 return 1;
}
int smoke(void){
 mx_cfg_region areas[3]={{STACK,stackbytes,65536U},
    {MEM,scratchbytes,4096U},{UINT64_C(0x777777),ripbytes,8U}};
 mx_cfg_memory memory={areas,3U};
 mx_native_link_registry registry={0};
 registry.entries=links;registry.count=COUNT;registry.max_depth=8U;
 if(mx_native_link_seal(&registry)!=MX_NATIVE_LINK_OK)return 1;
 for(unsigned i=0;i<COUNT;i++){
   if(rip_addresses[i])areas[2].base=rip_addresses[i];
   else areas[2].base=UINT64_C(0x777777);
   for(unsigned k=0;k<CASES;k++){
     const fixture*f=&fixtures[i][k];
     mx_crt_cluster_state s={0};
     s.rax=f->initial[0];s.rbx=f->initial[1];
     s.rcx=f->initial[2];s.rdx=f->initial[3];
     s.r8=f->initial[4];s.r9=f->initial[5];
     s.rdi=f->initial[6];s.rsi=f->initial[7];
     s.r11=f->initial[8];
     s.cf=(f->flags&1U)!=0U;s.zf=(f->flags&64U)!=0U;
     s.sf=(f->flags&128U)!=0U;
     s.rip=CALLSITE;s.rsp=PARENT_SP;
     for(unsigned j=0;j<256U;j++)
        scratchbytes[j]=(uint8_t)((j*23U+k*17U+7U)&255U);
     for(unsigned j=0;j<8U;j++)
        ripbytes[j]=(uint8_t)((j*19U+k*31U+9U)&255U);
     if(mx_native_link_call(&registry,&s,&memory,
          links[i].original_va,RET)!=MX_NATIVE_LINK_OK)return 2;
     if(!equal64(&s,f))return 3;
     for(unsigned j=0;j<256U;j++)if(scratchbytes[j]!=f->scratch[j])return 4;
     if(rip_sizes[i]){
       for(unsigned j=0;j<rip_sizes[i];j++)
           if(ripbytes[j]!=f->rip[j])return 5;
     }
   }
 }
 if(registry.calls_completed!=COUNT*CASES)return 6;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    for key,value in {
        "__COUNT__":str(len(candidates)),
        "__FIXTURES__":",\n".join(rows),
        "__RIPADDRS__":",".join(f"UINT64_C({x})" for x in ripaddrs),
        "__RIPSIZES__":",".join(str(x) for x in ripsizes),
        "__DEFINITIONS__":"\n".join(defs),
        "__ENTRIES__":",\n".join(regs),
    }.items():text=text.replace(key,value)
    return text

def run(exe,out):
    candidates,considered,rejections=discover(exe)
    if not candidates:raise RuntimeError("No supported MOV/LEA + RET original entry paths")
    references={item["rva"]:[x64_original(item,j) for j in range(CASES)]
                for item in candidates}
    source=emit(candidates,references)
    with tempfile.TemporaryDirectory(prefix="mxb-mem-native-") as td:
        root=Path(td);src=root/"original-private-memory-leafs.c";src.write_text(source)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
              "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"test-host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(src),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host compiler: "+p.stderr[-3000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:raise RuntimeError("Host memory differential failure: "+str(p.returncode))
        elf=root/"test-native-aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
             "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
             "-fno-builtin","-fno-stack-protector",*flags,
             "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
             "-Wl,--build-id=none",str(src),"-o",str(elf)],
             capture_output=True,text=True)
        if p.returncode:raise RuntimeError("ARM64 compiler: "+p.stderr[-3000:])
        execute_arm64_elf(elf,instruction_budget=2000000,timeout_us=15000000)
    out.mkdir(parents=True,exist_ok=True)
    kinds=dict(Counter(x["kind"] for x in candidates))
    evidences=dict(Counter(x["evidence"] for x in candidates))
    report={
      "original_sha_verified":True,
      "distinct_direct_call_targets_examined":considered,
      "native_original_entry_paths_executed":len(candidates),
      "original_x64_reference_cases":len(candidates)*CASES,
      "native_host_guest_cases":len(candidates)*CASES,
      "native_aarch64_guest_cases":len(candidates)*CASES,
      "operation_types":kinds,
      "entry_evidence":evidences,
      "native_guest_memory_bytes_compared_per_case":256,
      "full_function_proven_only_when_exact_unwind":True,
      "prior_verified_trivial_leafs_not_included":True,
      "main_callee_rva_0x136120_implemented":False,
      "engine_booted":False,
      "native_elf_is_ephemeral":True,
      "untranslated_remill_objects_not_registered":True
    }
    (out/"memory-leaf-native.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
      "# MX Bikes memory-aware native guest linker batch","",
      "- Original distinct direct call targets scanned: **"+str(considered)+"**",
      "- New original memory/address leaf entry paths executed on ARM64: **"+str(len(candidates))+"**",
      "- Original x64 differential cases: **"+str(len(candidates)*CASES)+"**",
      "- Native ARM64 guest-dispatched cases: **"+str(len(candidates)*CASES)+"**",
      "- Original guest-memory bytes compared per case: **256**",
      "- Supported instruction families: **"+", ".join(kinds)+"**",
      "- Verified exact unwind whole-body intervals: **"+str(evidences.get("exact_unwind_interval",0))+"**",
      "- Direct-call leaf paths without unwind: **"+str(evidences.get("closed_direct_call_entry_path_no_unwind",0))+"**",
      "",
      "**This tests MOV/LEA plus RET with bounded guest memory and registers. "
      "Unwindless paths are NOT proven complete functions. No game engine, "
      "Remill whole-function linkage, iOS or graphical boot.**",""
    ])
    (out/"memory-leaf-native.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: memory-leafs.py original.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
