#!/usr/bin/env python3
"""Bulk original Win64 entry->first direct CALL native AArch64 prefix differential.

Only complete, linear, exact-bounded original prefixes are admitted. Original
x64 guest registers/flags/stack MUST match host-C and executed AArch64. No
callee executes, no full parent or game engine function is registered.
Original bytes, generated C and ELF remain on the private CI runner.
"""
from __future__ import annotations
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RDI, UC_X86_REG_RSI,
    UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_bulk_firstcall_triage import STARTUP_ROOTS
from mxbikes_win64_unwind_frame import pdata_index

BASE = 0x140000000
STACK = 0x710000000
ENTRY = STACK + 0x8000 - 8
CASES = 4
MAX_PREFIX_BYTES = 160
MAX_PREFIX_INSNS = 32
MAX_CANDIDATES = 96
MAX_BATCHES = 6
MAX_TOTAL_CANDIDATES = MAX_CANDIDATES * MAX_BATCHES
MAX_PARENT_SCAN = 6000
STACK_WINDOW = 1024
WINDOW_LO = ENTRY - 768
MASK = (1 << 64) - 1
REGS = [
    ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX),
    ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX),
    ("r8", UC_X86_REG_R8), ("r9", UC_X86_REG_R9),
    ("rdi", UC_X86_REG_RDI), ("rsi", UC_X86_REG_RSI),
    ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11),
    ("rbp", UC_X86_REG_RBP), ("rsp", UC_X86_REG_RSP),
    ("rip", UC_X86_REG_RIP),
]
C_REGS = set(n for n, _ in REGS) - {"rsp","rip"}
GP32 = {
    "eax":"rax", "ebx":"rbx", "ecx":"rcx", "edx":"rdx",
    "r8d":"r8","r9d":"r9","edi":"rdi","esi":"rsi",
    "r10d":"r10","r11d":"r11","ebp":"rbp",
}
NATIVE_NAMES = set(C_REGS) | set(GP32) | {"rsp"}

def reg(ins, op):
    if op.type != X86_OP_REG:
        return None
    name = ins.reg_name(op.reg)
    width = op.size
    if width not in (4,8) or name not in NATIVE_NAMES:
        return None
    if width == 4 and name not in GP32:
        return None
    if width == 8 and name not in C_REGS and name != "rsp":
        return None
    return GP32.get(name,name), width

def guest_stack_mem(ins, op):
    if op.type != X86_OP_MEM or op.size not in (4,8):
        return None
    m = op.mem
    base = ins.reg_name(m.base)
    if base not in ("rsp","rbp") or m.index or m.segment or abs(m.disp)>1024:
        return None
    return {"base":base,"disp":m.disp,"size":op.size}

def translate_instruction(ins):
    """Small exact-semantic guest op set. Everything else is rejected."""
    operands=ins.operands
    name=ins.mnemonic
    if name=="nop" and not operands:
        return "(void)0;"
    if name=="push" and len(operands)==1:
        val=reg(ins,operands[0])
        if val and val[1]==8 and val[0]!="rsp":
            return (f"if(s.rsp<8U){{return 10;}}s.rsp-=8U;"
                    f"{{uint64_t v=s.{val[0]};"
                    f"if(!mx_cfg_transfer(&mem,s.rsp,&v,8U,1))return 11;}}")
    if name=="pop" and len(operands)==1:
        val=reg(ins,operands[0])
        if val and val[1]==8 and val[0]!="rsp":
            return (f"{{uint64_t v=0U;if(!mx_cfg_transfer(&mem,s.rsp,&v,8U,0))return 11;"
                    f"s.{val[0]}=v;s.rsp+=8U;}}")
    if name in ("sub","add") and len(operands)==2:
        target=operands[0]
        imm=operands[1]
        if (target.type==X86_OP_REG and ins.reg_name(target.reg)=="rsp" and
            target.size==8 and imm.type==X86_OP_IMM and 0<=imm.imm<=65536):
            if name=="sub":
                return (f"{{uint64_t v=s.rsp;uint64_t b=UINT64_C({imm.imm});"
                        "s.rsp=v-b;s.cf=(v<b);s.zf=(s.rsp==0U);s.sf=(s.rsp>>63U)&1U;}")
            return (f"{{uint64_t v=s.rsp;uint64_t b=UINT64_C({imm.imm});"
                    "s.rsp=v+b;s.cf=(s.rsp<v);s.zf=(s.rsp==0U);s.sf=(s.rsp>>63U)&1U;}")
    if name in ("mov","lea","xor","test") and len(operands)==2:
        a,b=operands
        dst=reg(ins,a)
        src=reg(ins,b)
        if name=="mov":
            if dst and src and dst[1]==src[1]:
                cast="(uint32_t)" if dst[1]==4 else ""
                return f"s.{dst[0]}={cast}s.{src[0]};"
            if dst and b.type==X86_OP_IMM:
                width=dst[1]
                val=b.imm & ((1<<(width*8))-1)
                return f"s.{dst[0]}=UINT64_C({val});"
            mem_src=guest_stack_mem(ins,b)
            mem_dst=guest_stack_mem(ins,a)
            if dst and mem_src and dst[1]==mem_src["size"]:
                m=mem_src
                cast="(uint32_t)" if dst[1]==4 else ""
                return (f"{{uint64_t v=0U;if(!mx_cfg_transfer(&mem,"
                        f"s.{m['base']}+UINT64_C({m['disp']&MASK}),"
                        f"&v,{m['size']}U,0))return 11;"
                        f"s.{dst[0]}={cast}v;}}")
            if mem_dst and src and mem_dst["size"]==src[1]:
                m=mem_dst
                return (f"{{uint64_t v=s.{src[0]};if(!mx_cfg_transfer(&mem,"
                        f"s.{m['base']}+UINT64_C({m['disp']&MASK}),"
                        f"&v,{m['size']}U,1))return 11;}}")
        elif name=="lea" and dst and dst[1]==8 and b.type==X86_OP_MEM:
            base=ins.reg_name(b.mem.base) if b.mem.base else ""
            if base in C_REGS | {"rsp","rip"} and not b.mem.index and not b.mem.segment:
                base_expr=(f"UINT64_C({ins.address+ins.size})" if base=="rip" else f"s.{base}")
                return f"s.{dst[0]}={base_expr}+UINT64_C({b.mem.disp&MASK});"
        elif name=="xor" and dst and src and dst==src:
            return f"s.{dst[0]}=0U;s.cf=0U;s.zf=1U;s.sf=0U;"
        elif name=="test" and dst and src and dst[1]==src[1]:
            mask=("UINT64_C(0xffffffff)" if dst[1]==4 else "UINT64_MAX")
            bit=31 if dst[1]==4 else 63
            return (f"{{uint64_t x=(s.{dst[0]}&s.{src[0]})&{mask};"
                    f"s.cf=0U;s.zf=(x==0U);s.sf=(x>>{bit}U)&1U;}}")
    return None

def candidate_from_blob(blob, base, parent_targets):
    """Reject any branch/unknown instruction before exact direct E8 CALL."""
    md=Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail=True
    offset=0
    statements=[]
    for ins in md.disasm(blob, BASE+base):
        if ins.address != BASE+base+offset:
            return None
        if ins.group(CS_GRP_CALL):
            if ins.bytes[0]!=0xe8 or len(ins.bytes)!=5 or not statements:
                return None
            target=ins.operands[0].imm-BASE
            if target not in parent_targets or ins.address+ins.size != BASE+base+offset+5:
                return None
            return {
                "rva":base, "callsite":ins.address,
                "callee":target, "instructions":len(statements),
                "prefix_bytes":offset, "statements":statements,
                "bytes":blob[:offset+5],
            }
        if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            return None
        native=translate_instruction(ins)
        if not native:
            return None
        statements.append(native)
        offset+=ins.size
        if offset>MAX_PREFIX_BYTES or len(statements)>MAX_PREFIX_INSNS:
            return None
    return None

def prioritized_parent_wave(mapping, limit=MAX_PARENT_SCAN):
    """Scale the candidate wave beyond the original 384-parent survey.

    Rank all original direct-call parents from metadata, preserving startup
    roots and frequency, and execute only privately SHA-pinned original code.
    """
    if not 1 <= limit <= MAX_PARENT_SCAN:
        raise ValueError("Unbounded original caller wave")
    graph = mapping.get("direct_call_graph", {})
    inbound=Counter(int(t,16) for row in graph.values() for t in row)
    ranked=[]
    for parent,children in graph.items():
        if not children:
            continue
        rva=int(parent,16)
        ranked.append((rva,len(set(children)),inbound[rva]))
    startup=set(STARTUP_ROOTS)
    ranked.sort(key=lambda row:(
        0 if row[0] in startup else 1,
        -(4*row[2]+row[1]),-row[2],-row[1],row[0]))
    return ranked[:limit]

def discover(pe, mapping, limit=MAX_TOTAL_CANDIDATES):
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Unverified original game map")
    if not 1<=limit<=MAX_TOTAL_CANDIDATES:
        raise ValueError("Invalid prefix cap")
    pdata=pdata_index(pe)
    selected=[]
    causes=Counter()
    for rva,_,_ in prioritized_parent_wave(mapping):
        if rva not in pdata:
            causes["no_unwind_parent"]+=1
            continue
        end,_=pdata[rva]
        size=min(end-rva, MAX_PREFIX_BYTES+16)
        if size<6:
            causes["short_original_parent"]+=1
            continue
        try:
            body=pe.read_rva(rva,size)
        except ValueError:
            causes["unmapped_parent"]+=1
            continue
        targets={int(v,16) for v in mapping["direct_call_graph"].get(hex(rva),[])}
        item=candidate_from_blob(body,rva,targets)
        if item is None:
            causes["unsupported_prefix_family"]+=1
            continue
        selected.append(item)
        if len(selected)>=limit:
            break
    return selected,causes

def initial_state(case):
    regs={}
    for i,(n,_) in enumerate(REGS):
        regs[n]=(0x123456789abcdef0 + i*0x15151111 + case*0x1010121)&MASK
    regs["rsp"]=ENTRY
    regs["rbp"]=STACK+0x9000
    regs["rip"]=0
    return regs

def original_reference(item, case):
    uc=Uc(UC_ARCH_X86,UC_MODE_64)
    code=BASE+item["rva"]
    # Parent spans at most two pages. Avoid operator-precedence ambiguity.
    lo=code&~4095
    hi=(code+len(item["bytes"])-1)&~4095
    for addr in range(lo,hi+1,4096):
        uc.mem_map(addr,4096)
    uc.mem_write(code,item["bytes"])
    uc.mem_map(STACK,0x10000)
    seed=bytes(((i*13+case*19+3)&255) for i in range(STACK_WINDOW))
    uc.mem_write(WINDOW_LO,seed)
    regs=initial_state(case)
    for name,reg in REGS:
        uc.reg_write(reg, code if name=="rip" else regs[name])
    flag=0x202|[0,1,0x40,0x80][case]
    uc.reg_write(UC_X86_REG_EFLAGS,flag)
    try:
        uc.emu_start(code,item["callsite"],timeout=1000000,
                     count=MAX_PREFIX_INSNS+1)
    except UcError:
        return None
    if uc.reg_read(UC_X86_REG_RIP)!=item["callsite"]:
        return None
    final={name:uc.reg_read(reg) for name,reg in REGS}
    eflags=uc.reg_read(UC_X86_REG_EFLAGS)
    flags=(int(bool(eflags&1)),int(bool(eflags&0x40)),int(bool(eflags&0x80)))
    return regs,flag,final,flags,bytes(uc.mem_read(WINDOW_LO,STACK_WINDOW))

def generate(candidates,references):
    # All source generated only under transient private Actions temp dir.
    bodies=[]
    dataset=[]
    for index,item in enumerate(candidates):
        ops="\n".join(item["statements"])
        bodies.append(
            f"static int run_{index}(struct cpu *sp,mx_cfg_memory*memory){{\n"
            "struct cpu s=*sp;mx_cfg_memory mem=*memory;(void)mem;\n"
            f"{ops}\n"
            f"s.rip=UINT64_C({item['callsite']});"
            "*sp=s;return 0;}\n"
        )
        all_cases=[]
        for (regs,flag,expected,flags,stack) in references[item["rva"]]:
            inputs=[regs[n] for n,_ in REGS]
            outputs=[expected[n] for n,_ in REGS]
            row=("{{"+",".join(f"UINT64_C({v})" for v in inputs)+"},"
                 +str(flag)+",{" +",".join(f"UINT64_C({v})" for v in outputs)+"},"
                 +"{" +",".join(str(v) for v in flags)+"},"
                 +"{" +",".join(str(v) for v in stack)+"}}")
            all_cases.append(row)
        dataset.append("{"+",\n".join(all_cases)+"}")
    code=r'''#include <stdint.h>
#include "mx_cfg_vm.h"
#define COUNT __COUNT__
#define CASES 4U
#define STACK UINT64_C(0x710000000)
#define ENTRY (STACK+UINT64_C(0x7ff8))
#define WINDOW (ENTRY-UINT64_C(768))
#define WINDOW_SIZE 1024U
struct cpu {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r10,r11,rbp,rsp,rip;
 uint8_t cf,zf,sf;
};
typedef struct {
 uint64_t initial[13];uint32_t flags;
 uint64_t expected[13];uint8_t expected_flags[3];uint8_t stack[1024];
} case_data;
static const case_data fixtures[COUNT][CASES]={__DATA__};
static uint8_t stack_mem[65536];
__BODIES__
typedef int (*fn)(struct cpu*,mx_cfg_memory*);
static const fn workers[COUNT]={__WORKERS__};
int smoke(void){
 mx_cfg_region region={STACK,stack_mem,sizeof(stack_mem)};
 mx_cfg_memory memory={&region,1U};
 for(unsigned i=0;i<COUNT;i++)for(unsigned t=0;t<CASES;t++){
  const case_data*f=&fixtures[i][t];
  for(unsigned j=0;j<WINDOW_SIZE;j++)
   stack_mem[ENTRY-768U-STACK+j]=(uint8_t)((j*13U+t*19U+3U)&255U);
  struct cpu s={0};
  uint64_t *regs=&s.rax;
  for(unsigned j=0;j<13U;j++)regs[j]=f->initial[j];
  s.cf=(f->flags&1U)!=0;s.zf=(f->flags&64U)!=0;
  s.sf=(f->flags&128U)!=0;
  if(workers[i](&s,&memory)!=0)return 1;
  for(unsigned j=0;j<13U;j++)if(regs[j]!=f->expected[j])return 2;
  if(s.cf!=f->expected_flags[0]||
     s.zf!=f->expected_flags[1]||
     s.sf!=f->expected_flags[2])return 3;
  for(unsigned j=0;j<WINDOW_SIZE;j++)
   if(stack_mem[ENTRY-768U-STACK+j]!=f->stack[j])return 4;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    for key,val in {
        "__COUNT__":str(len(candidates)),
        "__DATA__":",\n".join(dataset),
        "__BODIES__":"\n".join(bodies),
        "__WORKERS__":",".join(f"run_{i}" for i in range(len(candidates))),
    }.items():
        code=code.replace(key,val)
    return code

def run(original, mapping_json, output):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original executable revision mismatch")
    mapping=json.loads(mapping_json.read_text())
    candidates,reasons=discover(pe,mapping)
    tested=[]
    references={}
    rejected=Counter(reasons)
    for item in candidates:
        samples=[original_reference(item,k) for k in range(CASES)]
        if any(x is None for x in samples):
            rejected["original_x64_reference_failed"]+=1
            continue
        tested.append(item)
        references[item["rva"]]=samples
    # Split large original waves into independently executed ARM64 ELFs so
    # each is below the strict emulator instruction and time limits. Any
    # failing wave aborts the whole proof: no partial registration.
    completed_batches=[]
    for offset in range(0,len(tested),MAX_CANDIDATES):
        chunk=tested[offset:offset+MAX_CANDIDATES]
        source=generate(chunk,references)
        with tempfile.TemporaryDirectory(prefix="mxb-original-native-prefix-") as tmp:
            out=Path(tmp)
            c=out/"original-guest-prefixes.c"
            c.write_text(source)
            flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
                   "-I",str(ROOT/"arm64-lab"/"runtime")]
            host=out/"host"
            p=subprocess.run(["cc",*flags,"-DHOST",str(c),"-o",str(host)],
                             capture_output=True,text=True)
            if p.returncode:
                raise RuntimeError("Host prefix compilation failed: "+p.stderr[-3000:])
            p=subprocess.run([str(host)],capture_output=True,text=True)
            if p.returncode:
                raise RuntimeError("Original x64 vs C host prefix mismatch: "+str(p.returncode))
            elf=out/"arm64.elf"
            p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
                "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
                "-fno-builtin","-fno-stack-protector",*flags,
                "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
                "-Wl,--build-id=none",str(c),"-o",str(elf)],
                capture_output=True,text=True)
            if p.returncode:
                raise RuntimeError("ARM64 prefix compilation failed: "+p.stderr[-3000:])
            res=execute_arm64_elf(elf,instruction_budget=6000000,timeout_us=15000000)
            if res["arm64_smoke_exit"]!=0:
                raise RuntimeError("Original x64 vs executed ARM64 prefix mismatch")
        completed_batches.append({
            "batch_index":len(completed_batches),
            "original_parent_prefixes_native_verified":len(chunk),
            "original_x64_host_arm64_cases":len(chunk)*CASES,
            "native_elf_executed":True,
            "compiled_original_game_code_persisted":False,
        })
    output.mkdir(parents=True,exist_ok=True)
    report={
        "schema":1,"original_sha256":INPUT_SHA,
        "original_parent_wave_cap":MAX_PARENT_SCAN,
        "original_candidate_per_batch_cap":MAX_CANDIDATES,
        "max_native_batches":MAX_BATCHES,
        "native_batches_completed":len(completed_batches),
        "completed_batches":completed_batches,
        "native_verified_parent_prefixes":len(tested),
        "x64_host_arm64_fixture_cases":len(tested)*CASES,
        "original_first_call_targets_with_native_prefixes":[
            {"parent_rva":hex(x["rva"]),"callsite_rva":hex(x["callsite"]-BASE),
             "target_rva":hex(x["callee"]),"original_prefix_instructions":x["instructions"]}
            for x in tested
        ],
        "candidate_rejections":dict(sorted(rejected.items())),
        "full_original_parent_functions_native_verified":0,
        "original_callees_executed":False,
        "native_game_engine_booted":False,
        "proprietary_derived_artifacts_exported":False
    }
    (output/"native-parent-prefix-wave.json").write_text(json.dumps(report,indent=2)+"\n")
    md=["# MX Bikes original caller prefix native AArch64 differential","",
        "- Genuine original parent prefixes executed on native ARM64: **"+
        str(len(tested))+"**",
        "- x64/host/ARM64 four-case differentials: **"+str(len(tested)*CASES)+"**",
        "- Separate native ARM64 batches executed: **"+str(len(completed_batches))+"**",
        "- Complete parent functions newly registered: **0**",
        "- Every CALL intercepted before its callee; no engine or iOS boot.","",
        "| Rejected family | Count |","| --- | ---: |"]
    md.extend("| "+k+" | "+str(v)+" |" for k,v in sorted(rejected.items()))
    (output/"native-parent-prefix-wave.md").write_text("\n".join(md)+"\n")
    print("\n".join(md))
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("sha_pinned_original",type=Path)
    p.add_argument("whole_game_map",type=Path)
    p.add_argument("metadata_dir",type=Path)
    a=p.parse_args()
    run(a.sha_pinned_original,a.whole_game_map,a.metadata_dir)
