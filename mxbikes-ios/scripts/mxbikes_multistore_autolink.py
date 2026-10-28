#!/usr/bin/env python3
"""Batch translate original straight-line MOV/XOR store entry paths to native ARM64.

Only original SHA-matched direct call targets. Fails closed unless every
instruction before the first RET is from a strictly modelled operand subset.
Unwindless entries count as verified ENTRY PATHS, not complete game functions.
Original code, private C translations and native ELF stay on the CI runner.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import hashlib,json,subprocess,sys,tempfile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_REG,X86_OP_MEM,X86_OP_IMM
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_EFLAGS
from mxbikes_memory_leaf_autolink import (
  BASE,MEM,RCX,STACK,PARENT_SP,RET,CALLSITE,GP,GP_MAP,FIELDS,
  _input,_scratch
)
from mxbikes_whole_game_map import map_executable
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

EXE_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
MAX_BYTES=80
MAX_INSTRUCTIONS=12
MAX_TARGETS=64
CASES=8

def operand(inst,op):
    if op.type==X86_OP_REG:
        name=inst.reg_name(op.reg)
        if name not in GP_MAP or op.size not in (4,8):
            return None
        return {"type":"reg","name":GP_MAP[name],"size":op.size}
    if op.type==X86_OP_IMM:
        return {"type":"imm","value":op.imm,"size":op.size}
    if op.type==X86_OP_MEM:
        m=op.mem
        if (inst.reg_name(m.base)!="rcx" or m.index or m.segment or
            op.size not in (4,8) or not 0<=m.disp<=192):
            return None
        return {"type":"mem","offset":m.disp,"size":op.size}
    return None

def decode(inst):
    ops=inst.operands
    if inst.mnemonic=="nop" and not ops:return {"kind":"nop"}
    if inst.mnemonic=="xor" and len(ops)==2:
        a,b=operand(inst,ops[0]),operand(inst,ops[1])
        if not a or not b or a["type"]!="reg" or b["type"]!="reg" or a!=b:
            return None
        return {"kind":"xor_self","dest":a}
    if inst.mnemonic=="mov" and len(ops)==2:
        a,b=operand(inst,ops[0]),operand(inst,ops[1])
        if not a or not b:return None
        if a["type"]=="reg":
            if b["type"] not in ("reg","imm") or b["size"]!=a["size"]:
                return None
        elif a["type"]=="mem":
            if b["type"] not in ("reg","imm"):
                return None
            if b["type"]=="reg" and a["size"]!=b["size"]:
                return None
            if b["type"]=="imm" and a["size"]!=4:
                return None
        else:return None
        return {"kind":"mov","dest":a,"src":b}
    return None

def discover(exe):
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Original MX Bikes executable SHA mismatch")
    mapping=map_executable(exe)
    starts={int(row["rva"],16):row for row in mapping["interval_map"]}
    targets=Counter(int(x,16) for xs in mapping["direct_call_graph"].values() for x in xs)
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    selected=[]
    reasons=Counter()
    seen=set()
    for rva,refs in targets.most_common():
        if rva in seen:continue
        seen.add(rva)
        original=starts.get(rva)
        if original and (original["status"]!="decoded_linear" or
                         original["bytes"]>MAX_BYTES):
            reasons["unwind_not_eligible"]+=1;continue
        amount=original["bytes"] if original else MAX_BYTES
        try:
            blob=pe.read_rva(rva,amount)
        except ValueError:
            reasons["unmapped"]+=1;continue
        decoded=list(md.disasm(blob,rva))
        if not decoded:
            reasons["no_decode"]+=1;continue
        ops=[]
        total=0
        closed=False
        for ins in decoded:
            if len(ops)>=MAX_INSTRUCTIONS:
                reasons["exceeded_instruction_cap"]+=1;break
            if ins.mnemonic=="ret" and len(ins.operands)==0:
                closed=True
                total+=ins.size
                break
            item=decode(ins)
            if item is None:
                reasons["unsupported_op"]+=1;break
            ops.append(item)
            total+=ins.size
        if not closed or len(ops)<2:
            reasons["not_multistep_closed_path"]+=1;continue
        if original and total!=original["bytes"]:
            reasons["unwind_not_full_interval"]+=1;continue
        if not any(x["kind"]=="mov" and x["dest"]["type"]=="mem" for x in ops):
            reasons["no_store"]+=1;continue
        body=pe.read_rva(rva,total)
        if sum(x.size for x in md.disasm(body,rva))!=len(body):
            reasons["incomplete_exact_decode"]+=1;continue
        selected.append({"rva":rva,"raw":body,"ops":ops,
                         "refs":refs,"instructions":len(ops)+1,
                         "boundary_evidence":("exact_unwind_interval" if original
                                              else "closed_direct_call_path_no_unwind")})
        if len(selected)>=MAX_TARGETS:break
    return selected,len(targets),reasons

def original(candidate,case):
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    va=BASE+candidate["rva"]
    cpu.mem_map(va&~4095,8192)
    cpu.mem_write(va,candidate["raw"])
    cpu.mem_map(MEM,4096)
    cpu.mem_map(STACK,0x10000)
    seed=_scratch(case)
    cpu.mem_write(MEM,seed)
    cpu.mem_write(PARENT_SP-8,RET.to_bytes(8,"little"))
    inp=_input(case);inp["rcx"]=RCX
    for name,reg in GP:cpu.reg_write(reg,inp[name])
    flags=0x202|([0,1,0x40,0x80,0xc1,0x41,0x200,0x81][case])
    cpu.reg_write(UC_X86_REG_EFLAGS,flags)
    cpu.reg_write(UC_X86_REG_RIP,va)
    cpu.reg_write(UC_X86_REG_RSP,PARENT_SP-8)
    cpu.emu_start(va,RET,timeout=1200000,count=MAX_INSTRUCTIONS+2)
    finflags=cpu.reg_read(UC_X86_REG_EFLAGS)
    out={name:cpu.reg_read(reg) for name,reg in GP}
    out.update({"rsp":cpu.reg_read(UC_X86_REG_RSP),
                "rip":cpu.reg_read(UC_X86_REG_RIP),
                "cf":int(bool(finflags&1)),
                "zf":int(bool(finflags&0x40)),
                "sf":int(bool(finflags&0x80))})
    if out["rsp"]!=PARENT_SP or out["rip"]!=RET:
        raise RuntimeError(f"Original function {candidate['rva']:#x} failed to return")
    return inp,flags,out,bytes(cpu.mem_read(MEM,256))

def make_statement(op):
    if op["kind"]=="nop":return "(void)0;"
    if op["kind"]=="xor_self":
        v=op["dest"]["name"]
        return f"s->{v}=0U;s->cf=0U;s->zf=1U;s->sf=0U;"
    a,b=op["dest"],op["src"]
    if b["type"]=="reg":source="s->"+b["name"]
    elif b["type"]=="imm":source=f"UINT64_C({b['value']&((1<<64)-1)})"
    else:raise RuntimeError("Unsupported source in native multi-store generator")
    if a["type"]=="reg":
        return f"s->{a['name']}="+(f"(uint32_t)({source});" if a["size"]==4
                                 else f"{source};")
    if a["type"]=="mem":
        return (f"{{uint64_t tmp=(uint64_t)({source});"
                f"if(!mx_cfg_transfer(mem,s->rcx+UINT64_C({a['offset']}),"
                f"&tmp,{a['size']}U,1))return MX_NATIVE_LINK_STACK;}}")
    raise RuntimeError("Unknown destination")

def generate(selected,references):
    ordered=sorted(selected,key=lambda x:x["rva"])
    bodies=[]
    entries=[]
    cases=[]
    for item in ordered:
        name=f"mx_verified_multi_{item['rva']:08x}"
        statements="\n".join(make_statement(op) for op in item["ops"])
        bodies.append(f"""
static int {name}(mx_crt_cluster_state*s,mx_cfg_memory*mem,void*unused){{
 (void)unused;
 if(!s||!mem||s->rip!=BASE+UINT64_C({item['rva']})||(s->rsp&15U)!=8U)
   return MX_NATIVE_LINK_INVALID;
 uint64_t ret=0U;
 if(!mx_cfg_transfer(mem,s->rsp,&ret,8U,0))return MX_NATIVE_LINK_STACK;
 {statements}
 s->rip=ret;s->rsp+=8U;
 return MX_NATIVE_LINK_OK;
}}
""")
        entries.append(f"{{BASE+UINT64_C({item['rva']}),{name},0}}")
        variants=[]
        for inp,fl,out,buf in references[item["rva"]]:
            before=[inp[n] for n,_ in GP]
            after=[out[n] for n in FIELDS]
            variants.append("{{"+",".join(f"UINT64_C({v})" for v in before)+"},"
                +str(fl)+",{"+",".join(f"UINT64_C({v})" for v in after)+"},{"
                +",".join(str(x) for x in buf)+"}}")
        cases.append("{"+",\n".join(variants)+"}")
    template=r'''#include <stdint.h>
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
 uint64_t inputs[9];uint32_t flags;
 uint64_t expected[14];uint8_t memory[256];
} test_case;
static const test_case cases[COUNT][CASES]={__TESTS__};
static uint8_t guest_stack[65536],guest_memory[4096];
__BODIES__
static const mx_native_link_entry entries[COUNT]={__ENTRIES__};
int smoke(void){
 mx_cfg_region areas[2]={{STACK,guest_stack,65536U},
                         {MEM,guest_memory,4096U}};
 mx_cfg_memory mem={areas,2U};
 mx_native_link_registry router={0};
 router.entries=entries;router.count=COUNT;router.max_depth=8U;
 if(mx_native_link_seal(&router)!=MX_NATIVE_LINK_OK)return 1;
 for(unsigned i=0;i<COUNT;i++){
  for(unsigned k=0;k<CASES;k++){
   const test_case*t=&cases[i][k];
   mx_crt_cluster_state s={0};
   s.rax=t->inputs[0];s.rbx=t->inputs[1];s.rcx=t->inputs[2];
   s.rdx=t->inputs[3];s.r8=t->inputs[4];s.r9=t->inputs[5];
   s.rdi=t->inputs[6];s.rsi=t->inputs[7];s.r11=t->inputs[8];
   s.cf=(t->flags&1U)!=0U;s.zf=(t->flags&0x40U)!=0U;
   s.sf=(t->flags&0x80U)!=0U;
   s.rip=CALLSITE;s.rsp=PARENT_SP;
   for(unsigned j=0;j<256U;j++)
      guest_memory[j]=(uint8_t)((j*23U+k*17U+7U)&255U);
   int result=mx_native_link_call(&router,&s,&mem,
                                  entries[i].original_va,RET);
   if(result!=MX_NATIVE_LINK_OK)return 2;
   const uint64_t actual[14]={
    s.rax,s.rbx,s.rcx,s.rdx,s.r8,s.r9,s.rdi,s.rsi,s.r11,
    s.rsp,s.rip,s.cf,s.zf,s.sf
   };
   for(unsigned j=0;j<14U;j++)
     if(actual[j]!=t->expected[j])return 3;
   for(unsigned j=0;j<256U;j++)
     if(guest_memory[j]!=t->memory[j])return 4;
  }
 }
 if(router.calls_completed!=COUNT*CASES ||router.unresolved_calls||
    router.active_depth)return 5;
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    for key,value in {
        "__COUNT__":str(len(ordered)),
        "__TESTS__":",\n".join(cases),
        "__BODIES__":"\n".join(bodies),
        "__ENTRIES__":",\n".join(entries)
    }.items():template=template.replace(key,value)
    return template

def run(executable,destination):
    selected,inspected,rejections=discover(executable)
    if not selected:
        raise RuntimeError("No multi-instruction bounded MOV/XOR memory paths found")
    references={}
    for item in selected:
        references[item["rva"]]=[original(item,k) for k in range(CASES)]
    generated=generate(selected,references)
    with tempfile.TemporaryDirectory(prefix="mxb-private-multistore-") as d:
        root=Path(d);c=root/"x64-original-batched-mov-xor.c";c.write_text(generated)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        result=subprocess.run(["cc",*flags,"-DHOST",str(c),"-o",str(host)],
                              capture_output=True,text=True)
        if result.returncode:raise RuntimeError("Host compilation error: "+result.stderr[-2000:])
        result=subprocess.run([str(host)],capture_output=True,text=True)
        if result.returncode:
            raise RuntimeError("Host original/native differential exit "+str(result.returncode))
        arm=root/"arm64.elf"
        result=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(c),"-o",str(arm)],
            capture_output=True,text=True)
        if result.returncode:raise RuntimeError("ARM64 compilation error: "+result.stderr[-2000:])
        arm_result=execute_arm64_elf(arm,instruction_budget=1950000,
                                     timeout_us=15000000)
        if arm_result["arm64_smoke_exit"]!=0:
            raise RuntimeError("ARM64 guest dispatcher mismatch: "+str(arm_result["arm64_smoke_exit"]))
    destination.mkdir(parents=True,exist_ok=True)
    kinds=Counter(op["kind"] for item in selected for op in item["ops"])
    evidences=Counter(item["boundary_evidence"] for item in selected)
    report={
      "original_game_sha_verified":True,
      "distinct_original_direct_call_targets_scanned":inspected,
      "new_original_multistep_entry_paths_native_arm64_executed":len(selected),
      "original_x64_reference_cases":len(selected)*CASES,
      "native_host_function_dispatches":len(selected)*CASES,
      "native_aarch64_function_dispatches":len(selected)*CASES,
      "original_guest_memory_bytes_checked_per_case":256,
      "native_instruction_families":dict(kinds),
      "boundary_evidence":dict(evidences),
      "original_entry_path_rvas":[hex(item["rva"]) for item in selected],
      "full_function_behavior_verified_only_if_exact_unwind":True,
      "original_game_main_0x136120_executed":False,
      "executable_persisted":False,
      "engine_booted":False,
      "limitations":"Only closed branch-free MOV and XOR-to-zero guest memory store paths. Unwindless entry paths not certified complete functions."
    }
    (destination/"multistore-native-differential.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes — verified multi-instruction native auto-link batch","",
        "- Original direct-call targets scanned: **"+str(inspected)+"**",
        "- New multi-instruction original entry paths executed natively: **"+str(len(selected))+"**",
        "- Original x64 reference cases: **"+str(len(selected)*CASES)+"**",
        "- Native ARM64 linked calls: **"+str(len(selected)*CASES)+"**",
        "- Each case validates 256 guest-memory bytes and GP/flags: **YES**",
        "- Operations exercised: **"+", ".join(f"{k} ({v})" for k,v in kinds.items())+"**",
        "- Exact unwind-covered entire intervals: **"+str(evidences.get("exact_unwind_interval",0))+"**",
        "- Unwindless bounded entry paths: **"+str(evidences.get("closed_direct_call_path_no_unwind",0))+"**",
        "",
        "**This verifies bounded entry paths only where no unwind metadata exists. "
        "No unverified Remill object is registered, no game engine or graphics boot.**",""
    ])
    (destination/"multistore-native-differential.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: multistore.py original-exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
