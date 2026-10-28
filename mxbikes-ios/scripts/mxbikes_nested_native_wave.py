#!/usr/bin/env python3
"""Batch translate and execute exact original Win64 caller->verified-leaf->RET.

Only exact, straight-line original .pdata parent intervals with bounded
direct CALL chains to same-run, independently ARM64-verified complete leaves
are eligible. All original callees and Win64 stack effects must be verified. No substitute game logic, fabricated callee or unverified
import. The complete original parent and child execute under Unicorn x64,
and ephemeral compiled host C / real AArch64 ELF are differentially tested
for guest registers, flags, 1024 stack bytes and exact final return.
Unsupported branches/ops/guest pointers stay blocked, never promoted.
"""
from __future__ import annotations
import argparse
from collections import Counter
from bisect import bisect_right
import re
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_EFLAGS

import mxbikes_native_prefix_wave as prefix
import mxbikes_native_scalar_ops as scalar
import mxbikes_whole_function_factory as factory
from mxbikes_verified_leaf_autolink import discover as discover_leaves
from mxbikes_whole_game_map import INPUT_SHA

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.import_aot_smoke import execute_arm64_elf

BASE=prefix.BASE
STACK=prefix.STACK
ENTRY=prefix.ENTRY
WINDOW_LO=prefix.WINDOW_LO
STACK_WINDOW=prefix.STACK_WINDOW
SENTINEL=factory.SENTINEL
MAX_BODY_BYTES=256
MAX_PARENT_INSTRUCTIONS=64
MAX_CHILD_BYTES=16
MAX_JOINED=120
MAX_PARENT_CALLS=8
MAX_REUSED_UNWINDLESS=192
RUN_EVIDENCE=re.compile(r"^https://github[.]com/NyerahMT/ReflexBuildInput/actions/runs/[0-9]+$")
BATCH_SIZE=24
FIXTURES=4

def decode_supported_leaf(item):
    """One already native-verified original leaf, no embedded CALL/branch."""
    body=item.get("body")
    if not isinstance(body,bytes) or not 1<=len(body)<=MAX_CHILD_BYTES:
        return None
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    inst=list(md.disasm(body,BASE+item["rva"]))
    if not inst or sum(op.size for op in inst)!=len(body):
        return None
    if not inst[-1].group(CS_GRP_RET) or inst[-1].mnemonic!="ret":
        return None
    native=[]
    for ins in inst[:-1]:
        if ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_RET):
            return None
        c=prefix.translate_instruction(ins)
        if c is None:
            return None
        native.append(c)
    return native

def reconstruct_same_run_unwindless_leaves(pe,mapping,verified,*,limit=MAX_REUSED_UNWINDLESS):
    """Re-read exact original code before linking a prior native proof.

    The input manifest is same-run metadata, not a precompiled native object.
    Only short, fully decoded, contiguous RET leaves with independently
    checked direct-CALL evidence qualify. Every selected parent is re-executed
    against the original x64 and compiled host/AArch64 in this CI pass.
    """
    if not 0<=limit<=MAX_REUSED_UNWINDLESS:
        raise ValueError("Unbounded original unwound-free native reuse")
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Original binary provenance mismatch")
    candidates=mapping.get("unwindless_direct_call_candidates",[])
    intervals=mapping.get("interval_map",[])
    if not isinstance(candidates,list) or len(candidates)>4000 or not isinstance(intervals,list):
        raise ValueError("Invalid original function inventories")
    bounds={}
    for row in candidates:
        addr=int(row["rva"],16)
        if addr in bounds:raise ValueError("Duplicate original direct-CALL entry")
        bounds[addr]=row
    spans=sorted((int(x["rva"],16),int(x["end_rva"],16)) for x in intervals)
    starts=[a for a,b in spans]
    ends=[b for a,b in spans]
    if any(a>=b for a,b in spans):
        raise ValueError("Malformed original PE unwind interval")
    selected=[]
    rejected=Counter()
    seen=set()
    for item in verified:
        if item.get("original_direct_CALL_entry_without_pdata") is not True:
            continue
        addr=int(item["original_rva"],16)
        if addr in seen:raise ValueError("Duplicate original ARM64 registration")
        seen.add(addr)
        proof=bounds.get(addr)
        if not proof or proof.get("unwind_protected") is not False or (
            proof.get("static_first_block_verified") is not True or
            not isinstance(proof.get("direct_call_references"),int) or
            proof["direct_call_references"]<=0):
            rejected["missing_exact_original_direct_call_evidence"]+=1
            continue
        idx=bisect_right(starts,addr)-1
        if idx>=0 and addr<ends[idx]:
            rejected["original_unwind_interval_contains_entry"]+=1
            continue
        if (item.get("full_function_behavior_verified") is not True or
            item.get("win64_guest_call_abi_verified") is not True or
            item.get("code_presence")!="ephemeral_ci_elf_only" or
            item.get("native_symbol")!=f"mx_unwindless_native_{addr:08x}" or
            not RUN_EVIDENCE.fullmatch(item.get("differential_test_run_url",""))):
            rejected["invalid_prior_original_arm64_proof"]+=1
            continue
        if len(selected)>=limit:
            rejected["reuse_limit"]+=1
            continue
        found=None
        for size in range(1,MAX_CHILD_BYTES+1):
            if any(addr<other<addr+size for other in bounds if other!=addr):
                break
            if any(addr<other<addr+size for other in starts):
                break
            try:
                original=bytes(pe.read_rva(addr,size))
            except (ValueError,OverflowError):
                break
            if len(original)!=size:break
            leaf={"rva":addr,"body":original,
                  "kind":"original_direct_call_native_verified_leaf",
                  "boundary_evidence":"exact_same_run_original_unwindless_proof"}
            stmts=decode_supported_leaf(leaf)
            if stmts is not None:
                found=dict(leaf,statements=stmts)
                break
        if found is None:
            rejected["no_supported_complete_original_ret_leaf"]+=1
        else:
            selected.append(found)
    return selected,rejected

def parse_parent(body,rva,eligible_children):
    """Require an entire exact parent body, not a first-CALL prefix."""
    if not isinstance(body,bytes) or not 5<=len(body)<=MAX_BODY_BYTES:
        return None,"parent_size"
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    ins=list(md.disasm(body,BASE+rva))
    if not ins or sum(x.size for x in ins)!=len(body):
        return None,"incomplete_original_x64_decode"
    if len(ins)>MAX_PARENT_INSTRUCTIONS or ins[-1].mnemonic not in ("ret","jmp"):
        return None,"parent_no_supported_final_return_"+ins[-1].mnemonic if ins else "parent_no_supported_final_return_empty"
    if (ins[-1].mnemonic=="ret" and ins[-1].operands) or any(i.group(CS_GRP_RET) for i in ins[:-1]):
        return None,"multiple_original_returns"
    ops=[]
    call_rows=[]
    for insn in ins[:-1]:
        if insn.group(CS_GRP_CALL):
            if (len(insn.bytes)!=5 or insn.bytes[0]!=0xe8 or
                not insn.operands or insn.operands[0].type!=X86_OP_IMM):
                return None,"indirect_or_import_call"
            target=insn.operands[0].imm-BASE
            if target not in eligible_children:
                return None,"unverified_direct_callee"
            call_rows.append((insn.address,target))
            ops.append({"kind":"call","site":insn.address,"target":target,
                        "continue":insn.address+insn.size})
            continue
        if insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET):
            return None,"branch_or_multi_return"
        stmt=prefix.translate_instruction(insn)
        if stmt is None:
            stmt=scalar.translate(insn)
        if stmt is None:
            return None,"unsupported_parent_instruction_"+insn.mnemonic
        ops.append({"kind":"simple","statement":stmt})
    tail_child=None
    if ins[-1].mnemonic=="jmp":
        final=ins[-1]
        if not final.operands or final.operands[0].type!=X86_OP_IMM or final.bytes[0] not in (0xe9,0xeb):
            return None,"indirect_or_unsupported_tail_jump"
        tail_child=final.operands[0].imm-BASE
        if tail_child not in eligible_children:
            return None,"unverified_tail_jump_callee"
        if call_rows:
            return None,"tail_jump_after_other_call_not_supported"
        ops.append({"kind":"tailjmp","target":tail_child})
    elif not 1<=len(call_rows)<=MAX_PARENT_CALLS:
        return None,"original_direct_call_count_outside_verified_budget"
    reason=factory.bounded_original_stack_effect(ins)
    if reason:
        return None,reason
    # The CALL instruction itself pushes onto RSP; Win64 requires RSP
    # 16-byte aligned immediately before the CALL (callee RSP mod 16 = 8).
    # Runtime checks enforce the actual entry fixture alignment.
    chosen_child=tail_child if tail_child is not None else call_rows[0][1]
    all_children=([tail_child] if tail_child is not None else
                  list(dict.fromkeys(target for _,target in call_rows)))
    return {"rva":rva,"bytes":body,"ops":ops,"child_rva":chosen_child,
            "child_rvas":all_children,"original_direct_calls":len(call_rows),
            "native_exit":"tail_jump" if tail_child is not None else "call_then_ret",
            "parent_instructions":len(ins),"return_address":call_rows[0][0]+5 if call_rows else None,
            "boundary":"exact_original_pdata_parent_full_body"},None

def discover(pe,mapping,leaves,verified,limit=MAX_JOINED):
    if not 0<=limit<=MAX_JOINED:
        raise ValueError("Unbounded original nested wave")
    if mapping.get("input_sha256")!=INPUT_SHA or mapping.get("original_file_verified") is not True:
        raise ValueError("Original executable map hash mismatch")
    registered={int(e["original_rva"],16) for e in verified
                if e.get("full_function_behavior_verified") is True
                and e.get("win64_guest_call_abi_verified") is True
                and e.get("code_presence")=="ephemeral_ci_elf_only"}
    supported={}
    for child in leaves:
        if child["rva"] in registered:
            statements=decode_supported_leaf(child)
            if statements is not None:
                supported[child["rva"]]=dict(child,statements=statements)
    selected=[]
    rejected=Counter()
    graph={int(k,16):{int(v,16) for v in vals}
           for k,vals in mapping.get("direct_call_graph",{}).items()}
    by_start={int(r["rva"],16):r for r in mapping.get("interval_map",[])}
    ordered=[]
    included=set()
    for rva,children in graph.items():
        if rva in registered or not (children&supported.keys()):
            continue
        row=by_start.get(rva)
        if row is not None:
            ordered.append((rva,row))
            included.add(rva)
    # Tail-call wrappers can reach verified native leaves via JMP rather than
    # CALL and therefore never appear as edges in direct_call_graph.
    for row in mapping.get("interval_map",[]):
        rva=int(row["rva"],16)
        if (rva not in included and rva not in registered and
            row.get("status")=="decoded_linear" and
            row.get("ret_count")==0 and row.get("escaping_branches",0)>=1 and
            5<=row.get("bytes",0)<=MAX_BODY_BYTES):
            ordered.append((rva,row))
    ordered.sort(key=lambda x:(
        x[1].get("depth_from_known_roots",99) if x[1].get("depth_from_known_roots") is not None else 99,
        x[1]["bytes"],x[0]))
    for rva,row in ordered:
        if row.get("status")!="decoded_linear":
            rejected["parent_not_exact_decoded_pdata"]+=1
            continue
        if not 5<=row.get("bytes",0)<=MAX_BODY_BYTES:
            rejected["parent_outside_full_body_budget"]+=1
            continue
        blob=pe.read_rva(rva,row["bytes"])
        item,reason=parse_parent(blob,rva,supported)
        if item is None:
            rejected[reason]+=1
            continue
        if item["native_exit"]=="call_then_ret" and not set(item["child_rvas"]).issubset(graph.get(rva,set())):
            rejected["call_graph_edge_mismatch"]+=1
            continue
        selected.append(item)
        if len(selected)>=limit:
            break
    return selected,supported,rejected,len(ordered)

def x64_reference(parent,child,case):
    # Backward-compatible single-leaf API for prior differential fixtures.
    children=(child if "rva" not in child else {child["rva"]:child})
    targets=parent.get("child_rvas",[parent["child_rva"]])
    if not 1<=len(targets)<=MAX_PARENT_CALLS:
        return None,"original_child_count_invalid"
    if any(v not in children for v in targets):
        return None,"original_verified_child_missing"
    cpu=Uc(UC_ARCH_X86,UC_MODE_64)
    pages=set()
    for rva,body in [(parent["rva"],parent["bytes"]),
                     *[(r,children[r]["body"]) for r in targets]]:
        a=BASE+rva
        pages.update(range(a&~4095,((a+len(body)-1)&~4095)+1,4096))
    for pg in sorted(pages):
        cpu.mem_map(pg,4096)
    cpu.mem_write(BASE+parent["rva"],parent["bytes"])
    for rva in targets:
        cpu.mem_write(BASE+rva,children[rva]["body"])
    cpu.mem_map(STACK,0x10000)
    seed=bytes((i*13+case*19+3)&255 for i in range(STACK_WINDOW))
    cpu.mem_write(WINDOW_LO,seed)
    cpu.mem_write(ENTRY,SENTINEL.to_bytes(8,"little"))
    start=prefix.initial_state(case)
    flags=0x202|[0,1,0x40,0x80][case]
    for name,reg in prefix.REGS:
        cpu.reg_write(reg,BASE+parent["rva"] if name=="rip" else start[name])
    cpu.reg_write(UC_X86_REG_EFLAGS,flags)
    trace=[]
    def on_code(emulator,address,size,context):
        trace.append(address)
    cpu.hook_add(UC_HOOK_CODE,on_code)
    try:
        cpu.emu_start(BASE+parent["rva"],SENTINEL,timeout=1000000,
                      count=MAX_PARENT_INSTRUCTIONS+
                            MAX_PARENT_CALLS*(MAX_CHILD_BYTES+1)+16)
    except UcError:
        return None,"original_x64_fault"
    if cpu.reg_read(UC_X86_REG_RIP)!=SENTINEL or cpu.reg_read(UC_X86_REG_RSP)!=ENTRY+8:
        return None,"original_win64_return_mismatch"
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    expected={BASE+x.address for x in decoder.disasm(parent["bytes"],parent["rva"])}
    for rva in targets:
        expected.update(BASE+x.address for x in decoder.disasm(children[rva]["body"],rva))
    if set(trace)!=expected:
        return None,"original_unvisited_or_escaped_instruction"
    output={name:cpu.reg_read(reg) for name,reg in prefix.REGS}
    final=cpu.reg_read(UC_X86_REG_EFLAGS)
    finalflags=[int(bool(final&1)),int(bool(final&0x40)),int(bool(final&0x80))]
    return (start,flags,output,finalflags,
            bytes(cpu.mem_read(WINDOW_LO,STACK_WINDOW))),None

def code_for_one_parent(parent,child_map,index):
    targets=parent.get("child_rvas",[parent["child_rva"]])
    if not targets or len(targets)>MAX_PARENT_CALLS:
        raise ValueError("Invalid verified child set")
    child_names={rva:f"child_{index}_{i}" for i,rva in enumerate(targets)}
    definitions=[]
    for rva in targets:
        leaf=child_map.get(rva)
        if leaf is None or leaf.get("statements") is None:
            raise ValueError("Unverified nested native leaf")
        child_code="\n".join(leaf["statements"])
        definitions.append(f"""
static int {child_names[rva]}(struct cpu*sp,mx_cfg_memory*memory){{
 struct cpu s=*sp;mx_cfg_memory mem=*memory;(void)mem;
 {child_code}
 uint64_t ret=0U;
 if(!mx_cfg_transfer(&mem,s.rsp,&ret,8U,0))return 21;
 s.rsp+=8U;s.rip=ret;
 *sp=s;return 0;
}}
""")
    lines=[]
    for op in parent["ops"]:
        if op["kind"]=="simple":
            lines.append(op["statement"])
            continue
        target=BASE+op["target"]
        child_name=child_names.get(op["target"])
        if child_name is None:
            raise ValueError("Missing linked callee")
        if op["kind"]=="tailjmp":
            lines.append(f"{{s.rip=UINT64_C({target});"
                         f"int substatus={child_name}(&s,&mem);"
                         "if(substatus!=0)return 24;"
                         "*sp=s;return 0;}")
            continue
        cont=op["continue"]
        lines.append(f"""
 {{
  if(s.rsp<8U||(s.rsp&15U)!=0U)return 22;
  uint64_t continuation=UINT64_C({cont});
  uint64_t caller_rsp=s.rsp;
  s.rsp-=8U;
  if(!mx_cfg_transfer(&mem,s.rsp,&continuation,8U,1))return 23;
  s.rip=UINT64_C({target});
  int substatus={child_name}(&s,&mem);
  if(substatus!=0)return 24;
  if(s.rsp!=caller_rsp||s.rip!=continuation)return 25;
 }}
""")
    if parent["native_exit"]=="call_then_ret":
        lines.append(factory.RET_STATEMENT)
        lines.append("s.rip=guest_ret;")
    return "\n".join(definitions)+f"""
static int parent_{index}(struct cpu*sp,mx_cfg_memory*memory){{
 struct cpu s=*sp;mx_cfg_memory mem=*memory;(void)mem;
 {"".join(lines)}
 *sp=s;return 0;
}}
"""

def source_for(batch,child_map,refs):
    functions=[]
    rows=[]
    for idx,p in enumerate(batch):
        functions.append(code_for_one_parent(p,child_map,idx))
        cases=[]
        for start,flags,out,finalflags,window in refs[p["rva"]]:
            src=[start[k] for k,_ in prefix.REGS]
            dst=[out[k] for k,_ in prefix.REGS]
            cases.append(
                "{{"+",".join(f"UINT64_C({v})" for v in src)+"},"
                +str(flags)+",{"+",".join(f"UINT64_C({v})" for v in dst)+"},{"
                +",".join(str(v) for v in finalflags)+"},{"
                +",".join(str(b) for b in window)+"}}"
            )
        rows.append("{"+",\n".join(cases)+"}")
    main=r'''#include <stdint.h>
#include "mx_cfg_vm.h"
#define COUNT __COUNT__
#define CASES 4U
#define STACK UINT64_C(0x710000000)
#define ENTRY (STACK+UINT64_C(0x7ff8))
#define SENTINEL UINT64_C(__SENTINEL__)
#define WINDOW (ENTRY-UINT64_C(768))
#define WINDOW_SIZE 1024U
struct cpu {
 uint64_t rax,rbx,rcx,rdx,r8,r9,rdi,rsi,r10,r11,rbp,rsp,rip;
 uint8_t cf,zf,sf;
};
typedef struct{
 uint64_t input[13];uint32_t flags;uint64_t expected[13];
 uint8_t expected_flags[3];uint8_t memory[1024];
} fixture;
static const fixture fixtures[COUNT][CASES]={__FIXTURES__};
static uint8_t guest_stack[65536];
__FUNCTIONS__
typedef int(*native_fn)(struct cpu*,mx_cfg_memory*);
static const native_fn workers[COUNT]={__ENTRIES__};
static const uint64_t starts[COUNT]={__STARTS__};
int smoke(void){
 mx_cfg_region region={STACK,guest_stack,sizeof(guest_stack)};
 mx_cfg_memory memory={&region,1U};
 for(unsigned k=0;k<COUNT;k++)for(unsigned t=0;t<CASES;t++){
  const fixture*f=&fixtures[k][t];
  for(unsigned j=0;j<WINDOW_SIZE;j++)
   guest_stack[WINDOW-STACK+j]=(uint8_t)((j*13U+t*19U+3U)&255U);
  for(unsigned j=0;j<8U;j++)
   guest_stack[ENTRY-STACK+j]=(uint8_t)(SENTINEL>>(8U*j));
  struct cpu s={0};uint64_t *regs=&s.rax;
  for(unsigned j=0;j<13U;j++)regs[j]=f->input[j];
  s.rip=starts[k];
  s.cf=(f->flags&1U)!=0U;s.zf=(f->flags&64U)!=0U;
  s.sf=(f->flags&128U)!=0U;
  if(workers[k](&s,&memory)!=0)return 1;
  for(unsigned j=0;j<13U;j++)if(regs[j]!=f->expected[j])return 2;
  if(s.cf!=f->expected_flags[0]||s.zf!=f->expected_flags[1]||
     s.sf!=f->expected_flags[2])return 3;
  for(unsigned j=0;j<WINDOW_SIZE;j++)
   if(guest_stack[WINDOW-STACK+j]!=f->memory[j])return 4;
 }
 return 0;
}
#ifdef HOST
int main(void){return smoke();}
#endif
'''
    updates={
        "__COUNT__":str(len(batch)),
        "__SENTINEL__":str(SENTINEL),
        "__FIXTURES__":",\n".join(rows),
        "__FUNCTIONS__":"\n".join(functions),
        "__ENTRIES__":",".join(f"parent_{i}" for i in range(len(batch))),
        "__STARTS__":",".join(f"UINT64_C({BASE+p['rva']})" for p in batch),
    }
    for a,b in updates.items():
        main=main.replace(a,b)
    return main

def compile_batch(batch,child_map,refs):
    source=source_for(batch,child_map,refs)
    with tempfile.TemporaryDirectory(prefix="mx-original-nested-native-") as tmp:
        root=Path(tmp)
        code=root/"private-native-call-chain.c"
        code.write_text(source)
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror",
               "-I",str(ROOT/"arm64-lab"/"runtime")]
        host=root/"host"
        p=subprocess.run(["cc",*flags,"-DHOST",str(code),"-o",str(host)],
                         capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("host_compiler: "+p.stderr[-1000:])
        p=subprocess.run([str(host)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("host_reference_mismatch: "+str(p.returncode))
        arm=root/"aarch64.elf"
        p=subprocess.run(["clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,"-Wl,-e,smoke",
            "-Wl,-z,max-page-size=4096","-Wl,--build-id=none",
            str(code),"-o",str(arm)],capture_output=True,text=True)
        if p.returncode:
            raise RuntimeError("arm64_compiler: "+p.stderr[-1000:])
        res=execute_arm64_elf(arm,instruction_budget=6000000,timeout_us=15000000)
        if res["arm64_smoke_exit"]!=0:
            raise RuntimeError("arm64_reference_mismatch: "+str(res["arm64_smoke_exit"]))

def run(original,mapfile,verified_file,out,*,reuse_unwindless=False):
    pe=PE(original)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise RuntimeError("Original MX Bikes SHA mismatch")
    mapping=json.loads(mapfile.read_text())
    prior=json.loads(verified_file.read_text())
    if not isinstance(prior,list):
        raise ValueError("Invalid prior native proof manifest")
    _,leaves,_,_=discover_leaves(original,mapping,None)
    reused,reuse_rejections=(reconstruct_same_run_unwindless_leaves(pe,mapping,prior)
                             if reuse_unwindless else ([],Counter()))
    available={v["rva"]:v for v in leaves}
    for item in reused:
        available.setdefault(item["rva"],item)
    parents,children,rejected,considered=discover(pe,mapping,list(available.values()),prior)
    candidates=[]
    refs={}
    ref_faults=Counter()
    for parent in parents:
        samples=[]
        for case in range(FIXTURES):
            item,why=x64_reference(parent,children,case)
            if why:
                ref_faults[why]+=1
                break
            samples.append(item)
        if len(samples)==FIXTURES:
            candidates.append(parent)
            refs[parent["rva"]]=samples
    proofs=[]
    native_faults=Counter()
    def verify_group(group):
        if not group:
            return
        try:
            compile_batch(group,children,refs)
        except (RuntimeError,ValueError,subprocess.SubprocessError) as e:
            if len(group)>1:
                cut=len(group)//2
                verify_group(group[:cut]);verify_group(group[cut:])
            else:
                native_faults[str(e).split(":",1)[0]]+=1
        else:
            proofs.extend(group)
    for i in range(0,len(candidates),BATCH_SIZE):
        verify_group(candidates[i:i+BATCH_SIZE])
    if len(proofs)>len(candidates):
        raise RuntimeError("Invalid nested original proof accounting")
    # Never promote a parent into the active manifest unless complete original
    # child+parent x64 and executed native state tests passed in THIS CI run.
    run_id=os.environ.get("GITHUB_RUN_ID","")
    if proofs and (not run_id.isdecimal()):
        raise RuntimeError("No trusted GitHub proof execution context")
    url="https://github.com/NyerahMT/ReflexBuildInput/actions/runs/"+run_id
    additions=[{
        "original_rva":hex(v["rva"]),
        "native_symbol":f"mx_verified_{v['rva']:08x}",
        "full_function_behavior_verified":True,
        "win64_guest_call_abi_verified":True,
        "code_presence":"ephemeral_ci_elf_only",
        "differential_test_run_url":url,
        "proof_scope":"Exact original .pdata parent and native-verified original child; original Win64 CALL/RET guest ABI and full 1024-byte stack comparison across four x64/host/AArch64 fixtures",
    } for v in proofs]
    combined={int(x["original_rva"],16):x for x in prior}
    for entry in additions:
        addr=int(entry["original_rva"],16)
        if addr in combined:raise RuntimeError("Duplicate native registered parent")
        combined[addr]=entry
    out.mkdir(parents=True,exist_ok=True)
    (out/"verified-batch-registrations.json").write_text(
        json.dumps(list(combined.values()),indent=2)+"\n")
    stats={
        "schema":1,
        "original_sha256":INPUT_SHA,
        "reused_native_unwindless_proofs":reuse_unwindless,
        "reconstructed_verified_original_unwindless_leaves":len(reused),
        "unwindless_leaf_reconstruction_rejections":dict(sorted(reuse_rejections.items())),
        "original_parents_with_direct_edges_to_known_native_leaves":considered,
        "exact_single_direct_call_parent_candidates":sum(p["original_direct_calls"]==1 for p in parents),
        "bounded_multiple_direct_call_parent_candidates":sum(p["original_direct_calls"]>1 for p in parents),
        "exact_complete_parent_candidates":len(parents),
        "complete_original_x64_nested_return_candidates":len(candidates),
        "whole_new_native_parent_functions_verified":len(proofs),
        "verified_original_direct_CALLs_in_complete_parents":sum(p["original_direct_calls"] for p in proofs),
        "native_verified_call_then_return_parents":sum(p["native_exit"]=="call_then_ret" for p in proofs),
        "native_verified_tail_call_wrappers":sum(p["native_exit"]=="tail_jump" for p in proofs),
        "native_x64_host_arm64_differential_cases":len(proofs)*FIXTURES,
        "merged_runtime_metadata_registrations":len(combined),
        "source_or_executable_exported":False,
        "game_engine_booted":False,
        "rejections":dict(sorted(rejected.items())),
        "original_reference_failures":dict(sorted(ref_faults.items())),
        "native_rejections":dict(sorted(native_faults.items())),
        "new_native_parent_rvas":[hex(v["rva"]) for v in proofs],
    }
    suffix="-second" if reuse_unwindless else ""
    (out/f"nested-native-full-call-wave{suffix}.json").write_text(json.dumps(stats,indent=2)+"\n")
    lines=["# MX Bikes original Win64 nested call native translator","",
        "- Second native callee reuse wave: **"+("YES" if reuse_unwindless else "NO")+"**",
        "- Reconstructed original proven unwindless leaves: **"+str(len(reused))+"**",
        "- Original parent functions with direct edges to verified leaves: **"+str(considered)+"**",
        "- Supported complete original parent CALL/RET or tail-jump shapes: **"+str(len(parents))+"**",
        "- Original complete parents with multiple bounded verified direct CALLs: **"+str(sum(p["original_direct_calls"]>1 for p in parents))+"**",
        "- Complete new original parent functions x64/host/ARM64 verified: **"+str(len(proofs))+"**",
        "- Native-verified direct JMP tail-call wrappers: **"+str(sum(p['native_exit']=='tail_jump' for p in proofs))+"**",
        "- Nested CALL/RET differential cases: **"+str(len(proofs)*FIXTURES)+"**",
        "- Merged verified native registry metadata entries: **"+str(len(combined))+"**",
        "- iOS boot or graphics executed: **NO**","",
        "## Unsupported original call-family reasons",
        "| Reason | Functions |","| --- | ---: |"]
    lines.extend("| "+x+" | "+str(v)+" |" for x,v in rejected.most_common())
    lines.extend(["","**No CALLs are skipped, imported services faked, or unverified functions promoted.**",""])
    (out/f"nested-native-full-call-wave{suffix}.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return stats

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("sha_pinned_original",type=Path)
    ap.add_argument("whole_game_map",type=Path)
    ap.add_argument("previous_native_proofs",type=Path)
    ap.add_argument("metadata_dir",type=Path)
    ap.add_argument("--reuse-unwindless",action="store_true")
    args=ap.parse_args()
    run(args.sha_pinned_original,args.whole_game_map,
        args.previous_native_proofs,args.metadata_dir,
        reuse_unwindless=args.reuse_unwindless)
