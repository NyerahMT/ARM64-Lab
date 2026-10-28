#!/usr/bin/env python3
"""Bounded static register/memory provenance for original startup CALL 0x130722.

This is analysis of *possible* x64 paths following the unsupported original
Steam restart import. No Steam return value is set, Steam client is not
invoked, and later native or game-engine execution is never claimed.
"""
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

from mxbikes_post_steam_static_successors import (
    STEAM_RETURN_RVA, STEAM_CALL_RVA, STEAM_IAT_RVA, STEAM_SYMBOL,
    containing_unwind, _one, _direct_target, classify_call, map_possible_successors
)
from mxbikes_first_callee_emu import import_slots
from mxbikes_whole_game_map import INPUT_SHA

TARGET_RVA=0x130722
MAX_PATHS=64
MAX_PATH_STEPS=96
MAX_QUEUE=4096
MAX_CALL_FALLTHROUGHS=8
BASE=0x140000000

_ALIASES={
 "rax":"rax","eax":"rax","ax":"rax","al":"rax","ah":"rax",
 "rbx":"rbx","ebx":"rbx","bx":"rbx","bl":"rbx","bh":"rbx",
 "rcx":"rcx","ecx":"rcx","cx":"rcx","cl":"rcx","ch":"rcx",
 "rdx":"rdx","edx":"rdx","dx":"rdx","dl":"rdx","dh":"rdx",
 "rsi":"rsi","esi":"rsi","si":"rsi","sil":"rsi",
 "rdi":"rdi","edi":"rdi","di":"rdi","dil":"rdi",
 "rbp":"rbp","ebp":"rbp","bp":"rbp","bpl":"rbp",
 "rsp":"rsp","esp":"rsp","sp":"rsp","spl":"rsp",
 "rip":"rip","eip":"rip",
}
for _index in range(8,16):
    for _suffix in ("","d","w","b"):
        _ALIASES["r"+str(_index)+_suffix]="r"+str(_index)

def family(register):
    return _ALIASES.get(register, register)

def operand_info(ins,op):
    if op.type==X86_OP_REG:
        return {"type":"register","register":family(ins.reg_name(op.reg))}
    if op.type==X86_OP_MEM:
        mem=op.mem
        return {
            "type":"memory",
            "base":family(ins.reg_name(mem.base)) if mem.base else None,
            "index":family(ins.reg_name(mem.index)) if mem.index else None,
            "scale":mem.scale,
            "displacement":mem.disp
        }
    if op.type==X86_OP_IMM:
        # No proprietary original immediates are needed to explain the dependency.
        return {"type":"immediate"}
    return {"type":"unknown"}

def static_paths(pe,*,base=BASE,return_rva=STEAM_RETURN_RVA,
                 target_rva=TARGET_RVA,max_paths=MAX_PATHS):
    """Enumerate possible intraprocedural paths; CALL returns are assumptions."""
    start,end=containing_unwind(pe,return_rva)
    if not start<=return_rva<=target_rva<end:
        raise ValueError("Target and return not in same original unwind")
    dec=Cs(CS_ARCH_X86,CS_MODE_64);dec.detail=True
    todo=deque([(return_rva,(),frozenset(),0)])
    paths=[]
    examined=0
    while todo:
        if examined>=MAX_QUEUE:
            raise ValueError("Static provenance queue exceeded strict budget")
        examined+=1
        pc,steps,seen,foreign_calls=todo.popleft()
        if pc==target_rva:
            target=_one(pe,dec,pc,end,base)
            if target.mnemonic!="call" or len(target.operands)!=1 or target.operands[0].type not in (X86_OP_REG,X86_OP_MEM):
                raise ValueError("Expected unresolved indirect CALL moved")
            paths.append((steps,target))
            if len(paths)>max_paths:
                raise ValueError("Too many possible original code paths")
            continue
        if not start<=pc<end or pc in seen or len(steps)>=MAX_PATH_STEPS:
            continue
        try:ins=_one(pe,dec,pc,end,base)
        except (ValueError,OverflowError):
            continue
        if ins.mnemonic.startswith("ret") or ins.mnemonic in ("ud2","int","int3","hlt","syscall"):
            continue
        nextpc=pc+ins.size
        newsteps=steps+(ins,)
        newseen=seen|{pc}
        if ins.group(CS_GRP_JUMP):
            dest=_direct_target(ins,base)
            if dest is None:continue
            todo.append((dest,newsteps,newseen,foreign_calls))
            if ins.mnemonic!="jmp":
                todo.append((nextpc,newsteps,newseen,foreign_calls))
        elif ins.mnemonic=="call":
            if foreign_calls<MAX_CALL_FALLTHROUGHS:
                todo.append((nextpc,newsteps,newseen,foreign_calls+1))
        else:
            todo.append((nextpc,newsteps,newseen,foreign_calls))
    if not paths:
        raise ValueError("Unresolved indirect CALL is not on a bounded possible path")
    return paths

def _unknown(reg):
    return {"kind":"unproven_entry_register","register":reg}

def _source_of(state,reg):
    return state.get(reg,_unknown(reg))

def _limit_origin(source,depth=0):
    """No unbounded JSON growth when chains traverse many register writes."""
    if depth>6:return {"kind":"provenance_depth_limit"}
    if isinstance(source,dict):
        return {k:(_limit_origin(v,depth+1) if k in ("source","base_origin","index_origin")
                  else v) for k,v in source.items()}
    return source

def trace_path(steps,target,slots,*,base=BASE):
    """Conservative register abstract interpretation; never infer CALL results."""
    state={}
    calls=[]
    for ins in steps:
        pc=ins.address-base
        if ins.mnemonic=="call":
            call=classify_call(ins,slots,base)
            calls.append({k:call[k] for k in ("site_rva","kind")
                          if k in call} | {k:call[k] for k in
                          ("library","symbol","target_rva") if k in call})
            # Win64 ABI permits external and internal calls to overwrite all
            # volatile GPRs; returning to the next PC is only hypothetical.
            for reg in ("rcx","rdx","r8","r9","r10","r11"):
                state[reg]={"kind":"call_clobbered","site_rva":hex(pc)}
            state["rax"]={"kind":"unobserved_call_result",
                          "site_rva":hex(pc),
                          "library":call.get("library"),
                          "symbol":call.get("symbol"),
                          "target_rva":call.get("target_rva")}
            continue

        ops=ins.operands
        if len(ops)>=2 and ops[0].type==X86_OP_REG and ins.mnemonic in (
            "mov","movzx","movsxd","movsx","lea"):
            dest=family(ins.reg_name(ops[0].reg))
            src=ops[1]
            if src.type==X86_OP_REG:
                name=family(ins.reg_name(src.reg))
                origin={"kind":"register_copy","register":name,
                        "source":_source_of(state,name)}
            elif src.type==X86_OP_MEM:
                shape=operand_info(ins,src)
                origin={"kind":"lea_address" if ins.mnemonic=="lea" else "guest_memory_load",
                        "memory":shape,
                        "base_origin":_source_of(state,shape["base"]) if shape["base"] else None,
                        "index_origin":_source_of(state,shape["index"]) if shape["index"] else None}
            elif src.type==X86_OP_IMM:
                origin={"kind":"instruction_constant"}
            else:
                origin={"kind":"unsupported_operand_origin"}
            state[dest]={"kind":"register_write","site_rva":hex(pc),
                         "mnemonic":ins.mnemonic,"source":_limit_origin(origin)}
            continue

        # For unmodeled instructions, invalidate any register they can write.
        # TEST/CMP and conditional branch do not write GPRs.
        try:_read,write=ins.regs_access()
        except (ValueError,AttributeError):write=[]
        for reg_id in write:
            reg=family(ins.reg_name(reg_id))
            if reg in _ALIASES.values() and reg!="rip":
                state[reg]={"kind":"unmodeled_register_write",
                            "site_rva":hex(pc),"mnemonic":ins.mnemonic}
    shape=operand_info(target,target.operands[0])
    if shape["type"]=="register":
        source=_source_of(state,shape["register"])
    elif shape["type"]=="memory":
        source={"kind":"indirect_memory_target","memory":shape,
                "base_origin":_source_of(state,shape["base"]) if shape["base"] else None,
                "index_origin":_source_of(state,shape["index"]) if shape["index"] else None}
    else:
        raise ValueError("Unsupported target operand")
    return {"target_operand":shape,"target_provenance":_limit_origin(source),
            "possible_prior_calls":calls,
            "possible_path_rvas":[hex(i.address-base) for i in steps],
            "hypothetical_return_from_imports":True,
            "runtime_target_address_known":False,
            "game_engine_function_verified":False}

def analyze(pe,imports,*,base=BASE,return_rva=STEAM_RETURN_RVA,
            target_rva=TARGET_RVA,call_rva=STEAM_CALL_RVA,
            expected_slot=STEAM_IAT_RVA,expected_symbol=STEAM_SYMBOL):
    previous=map_possible_successors(pe,imports,base=base,return_rva=return_rva,
            call_rva=call_rva,expected_slot=expected_slot,
            expected_symbol=expected_symbol)
    if previous["incomplete"]:
        raise ValueError("Previous original callsite scan not complete")
    if not any(x["site_rva"]==hex(target_rva) and
               x["kind"].startswith("indirect") for x in previous["possible_calls"]):
        raise ValueError("Unresolved callsite absent from trusted static scan")
    slots={r:(d.lower(),s) for r,d,s in imports}
    possible=static_paths(pe,base=base,return_rva=return_rva,
                          target_rva=target_rva)
    traces=[trace_path(path,inst,slots,base=base) for path,inst in possible]
    # Deduplicate by target/source and prior import history, not by a single
    # arbitrarily chosen first path.
    unique={}
    for trace in traces:
        key=json.dumps({"operand":trace["target_operand"],
              "origin":trace["target_provenance"],
              "calls":trace["possible_prior_calls"]},sort_keys=True)
        unique.setdefault(key,trace)
    return {
        "original_steam_return_rva":hex(return_rva),
        "original_indirect_call_rva":hex(target_rva),
        "bounded_possible_paths":len(possible),
        "unique_provenance_variants":len(unique),
        "candidate_provenances":list(unique.values()),
        "all_prior_calls_hypothetical":True,
        "no_actual_steam_import_called":True,
        "actual_indirect_target_resolved":False,
        "native_engine_execution_verified":False
    }

def run(exe,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("SHA-pinned original executable changed")
    out=Path(out)
    prior=json.loads((out/"original-post-steam-static-successors.json").read_text())
    if not prior.get("original_exe_sha_verified") or not prior.get(
        "prior_native_steam_stop_verified") or prior.get(
        "original_steam_return_rva")!=hex(STEAM_RETURN_RVA):
        raise ValueError("Cannot inspect unknown post-Steam source")
    report=analyze(pe,import_slots(pe))
    report["original_exe_sha_verified"]=True
    out.mkdir(parents=True,exist_ok=True)
    (out/"post-steam-indirect-provenance.json").write_text(
        json.dumps(report,indent=2)+"\n")
    summary=["# MX Bikes original indirect-call provenance (static only)","",
        "- Original unresolved call: **"+hex(TARGET_RVA)+"**",
        "- Enumerated hypothetical original paths: **"+str(report["bounded_possible_paths"])+"**",
        "- Distinct source/provenance variants: **"+str(report["unique_provenance_variants"])+"**",
        "- Original Steam imports executed: **NO**",
        "- Original engine code executed after Steam: **NO**","",
        "## Indirect call operands and source chains"]
    for i,row in enumerate(report["candidate_provenances"]):
        summary.append("### Candidate "+str(i+1))
        summary.append("- Operand: \`"+json.dumps(row["target_operand"],sort_keys=True)+"\`")
        summary.append("- Source: \`"+json.dumps(row["target_provenance"],sort_keys=True)+"\`")
        summary.append("- Hypothetical prior calls: "+(", ".join(
            (x.get("library","")+("!" if x.get("library") else "")+
             x.get("symbol",x.get("target_rva","unknown")))
            for x in row["possible_prior_calls"]) or "none"))
    summary.extend(["","No Steam return values are invented. The actual",
                    "dynamic indirect target and engine entry remain unknown.",""])
    (out/"post-steam-indirect-provenance.md").write_text("\n".join(summary))
    print("\n".join(summary))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: provenance.py original.exe reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
