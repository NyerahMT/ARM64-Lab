#!/usr/bin/env python3
"""Prioritize ORIGINAL non-Steam game-main CALL dependencies after init returns.

Work independently of the Steamworks pointer path by statically entering
original Win64 game-main at the return PC of CALL 0x13677f -> 0x133e80.
That initializer has NOT returned in the native fused game startup; these are
possible original x64 successors, never a claim that a service or engine ran.

Scans bounded in-function conditional paths, then performs a bounded call-only
audit of distinct direct original callees to identify those with no *observed*
Steam imports. No original instruction bytes or native machine objects leave CI.
"""
from __future__ import annotations
from collections import Counter,deque
import hashlib,json,struct,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from mxbikes_first_callee_emu import import_slots
from mxbikes_post_steam_static_successors import containing_unwind,_one,_direct_target,classify_call
from mxbikes_whole_game_map import INPUT_SHA

BASE=0x140000000
MAIN_CALL=0x13677f
MAIN_RETURN=0x136784
INIT_CALLEE=0x133e80
STEAM_LIBRARIES=frozenset(("steam_api64.dll","steam_api.dll"))
MAX_MAIN_SITES=1500
MAX_MAIN_EDGES=300
MAX_CALLEES=64
MAX_CALLEE_BYTES=32768
MAX_CALLEE_SCAN_BYTES=1024*1024
MAX_PDATA_BYTES=2*1024*1024


def unwind_intervals(pe):
    directory,size=pe.directory(3)
    if not directory or size%12 or size>MAX_PDATA_BYTES:
        raise ValueError("Original PE unwind index unavailable")
    intervals=[]
    for a,b,_ in struct.iter_unpack("<III",pe.read_rva(directory,size)):
        if a>=b:
            raise ValueError("Bad original unwind interval")
        intervals.append((a,b))
    intervals.sort()
    if any(x[1]>y[0] for x,y in zip(intervals,intervals[1:])):
        raise ValueError("Overlapping original unwind ranges")
    return intervals



def audit_unwindless_prefix(pe,decoder,rva,slots,*,base):
    """Read only a bounded initial executable prefix, not an inferred function."""
    code=None
    for width in (96,64,48,32,20,16,12,8,6,5,3,2,1):
        try:
            code=bytes(pe.read_rva(rva,width))
            break
        except (ValueError,OverflowError):
            continue
    if not code:
        return {"target_rva":hex(rva),"status":"outside_original_unwind",
                "engine_identity_proven":False,"steam_independent_proven":False}
    forms=[]
    transfer=None
    for inst in decoder.disasm(code,base+rva):
        if len(forms)>=24:break
        forms.append({"rva":hex(inst.address-base),
                      "mnemonic":inst.mnemonic,"operands":inst.op_str})
        if inst.mnemonic in ("call","ret","retf","jmp","je","jne","jz","jnz",
                              "jb","jbe","ja","jae","jg","jge","jl","jle","int3",
                              "syscall","ud2","hlt"):
            transfer=inst
            break
    info={
        "target_rva":hex(rva),
        "status":"original_unwindless_bounded_prefix_not_executed",
        "original_prefix_forms":forms,
        "first_control_rva":hex(transfer.address-base) if transfer else None,
        "first_control_kind":transfer.mnemonic if transfer else None,
        "native_arm64_verified":False,
        "complete_function_verified":False,
        "engine_identity_proven":False,
        "transitive_steam_independence_proven":False
    }
    if transfer:
        target=_direct_target(transfer,base)
        if target is not None and transfer.mnemonic in ("jmp","call"):
            info["direct_transfer_target_rva"]=hex(target)
        elif transfer.mnemonic=="call":
            info["transfer_call_info"]=classify_call(transfer,slots,base)
        elif transfer.mnemonic=="jmp" and len(transfer.operands)==1:
            operand=transfer.operands[0]
            if (operand.type==X86_OP_MEM and
                transfer.reg_name(operand.mem.base)=="rip" and
                not operand.mem.index):
                slot=transfer.address+transfer.size+operand.mem.disp-base
                info["indirect_slot_rva"]=hex(slot)
                if slot in slots:
                    lib,symbol=slots[slot]
                    info["status"]="named_original_import_thunk_prefix"
                    info["import_library"]=lib
                    info["import_symbol"]=symbol
                    info["steam_import_thunk"]=lib.lower() in STEAM_LIBRARIES
            else:
                info["unresolved_jump_target"]=True
    return info

def audit_callee(pe,decoder,intervals,rva,slots,*,base):
    enclosing=[(a,b) for a,b in intervals if a<=rva<b]
    if len(enclosing)!=1:
        return audit_unwindless_prefix(pe,decoder,rva,slots,base=base)
    entry,end=enclosing[0]
    length=end-entry
    if length>MAX_CALLEE_BYTES or not length:
        return {"target_rva":hex(rva),"original_unwind_rva":hex(entry),
                "status":"function_out_of_decode_budget",
                "engine_identity_proven":False,"steam_independent_proven":False}
    try:
        raw=pe.read_rva(entry,length)
        code=list(decoder.disasm(raw,base+entry))
    except (ValueError,OverflowError):
        code=[]
    if not code or sum(i.size for i in code)!=length:
        return {"target_rva":hex(rva),"original_unwind_rva":hex(entry),
                "status":"original_unwind_decode_incomplete",
                "engine_identity_proven":False,"steam_independent_proven":False}
    links=[classify_call(i,slots,base) for i in code if i.mnemonic=="call"]
    names=[{"library":i["library"],"symbol":i["symbol"],"at_rva":i["site_rva"]}
           for i in links if i["kind"]=="named_import"]
    steam=[i for i in names if i["library"].lower() in STEAM_LIBRARIES]
    indirect=[i for i in links if i["kind"].startswith("indirect") or
              i["kind"]=="unresolved_indirect_memory_call"]
    return {
        "target_rva":hex(rva),
        "original_unwind_rva":hex(entry),
        "status":"fully_decoded_original_unwind_not_executed",
        "original_instruction_count":len(code),
        "original_callsite_count":len(links),
        "steam_imports":steam,
        "other_named_imports":names if not steam else [
            i for i in names if i["library"].lower() not in STEAM_LIBRARIES],
        "direct_original_callees":[i["target_rva"] for i in links if
                                   i["kind"]=="direct_original_call"],
        "unknown_indirect_calls":len(indirect),
        "no_direct_steam_import_in_this_body":not steam,
        "transitive_steam_independence_proven":False,
        "engine_identity_proven":False,
        "native_arm64_verified":False,
    }


def map_main_return(pe, imports, *,base=BASE,
                    call_rva=MAIN_CALL,return_rva=MAIN_RETURN,
                    init_target=INIT_CALLEE):
    if not 0<base<1<<64 or not 0<=call_rva<return_rva<1<<32:
        raise ValueError("Bad main call coordinates")
    slots={}
    for rva,lib,name in imports:
        if not 0<=rva<1<<32 or rva in slots or not lib or not name:
            raise ValueError("Invalid original IAT symbol")
        slots[rva]=(lib.lower(),name)
    if len(slots)>4096:
        raise ValueError("Excessive original imports")
    start,end=containing_unwind(pe,return_rva)
    if not start<=call_rva<return_rva<end:
        raise ValueError("Original initializer call is outside main function")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    inst=_one(pe,decoder,call_rva,end,base)
    if (inst.mnemonic!="call" or len(inst.operands)!=1 or
        inst.operands[0].type!=X86_OP_IMM or
        _direct_target(inst,base)!=init_target or
        inst.address+inst.size!=base+return_rva):
        raise ValueError("Original Win64 game-main initializer CALL drifted")

    todo=deque([return_rva])
    visited=set()
    transfers=[]
    calls=[]
    terminal=[]
    opcode_counts=Counter()
    while todo and len(visited)<MAX_MAIN_SITES and len(transfers)<MAX_MAIN_EDGES:
        pc=todo.popleft()
        if pc in visited:continue
        if not start<=pc<end:
            terminal.append({"kind":"outside_main_unwind","rva":hex(pc)})
            continue
        try:ins=_one(pe,decoder,pc,end,base)
        except (ValueError,OverflowError):
            terminal.append({"kind":"unreadable_original_instruction","rva":hex(pc)})
            continue
        visited.add(pc)
        opcode_counts[ins.mnemonic]+=1
        after=pc+ins.size
        if ins.mnemonic=="call":
            call=classify_call(ins,slots,base)
            calls.append(call)
            transfers.append({"at_rva":hex(pc),"kind":"call_fallthrough_hypothetical"})
            todo.append(after)
        elif ins.mnemonic.startswith("ret"):
            terminal.append({"kind":"original_main_return","rva":hex(pc)})
        elif ins.mnemonic in ("ud2","int","int3","syscall","sysenter","hlt"):
            terminal.append({"kind":"noncontinuable_opcode","rva":hex(pc)})
        elif ins.group(CS_GRP_JUMP):
            dest=_direct_target(ins,base)
            if dest is None:
                terminal.append({"kind":"unresolved_indirect_jump","rva":hex(pc)})
                continue
            conditional=ins.mnemonic!="jmp"
            transfers.append({"at_rva":hex(pc),
                "kind":"conditional" if conditional else "unconditional",
                "target_rva":hex(dest),
                "fallthrough_rva":hex(after) if conditional else None})
            todo.append(dest)
            if conditional:todo.append(after)
        else:
            todo.append(after)
    truncated=bool(todo)
    unique={c["site_rva"]:c for c in calls}
    direct=sorted({int(c["target_rva"],16) for c in unique.values()
                   if c["kind"]=="direct_original_call"})
    candidates=[]
    intervals=unwind_intervals(pe)
    accounted=0
    for target in direct[:MAX_CALLEES]:
        detail=audit_callee(pe,decoder,intervals,target,slots,base=base)
        if detail.get("status")=="fully_decoded_original_unwind_not_executed":
            accounted+=detail["original_instruction_count"]
            if accounted>MAX_CALLEE_SCAN_BYTES:
                detail={"target_rva":hex(target),
                        "status":"aggregate_callee_scan_budget_exceeded",
                        "native_arm64_verified":False}
                truncated=True
        candidates.append(detail)
    if len(direct)>MAX_CALLEES:truncated=True
    steam_calls=[c for c in unique.values() if
                 c.get("library","").lower() in STEAM_LIBRARIES]
    other_imports=[c for c in unique.values() if c["kind"]=="named_import" and
                   c.get("library","").lower() not in STEAM_LIBRARIES]
    nonsteam=[r for r in candidates if
              r.get("status")=="fully_decoded_original_unwind_not_executed" and
              r["no_direct_steam_import_in_this_body"]]
    return {
        "original_initializer_call_rva":hex(call_rva),
        "original_initializer_target_rva":hex(init_target),
        "hypothetical_original_main_return_rva":hex(return_rva),
        "original_main_unwind_start_rva":hex(start),
        "original_main_unwind_end_rva":hex(end),
        "possible_main_instruction_sites":len(visited),
        "possible_main_transfers":len(transfers),
        "possible_main_calls":len(unique),
        "direct_original_callee_candidates_total":len(direct),
        "direct_original_callee_candidates_inspected":len(candidates),
        "direct_original_callee_no_steam_import_count":len(nonsteam),
        "direct_original_callee_no_steam_import_rvas":[x["target_rva"] for x in nonsteam],
        "original_main_steam_calls":[{"site_rva":x["site_rva"],"symbol":x["symbol"]}
                                    for x in steam_calls],
        "original_main_other_named_imports":[{"site_rva":x["site_rva"],
            "library":x["library"],"symbol":x["symbol"]} for x in other_imports],
        "original_main_callsite_inventory":sorted(unique.values(),key=lambda x:int(x["site_rva"],16)),
        "original_callee_dependency_audit":candidates,
        "original_main_branch_inventory":transfers,
        "original_main_terminal_inventory":terminal,
        "scan_budget_truncated":truncated,
        "game_init_returned_in_native_runtime":False,
        "startup_code_after_init_executed":False,
        "engine_init_or_renderer_confirmed":False,
        "steam_runtime_authorization_provided":False,
        "native_arm64_game_port_booted":False,
    }


def run(original_exe,reports):
    from tools.pe_probe import PE
    pe=PE(original_exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original-owned executable SHA changed")
    reports=Path(reports)
    prior=json.loads((reports/"joined-native-boot-nextcall.json").read_text())
    if (prior.get("original_game_main_next_callsite")!=hex(MAIN_CALL) or
        prior.get("original_next_untranslated_callee")!=hex(INIT_CALLEE) or
        prior.get("game_engine_or_ios_app_booted") is not False):
        raise ValueError("Missing independent original game-main call evidence")
    outcome=map_main_return(pe,import_slots(pe))
    outcome["original_sha_verified"]=True
    outcome["native_call_frontier_evidence_checked"]=True
    reports.mkdir(parents=True,exist_ok=True)
    (reports/"game-main-postinit-dependency-wave.json").write_text(json.dumps(outcome,indent=2)+"\n")
    lines=["# Original MX Bikes game main — hypothetical post-initializer CALL wave","",
        "- Original SHA and native caller boundary: **PASS**",
        "- Game initializer call: **"+hex(MAIN_CALL)+" -> "+hex(INIT_CALLEE)+"**",
        "- Hypothetical original return: **"+hex(MAIN_RETURN)+"**",
        "- Statically decoded possible main sites: **"+str(outcome["possible_main_instruction_sites"])+"**",
        "- Possible main callsites: **"+str(outcome["possible_main_calls"])+"**",
        "- Original direct callee targets inspected: **"+str(outcome["direct_original_callee_candidates_inspected"])+"**",
        "- First-tier callee bodies without direct Steam imports: **"+
                str(outcome["direct_original_callee_no_steam_import_count"])+"**",
        "- Scan exhausted configured budget: **"+str(outcome["scan_budget_truncated"])+"**",
        "- Original game initialization actually resumed: **NO**",
        "- Native engine/renderer: **NO**","",
        "## Independent first-tier game-function translation candidates"]
    for x in outcome["original_callee_dependency_audit"][:24]:
        lines.append("- "+x["target_rva"]+": "+x["status"]+
                     ("; direct Steam imports "+str(len(x["steam_imports"]))+
                      ", indirect calls "+str(x["unknown_indirect_calls"])
                      if "steam_imports" in x else "")+
                     (", import "+x["import_library"]+"!"+x["import_symbol"]
                      if "import_symbol" in x else "")+
                     (", first transfer "+x["first_control_rva"]+" "+
                      x["first_control_kind"] if x.get("first_control_rva") else ""))
        for form in x.get("original_prefix_forms",[])[:20]:
            lines.append("  - "+form["rva"]+" "+form["mnemonic"]+" "+form["operands"])
    lines+=["","## Possible original main caller CALL sites"]
    for x in outcome["original_main_callsite_inventory"]:
        lines.append("- "+x["site_rva"]+": "+x["kind"]+" "+x.get("target_rva",x.get("library","")+"!"+x.get("symbol","")))
    lines+=["","First-tier absence of direct Steam imports does NOT establish",
            "transitive independence or identify an engine entry. The original",
            "initializer has not returned in the native run; all future calls",
            "are *static possibilities*, not executed code.",""]
    (reports/"game-main-postinit-dependency-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return outcome


if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: original_game.exe metadata_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
