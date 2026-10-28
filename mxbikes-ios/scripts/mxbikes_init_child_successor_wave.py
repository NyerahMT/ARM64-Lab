#!/usr/bin/env python3
"""Batch map BOTH original initializer child JLE successors, no fabricated calls.

The 0x133640 first child has already been differentially run on AArch64 up
to JLE 0x133668. Now recover both authenticated successor blocks and trace
original x64 execution to their next control, preserving distinct inputs.
Only metadata is retained, never original machine or game asset bytes.
"""
import hashlib,json,sys
from pathlib import Path
from unicorn import UC_HOOK_CODE, UcError
from unicorn.x86_const import (
    UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RSI,
    UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX
)
import mxbikes_init_nested_jle_native as parent
import mxbikes_init_nested_wave as wave
import mxbikes_main_boot_next_call_native as prior
import mxbikes_main_joined_callee_native as joined
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
MAX_BRANCH_EXEC=256

def trace_branch(pe,expected_target,stop_rva,parser_value):
    uc=joined.new_cpu(pe)
    orig_rsp=joined.ENTRY_SP-0x288
    uc.mem_write(BASE+prior.GLOBAL_RVA,int(parser_value).to_bytes(4,"little"))
    for reg,value in (
       (UC_X86_REG_RIP,BASE+prior.CALLSITE),(UC_X86_REG_RSP,orig_rsp),
       (UC_X86_REG_RAX,1),(UC_X86_REG_RSI,0x123456789ABCD),
       (UC_X86_REG_RBX,0x123456789ABCD),
       (UC_X86_REG_RCX,parser_value),
       (UC_X86_REG_RDX,BASE+prior.CONSTANT_RVA)):
        uc.reg_write(reg,value)
    uc.emu_start(BASE+prior.CALLSITE,BASE+parent.CALL,
                 timeout=3000000,count=35)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+parent.CALL:
        raise ValueError("Previously verified original CALL context changed")
    hit=[]
    def on_code(u,pc,size,ctx):
        hit.append(pc)
        if pc==BASE+stop_rva:u.emu_stop()
    # Install BEFORE the first child JIT translation. Unicorn caches x64
    # translated blocks: a hook added after the earlier ten instructions
    # will miss cached successor instructions and silently run past a CALL.
    uc.hook_add(UC_HOOK_CODE,on_code)
    uc.emu_start(BASE+parent.CALL,0,timeout=3000000,count=10)
    if uc.reg_read(UC_X86_REG_RIP)!=BASE+expected_target:
        raise ValueError("Original child JLE took unexpected branch")
    hit.clear()
    report={"original_case_dword":parser_value,
            "entered_successor_rva":hex(expected_target),
            "expected_first_control_rva":hex(stop_rva),
            "native_arm64_successor_executed":False}
    try:
        uc.emu_start(BASE+expected_target,0,timeout=3000000,
                     count=MAX_BRANCH_EXEC)
        ok=bool(hit and hit[-1]==BASE+stop_rva)
        report["status"]="reached_original_x64_control" if ok else "unresolved_bounded_x64_execution"
    except UcError as exc:
        ok=False
        report["status"]="unresolved_guest_memory_or_execution"
        report["failure_class"]=type(exc).__name__
    report["original_x64_executed_instruction_count"]=len(hit)
    report["first_original_x64_rvas"]=[
        hex(pc-BASE) if BASE<=pc<BASE+0x800000 else "outside_PE"
        for pc in hit[:16]]
    report["expected_control_executed"]=BASE+stop_rva in hit
    report["reached_first_original_x64_control"]=ok
    report["last_original_rva"]=hex(hit[-1]-BASE) if hit and BASE<=hit[-1]<BASE+0x800000 else None
    return report

def run(executable,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original game asset SHA changed")
    taken,fall=parent.original_branch(pe)
    if (taken,fall)!=(0x133c9a,0x13366e):
        raise ValueError("Pinned original child successors changed")
    rows=[]
    cases={taken:(0,1,0x80000000),fall:(2,0x80,0x7fffffff)}
    for successor in (taken,fall):
        row=wave.scan_first_block(pe,successor)
        row["unwind"]=wave.unwind_owner(pe,successor)
        target=row.get("control_rva")
        samples=[]
        if target is not None:
            for value in cases[successor]:
                samples.append(trace_branch(pe,successor,int(target,16),value))
        row["authentic_x64_successor_fixtures"]=samples
        rows.append(row)
    result={
       "original_sha256":INPUT_SHA,
       "native_verified_parent_control_rva":hex(parent.BRANCH),
       "native_verified_branch_outcomes":[hex(taken),hex(fall)],
       "original_x64_successor_cases":sum(
           len(q["authentic_x64_successor_fixtures"]) for q in rows),
       "original_x64_next_controls_reached":sum(
           s["reached_first_original_x64_control"] for q in rows
           for s in q["authentic_x64_successor_fixtures"]),
       "branch_groups":rows,
       "native_arm64_successors_implemented":False,
       "actual_engine_or_renderer_started":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"native-child-successor-wave.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — both native-initializer branch successors","",
       "- Authenticated original JLE: **"+hex(parent.BRANCH)+"**",
       "- Original x64 successor controls: **"+
         str(result["original_x64_next_controls_reached"])+
         "/"+str(result["original_x64_successor_cases"])+"**",
       "- Actual executed AArch64 successor bodies: **0**",""]
    for q in rows:
        lines.extend(["## "+q["entry_rva"],"",
          "- Original precontrol instructions: **"+str(q.get("precontrol_instruction_count",0))+"**",
          "- Next original control: **"+q.get("control_rva","unresolved")+
          " "+q.get("control_kind","unsupported")+" "+q.get("control_operands","")+"**",
          "- Original x64 fixtures reaching control: **"+
             str(sum(x["reached_first_original_x64_control"] for x in q["authentic_x64_successor_fixtures"]))+
             "/"+str(len(q["authentic_x64_successor_fixtures"]))+"**"])
        lines.extend("- "+i["rva"]+" "+i["mnemonic"]+" "+i["operands"]
                     for i in q.get("precontrol_instruction_forms",[]))
        lines.extend("- Original x64 case "+str(s["original_case_dword"])+
                     ": "+s["status"]+", executed="+
                     str(s["original_x64_executed_instruction_count"])+
                     ", last="+str(s.get("last_original_rva"))+
                     ", fault="+str(s.get("failure_class"))+
                     ", first="+str(s.get("first_original_x64_rvas"))+
                     ", hit_control="+str(s.get("expected_control_executed"))
                     for s in q["authentic_x64_successor_fixtures"])
    lines.extend(["","Untranslated branches and original imports fail closed. No loading screen yet.",""])
    (out/"native-child-successor-wave.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: native-child-successor-wave.py owned.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
