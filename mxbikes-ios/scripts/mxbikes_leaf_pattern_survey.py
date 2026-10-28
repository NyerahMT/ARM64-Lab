#!/usr/bin/env python3
"""Survey no-branch original MX Bikes direct-call entry paths for native batch lifting.

Private original instructions are decoded but only aggregate mnemonic/shape
statistics are exported. A straight-line RET path is not proof a complete
source-level function was recovered, especially without unwind metadata.
"""
from collections import Counter
from pathlib import Path
import json
import sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_MEM
from mxbikes_whole_game_map import map_executable
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE

MAX_PREFIX_BYTES=64
MAX_INS=16

def run(exe,out):
    whole=map_executable(exe)
    pe=PE(exe)
    called=Counter(int(x,16) for xs in whole["direct_call_graph"].values() for x in xs)
    starts={int(x["rva"],16):x for x in whole["interval_map"]}
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    categories=Counter()
    patterns=Counter()
    opcodes=Counter()
    example=Counter()
    candidate_lengths=Counter()
    operand_forms=Counter()
    exact_samples=[]
    bounded_samples=[]
    for rva,refs in called.items():
        region=next(((int(section["start_rva"],16),
                      int(section["end_rva"],16),section["raw_bytes"])
                     for section in whole["sections"]
                     if int(section["start_rva"],16)<=rva<
                        int(section["start_rva"],16)+section["raw_bytes"]),None)
        if not region:
            categories["outside_raw_executable"]+=1
            continue
        end=min(rva+MAX_PREFIX_BYTES,region[0]+region[2])
        interval=starts.get(rva)
        if interval:
            if interval["status"]!="decoded_linear":
                categories["invalid_unwind_interval"]+=1;continue
            end=min(end,int(interval["end_rva"],16))
        try: chunk=pe.read_rva(rva,end-rva)
        except ValueError:
            categories["unreadable"]+=1;continue
        names=[]
        detail=[]
        inscount=0
        read_memory=False
        write_memory=False
        complete=False
        for inst in decoder.disasm(chunk,rva):
            inscount+=1
            if inscount>MAX_INS:break
            if inst.group(CS_GRP_CALL) or inst.group(CS_GRP_JUMP):
                break
            names.append(inst.mnemonic)
            detail.append(f"{inst.mnemonic} {inst.op_str}".strip())
            if any(op.type==X86_OP_MEM for op in inst.operands):
                if inst.mnemonic not in {"ret","nop"}:
                    read_memory=True
            if inst.group(CS_GRP_RET):
                complete=True;break
        if not complete:
            categories["no_closed_straight_ret_in_bound"]+=1;continue
        exact=bool(interval and inst.address+inst.size==end and
                   sum(i.size for i in decoder.disasm(chunk,rva))==len(chunk))
        key=("unwind_exact" if exact else "direct_called_short_path")
        cats=["no_mem" if not read_memory else "memory_access",
              "flags_preserving" if all(n in {"ret","nop","mov","movzx","movsx","movsxd","lea"} for n in names) else "flag_writing_or_other"]
        categories[key]+=1
        categories["/".join(cats)]+=1
        patterns[" ".join(names)]+=1
        if len(names)<=6:
            operand_forms["; ".join(detail)]+=1
            target={"rva":hex(rva),"referenced":refs,
                    "exact_unwind":exact,"size":inst.address+inst.size-rva,
                    "forms":detail}
            if exact and len(exact_samples)<35:exact_samples.append(target)
            elif not exact and len(bounded_samples)<65:bounded_samples.append(target)
        for n in names:opcodes[n]+=1
        if not read_memory and cats[1]=="flags_preserving":
            categories["pure_reg_no_flag_path"]+=1
            candidate_lengths[inscount]+=1
        if exact and not read_memory and cats[1]=="flags_preserving":
            categories["pure_reg_no_flag_exact_unwind"]+=1
        if len(names)<=6:
            example[tuple(names)]+=1
    out.mkdir(parents=True,exist_ok=True)
    info={"total_direct_call_targets":len(called),
          "classification":dict(categories),
          "top_mnemonic_paths":[{"path":k,"count":v} for k,v in patterns.most_common(40)],
          "top_opcodes":opcodes.most_common(35),
          "top_operand_forms":[{"forms":k,"count":v} for k,v in operand_forms.most_common(80)],
          "bounded_entry_samples":bounded_samples,
          "exact_unwind_samples":exact_samples,
          "eligible_instruction_lengths":dict(candidate_lengths),
          "limits":{"bytes":MAX_PREFIX_BYTES,"instructions":MAX_INS},
          "warnings":["Direct-call targets do not necessarily start unique functions.",
                      "No memory operands is a shallow classifier: pure-register semantics and operand widths still need validation.",
                      "A first RET proves one entry path, not full alternate-path coverage or an ARM64 conversion."]}
    (out/"native-leaf-pattern-survey.json").write_text(json.dumps(info,indent=2)+"\n")
    summary=["# MX Bikes automatic leaf-pattern survey","",
             "- Original direct-call targets considered: **"+str(len(called))+"**",
             "- Straight-line no-memory flag-preserving short entry paths: **"+str(categories['pure_reg_no_flag_path'])+"**",
             "- Same paths with exact unwind interval: **"+str(categories['pure_reg_no_flag_exact_unwind'])+"**",
             "","## Top x64 short-path mnemonic sequences"]
    for pattern,count in patterns.most_common(25):
        summary.append("- "+pattern+": **"+str(count)+"**")
    summary+=["","## Frequently occurring operand forms"]
    for form,count in operand_forms.most_common(25):
        summary.append(f"- ({count}) {form}")
    summary+=["","This is a structural survey, not native execution or complete-function proof."]
    text="\n".join(summary)+"\n"
    (out/"native-leaf-pattern-survey.md").write_text(text)
    print(text)
    return info

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: survey.py original.exe output-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
