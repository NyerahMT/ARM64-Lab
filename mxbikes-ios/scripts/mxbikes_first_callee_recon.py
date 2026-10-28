#!/usr/bin/env python3
"""Metadata-only scan of the two actual MX Bikes entry-level startup functions.

Never executes the real startup callees. Never exports original machine bytes.
The unwind interval (if present) is not a guaranteed whole source function.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.entry_wrapper import decode_entry_wrapper

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"


def profile(path):
    pe=PE(path)
    inventory=pe.inventory()
    if inventory["sha256"] != SHA:
        raise RuntimeError("Unexpected executable revision")
    entry=int(inventory["entry_rva"],16)
    wrapper=decode_entry_wrapper(pe.read_rva(entry,18),entry)
    pdata,plen=pe.directory(3)
    unwind={}
    if pdata and plen and plen%12==0:
        for begin,end,_unwind in struct.iter_unpack("<III",pe.read_rva(pdata,plen)):
            if begin and end>begin:
                unwind[begin]=end
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    targets=[]
    for kind,key in (("first_callee","direct_call_rva"),("tail_transfer","tail_jmp_rva")):
        start=int(wrapper[key],16)
        end=unwind.get(start)
        limit=min(end-start,768) if end and end>start else 320
        payload=pe.read_rva(start,limit)
        decoded=list(md.disasm(payload,start))
        if not decoded:
            raise RuntimeError("No instructions at target "+hex(start))
        counted=Counter(i.mnemonic for i in decoded)
        controls=[{"rva":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
                  for i in decoded if i.group(CS_GRP_CALL) or i.group(CS_GRP_JUMP) or i.group(CS_GRP_RET)]
        targets.append({
          "target":kind,
          "start_rva":hex(start),
          "unwind_interval_end":hex(end) if end is not None else None,
          "unwind_interval_size":end-start if end is not None else None,
          "bytes_decoded":sum(i.size for i in decoded),
          "instructions_decoded":len(decoded),
          "decode_complete":sum(i.size for i in decoded)==len(payload),
          "top_mnemonics":counted.most_common(15),
          "branch_and_call_instructions":controls[:55],
          "instruction_prefix":[
             {"rva":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
             for i in decoded[:32]
          ],
        })
    return {"original_exe_sha256":SHA,"entry_rva":hex(entry),
            "original_startup_target_metadata":targets,
            "note":"Static instruction reconnaissance only; no execution of original startup callees."}


def main():
    if len(sys.argv)!=3:
        raise SystemExit("Usage: mxbikes_first_callee_recon.py EXE REPORT_DIR")
    reports=Path(sys.argv[2]);reports.mkdir(parents=True,exist_ok=True)
    data=profile(sys.argv[1])
    (reports/"first-callees.json").write_text(json.dumps(data,indent=2)+"\n")
    lines=["# MX Bikes first original startup targets",""]
    for target in data["original_startup_target_metadata"]:
        lines += ["## "+target["target"],"",
                  "- Start: "+target["start_rva"],
                  "- Unwind interval size: "+str(target["unwind_interval_size"]),
                  "- Decoded instructions: "+str(target["instructions_decoded"]),
                  "- Full interval decoded: "+str(target["decode_complete"]),
                  "","### First instructions",""]
        lines.extend("- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"] for i in target["instruction_prefix"][:20])
        lines += ["","### Control flow",""]
        lines.extend("- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"]
                     for i in target["branch_and_call_instructions"][:15])
    lines+=["","No actual startup callee executed; do not count this as an engine boot.",""]
    summary="\n".join(lines)
    (reports/"first-callees.md").write_text(summary)
    print(summary)


if __name__=="__main__":
    main()
