#!/usr/bin/env python3
"""Private bounded inventory of the next ORIGINAL MX Bikes CRT startup routine.

Produces instruction-class/CFG/import metadata only, never original opcodes,
full disassembly, extracted machine code or compiled original-derived files.
The interval is an unwind span, not proof of a complete source-level routine.
"""
from collections import Counter
from pathlib import Path
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_OP_MEM, X86_OP_IMM

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots

INPUT_SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
CRT_ENTRY, CRT_LENGTH=0x2ab02c, 518
CRITICAL={"mov","movabs","lea","sub","add","and","xor","not","cmp","cmove",
          "push","pop","call","ret","je","jmp"}
MAX_INTERVAL=4096

def inspect(exe):
    pe=PE(exe)
    if pe.inventory()["sha256"]!=INPUT_SHA:
        raise RuntimeError("Unrecognized original game executable revision")
    directory,length=pe.directory(3)
    if not directory or length%12:
        raise RuntimeError("Missing or invalid original unwind directory")
    matching=[(a,b) for a,b,unwind in struct.iter_unpack("<III",pe.read_rva(directory,length))
              if a==CRT_ENTRY]
    if matching!=[(CRT_ENTRY,CRT_ENTRY+CRT_LENGTH)]:
        raise RuntimeError("Unexpected next CRT unwind interval")
    if CRT_LENGTH>MAX_INTERVAL:
        raise RuntimeError("CRT region exceeds inspection safety bound")
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    items=list(md.disasm(pe.read_rva(CRT_ENTRY,CRT_LENGTH),CRT_ENTRY))
    if len(items)!=126 or sum(i.size for i in items)!=CRT_LENGTH:
        raise RuntimeError("Pinned next CRT instruction count or boundaries changed")
    boundaries={i.address for i in items}
    leaders={CRT_ENTRY}
    mnemonics=Counter()
    memory_modes=Counter()
    branches=Counter()
    calls=Counter()
    imports=Counter()
    advanced=Counter()
    unsupported=Counter()
    iat={rva:(dll.lower(),name) for rva,dll,name in import_slots(pe)}
    for i in items:
        mnemonic=i.mnemonic
        mnemonics[mnemonic]+=1
        if mnemonic not in CRITICAL:
            unsupported[mnemonic]+=1
        if 0xf0 in i.prefix:
            advanced["lock_prefix"]+=1
        for op in i.operands:
            if op.type!=X86_OP_MEM:
                continue
            segment=i.reg_name(op.mem.segment)
            base=i.reg_name(op.mem.base)
            if segment=="gs":
                memory_modes["gs_segment"]+=1
            if segment=="fs":
                memory_modes["fs_segment"]+=1
            if base=="rip":
                memory_modes["rip_relative"]+=1
            elif base=="rsp":
                memory_modes["rsp_base"]+=1
            elif base=="rbp":
                memory_modes["rbp_base"]+=1
            else:
                memory_modes["other_base"]+=1
            if op.mem.index:
                memory_modes["indexed"]+=1
        if i.group(CS_GRP_JUMP):
            if len(i.operands)==1 and i.operands[0].type==X86_OP_IMM:
                dest=int(i.operands[0].imm)
                branches["direct"]+=1
                if dest in boundaries:
                    branches["internal"]+=1
                    leaders.add(dest)
                else:
                    branches["out_of_interval"]+=1
                if i.mnemonic!="jmp":
                    branches["conditional"]+=1
            else:
                branches["indirect"]+=1
            next_addr=i.address+i.size
            if next_addr in boundaries:
                leaders.add(next_addr)
        if i.group(CS_GRP_CALL):
            next_addr=i.address+i.size
            if next_addr in boundaries:
                leaders.add(next_addr)
            if len(i.operands)==1 and i.operands[0].type==X86_OP_IMM:
                calls["direct_relative"]+=1
            elif len(i.operands)==1 and i.operands[0].type==X86_OP_MEM:
                base=i.reg_name(i.operands[0].mem.base)
                if base=="rip":
                    slot=next_addr+i.operands[0].mem.disp
                    if slot in iat:
                        calls["validated_iat"]+=1
                        dll,name=iat[slot]
                        imports[dll+"::"+name]+=1
                    else:
                        calls["rip_indirect_unknown"]+=1
                else:
                    calls["non_rip_indirect"]+=1
            else:
                calls["register_or_other_indirect"]+=1
        if i.group(CS_GRP_RET):
            branches["ret"]+=1
            if i.address+i.size in boundaries:
                leaders.add(i.address+i.size)
    blocks=sorted(leaders)
    result={
        "input_executable_sha256":INPUT_SHA,
        "span_start_rva":hex(CRT_ENTRY),
        "span_end_rva_exclusive":hex(CRT_ENTRY+CRT_LENGTH),
        "unwind_interval_bytes":CRT_LENGTH,
        "statically_decoded_instructions":len(items),
        "static_candidate_block_count":len(blocks),
        "unique_mnemonics":len(mnemonics),
        "mnemonic_counts":dict(sorted(mnemonics.items())),
        "memory_operand_modes":dict(sorted(memory_modes.items())),
        "static_branch_types":dict(sorted(branches.items())),
        "static_call_types":dict(sorted(calls.items())),
        "validated_static_import_names":dict(sorted(imports.items())),
        "advanced_instruction_features":dict(sorted(advanced.items())),
        "mnemonics_outside_first_crt_subset":dict(sorted(unsupported.items())),
        "native_arm64_executed":False,
        "next_crt_original_executed_in_this_job":False,
        "limitations":[
            "An unwind span may not cover a complete function or all reachable CFG blocks.",
            "Static leaders and paths include potentially unreachable code.",
            "A recognized mnemonic does not establish all operand/flag semantics are supported.",
            "No original x64 or translated ARM64 code executed by this inventory."
        ],
    }
    return result

def run(exe,out):
    result=inspect(exe)
    out.mkdir(parents=True,exist_ok=True)
    (out/"next-crt-inventory.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes: next original CRT startup routine — static complexity","",
           f"- RVA: **{result['span_start_rva']}**",
           f"- Original unwind interval: **{result['unwind_interval_bytes']} bytes**",
           f"- Instructions: **{result['statically_decoded_instructions']}**",
           f"- Candidate basic blocks: **{result['static_candidate_block_count']}**",
           f"- Conditional jumps: **{result['static_branch_types'].get('conditional',0)}**",
           f"- Internal/escaping branch targets: **{result['static_branch_types'].get('internal',0)}/{result['static_branch_types'].get('out_of_interval',0)}**",
           f"- GS references: **{result['memory_operand_modes'].get('gs_segment',0)}**",
           f"- LOCK-prefixed instructions: **{result['advanced_instruction_features'].get('lock_prefix',0)}**",
           f"- Validated static imported calls: **{result['static_call_types'].get('validated_iat',0)}**",
           f"- Distinct mnemonics not in first-CRT subset: **{len(result['mnemonics_outside_first_crt_subset'])}**",
           "",
           "## Instruction families outside first-CRT subset",
           ""]
    lines += [f"- {name}: {count}" for name,count in result["mnemonics_outside_first_crt_subset"].items()]
    lines += ["","## Validated original imports",""]
    lines += [f"- {name}: {count}" for name,count in result["validated_static_import_names"].items()]
    lines += ["","**Static inventory only: no native second-CRT translation or execution verified.**",""]
    summary="\n".join(lines)
    (out/"next-crt-inventory.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py /private/original.exe /reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
