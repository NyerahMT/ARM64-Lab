#!/usr/bin/env python3
"""Metadata-only inventory of original CRT direct-call dependency cluster.

This is PRIVATE-REPO-only: no original code bytes, lifted C, disassembly,
ELF objects, or unpacked PE files are emitted to actions artifacts.
"""
from collections import Counter
from pathlib import Path
import hashlib,json,struct,sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from mxbikes_first_callee_emu import import_slots

SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
CRT_START=0x2ab02c
CRT_SIZE=518
MAX_SPAN=8192
SITES=(0x2ab08d,0x2ab0b6,0x2ab0ec,0x2ab119,0x2ab186)
SUPPORTED={"mov","movabs","cmp","test","lea","jne","je","jmp",
           "xor","xchg","and","or","push","pop","sub","add","ret",
           "call","nop","cmove"}

def inventory(path):
    original=PE(path)
    if hashlib.sha256(original.b).hexdigest()!=SHA:
        raise RuntimeError("Unexpected private original MX Bikes SHA")
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    decoder.detail=True
    body=list(decoder.disasm(original.read_rva(CRT_START,CRT_SIZE),CRT_START))
    indexed={i.address:i for i in body}
    if len(body)!=126 or sum(i.size for i in body)!=CRT_SIZE:
        raise RuntimeError("Changed original CRT source boundary")
    unwind_rva,size=original.directory(3)
    if not unwind_rva or size%12:
        raise RuntimeError("Invalid original PE x64 unwind directory")
    entries=list(struct.iter_unpack("<III",original.read_rva(unwind_rva,size)))
    ranges=[(a,b) for a,b,c in entries if a<b]
    iat={rva:(dll,name) for rva,dll,name in import_slots(original)}
    results=[]
    for site in SITES:
        ins=indexed.get(site)
        if not ins or ins.mnemonic!="call" or len(ins.operands)!=1 or ins.operands[0].type!=X86_OP_IMM:
            raise RuntimeError("A pinned direct callsite is no longer a direct original CALL")
        target=int(ins.operands[0].imm)
        matched=[(a,b) for a,b in ranges if a<=target<b]
        if len(matched)>1:
            raise RuntimeError("Overlapping unwind intervals for direct original CRT callee")
        if matched:
            a,b=matched[0]
            if b-a>MAX_SPAN:
                raise RuntimeError("Direct CRT callee unwind span exceeds fixed inspection bound")
            inspect_start=a
            byte_length=b-a
        else:
            inspect_start=target
            byte_length=96
        if not 0<byte_length<=MAX_SPAN:
            raise RuntimeError("Nonpositive or unsafe direct callee region")
        code=original.read_rva(inspect_start,byte_length)
        decoded=list(decoder.disasm(code,inspect_start))
        if not decoded or decoded[0].address!=inspect_start:
            raise RuntimeError("Original CRT callee failed at starting instruction")
        if matched and sum(x.size for x in decoded)!=byte_length:
            raise RuntimeError("Original unwind callee did not fully decode")
        if not matched:
            cut=next((n+1 for n,x in enumerate(decoded) if x.group(CS_GRP_RET)),None)
            if cut is not None:
                decoded=decoded[:cut]
        # Printed to PRIVATE Actions logs only: never included in metadata/artifacts.
        # Inspect the three shared CRT initialization wrappers together.
        if site in (0x2ab08d,0x2ab0b6,0x2ab0ec):
            print(f"PRIVATE ORIGINAL CRT CALLEE site={site:#x} target={target:#x}")
            for x in decoded[:24]:
                print(f"  {x.address:#010x}: {x.mnemonic:<12s} {x.op_str}")
        first_instruction=list(decoder.disasm(original.read_rva(target,16),target))[:1]
        thunk_name=None
        thunk_slot=None
        if first_instruction:
            first=first_instruction[0]
            if (first.mnemonic=="jmp" and len(first.operands)==1 and
                first.operands[0].type==X86_OP_MEM and
                first.reg_name(first.operands[0].mem.base)=="rip" and
                first.operands[0].mem.index==0):
                thunk_slot=first.address+first.size+first.operands[0].mem.disp
                if thunk_slot in iat:
                    dll,name=iat[thunk_slot]
                    thunk_name=dll.lower()+"::"+name
        if site in (0x2ab08d,0x2ab0b6,0x2ab0ec):
            print(f"PRIVATE IMPORT THUNK: site={site:#x} target={target:#x} "
                  f"IAT={thunk_slot!r} symbol={thunk_name!r}")
        mnemonics=Counter(x.mnemonic for x in decoded)
        unsupported={k:v for k,v in mnemonics.items() if k not in SUPPORTED}
        import_names=Counter()
        direct_targets=Counter()
        direct_jumps=0
        for x in decoded:
            if x.group(CS_GRP_JUMP):direct_jumps+=1
            if x.group(CS_GRP_CALL) and len(x.operands)==1:
                o=x.operands[0]
                if o.type==X86_OP_IMM:
                    direct_targets[hex(int(o.imm))]+=1
                elif (o.type==X86_OP_MEM and x.reg_name(o.mem.base)=="rip" and
                      o.mem.segment==0 and o.mem.index==0):
                    slot=x.address+x.size+o.mem.disp
                    if slot in iat:
                        dll,name=iat[slot]
                        import_names[dll.lower()+"::"+name]+=1
                    else:
                        import_names["unresolved_IAT"]+=1
        results.append({
            "callsite_rva":hex(site),
            "first_instruction_import_thunk":thunk_name,
            "thunk_iat_slot":hex(thunk_slot) if thunk_slot is not None else None,
            "target_rva":hex(target),
            "unwind_bounded":bool(matched),
            "containing_unwind_start_rva":hex(inspect_start),
            "containing_unwind_bytes":byte_length if matched else None,
            "target_is_exact_function_start":target==inspect_start if matched else None,
            "decoded_instruction_count":len(decoded),
            "fully_decoded_inspected_region":sum(x.size for x in decoded)==byte_length,
            "direct_jump_count":direct_jumps,
            "direct_call_targets":dict(sorted(direct_targets.items())),
            "imported_calls":dict(sorted(import_names.items())),
            "instruction_mnemonics":dict(sorted(mnemonics.items())),
            "mnemonics_outside_current_early_CRT_subset":dict(sorted(unsupported.items())),
            "original_game_code_executed":False,
            "native_arm64_translated":False,
        })
    return {
        "original_game_sha256":SHA,
        "caller_second_crt_rva":hex(CRT_START),
        "direct_callsite_count":len(results),
        "targets":results,
        "limitations":[
            "Static metadata only; no original direct CRT callee has been executed on ARM64.",
            "Unwind regions may contain more than a single source-level function.",
            "Targets outside unwind ranges are inspected only through a short bounded prefix.",
            "Mnemonic counts do not establish correct flag/operand semantics or Windows runtime support."
        ]
    }

def run(exe,out):
    report=inventory(exe)
    out.mkdir(parents=True,exist_ok=True)
    (out/"crt-direct-callee-survey.json").write_text(json.dumps(report,indent=2)+"\n")
    markdown=["# MX Bikes direct CRT startup dependency inventory","",
              "- Original direct-call sites surveyed: **"+str(report["direct_callsite_count"])+"**",
              "- Derived source/PE bytes are not uploaded",
              "",
              "| Callsite | Original target | Imported JMP thunk | Unwind bounded | Decoded instructions |",
              "| --- | --- | --- | --- | ---: |"]
    for x in report["targets"]:
        markdown.append("| "+x["callsite_rva"]+" | "+x["target_rva"]+" | "+
                        (x["first_instruction_import_thunk"] or "none")+" | "+
                        ("yes" if x["unwind_bounded"] else "no")+" | "+
                        str(x["decoded_instruction_count"])+" |")
    markdown+=["","**Static inventory only: these direct CRT callees remain unexecuted on ARM64.**",""]
    summary="\n".join(markdown)
    (out/"crt-direct-callee-survey.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: inventory.py /private/owned-mxbikes.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
