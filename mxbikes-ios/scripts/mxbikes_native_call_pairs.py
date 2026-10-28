#!/usr/bin/env python3
"""Identify original MX Bikes unwind-backed direct caller/callee candidates.

Does not lift functions or report a verified function call; ranks bounded,
fully decoded x64 unwind ranges by size, branching and memory complexity.
Publishes metadata only, never raw commercial bytes.
"""
import json
from pathlib import Path
import struct
import sys
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE

EXPECTED="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"
EASY={"mov","movzx","movsxd","lea","push","pop","sub","add","xor",
      "cmp","test","inc","dec","and","or","ret","call","nop","jmp",
      "je","jne","jl","jle","jg","jge","ja","jae","jb","jbe"}

def scan(exe):
    pe=PE(exe)
    if pe.inventory()["sha256"]!=EXPECTED:raise RuntimeError("Unexpected original game binary")
    p,ps=pe.directory(3)
    unwinds={b:e for b,e,u in struct.iter_unpack("<III",pe.read_rva(p,ps))
             if 0<b<e and e-b<=384}
    md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
    decoded={}
    for b,e in unwinds.items():
        try:
            code=pe.read_rva(b,e-b)
            ins=list(md.disasm(code,b))
            if not ins or len(ins)>150 or sum(x.size for x in ins)!=len(code):
                continue
            if not ins[-1].group(CS_GRP_RET):
                continue
            decoded[b]=ins
        except (ValueError,struct.error):
            continue
    pairs=[]
    for b,ins in decoded.items():
        calls=[x for x in ins if x.group(CS_GRP_CALL)]
        if len(calls)!=1 or len(ins)>60:continue
        call=calls[0]
        if len(call.operands)!=1 or call.operands[0].type!=X86_OP_IMM:continue
        target=int(call.operands[0].imm)
        if target not in decoded or target==b or len(decoded[target])>100:continue
        callee=decoded[target]
        callee_calls=sum(x.group(CS_GRP_CALL) for x in callee)
        callee_branches=sum(x.group(CS_GRP_JUMP) for x in callee)
        rest=[x for x in ins if x.group(CS_GRP_JUMP)]
        caller_starts={x.address for x in ins}
        callee_starts={x.address for x in callee}
        if rest and any(len(x.operands)!=1 or x.operands[0].type!=X86_OP_IMM or x.operands[0].imm not in caller_starts for x in rest):continue
        callee_external_jumps=[
            hex(int(x.operands[0].imm)) if len(x.operands)==1 and x.operands[0].type==X86_OP_IMM else "indirect"
            for x in callee if x.group(CS_GRP_JUMP) and
            (len(x.operands)!=1 or x.operands[0].type!=X86_OP_IMM or x.operands[0].imm not in callee_starts)
        ]
        is_closed_callee=not callee_external_jumps and not callee_calls
        unsupported=sum(x.mnemonic not in EASY for x in ins+callee)
        complexity=unsupported*50+len(ins)+len(callee)+len(rest)*8+callee_calls*20+callee_branches*8+len(callee_external_jumps)*200
        pairs.append({
          "caller_rva":hex(b),"caller_end":hex(unwinds[b]),"callee_rva":hex(target),
          "callee_end":hex(unwinds[target]),
          "caller_instructions":len(ins),"callee_instructions":len(callee),
          "unsupported_mnemonics":unsupported,"branch_count":len(rest),
          "callee_calls":callee_calls,"callee_branches":callee_branches,
          "callee_external_jump_targets":callee_external_jumps,
          "callee_closed_no_nested_calls":is_closed_callee,
          "score":complexity,
          "caller_disasm":[f"{x.address:#x}: {x.mnemonic} {x.op_str}" for x in ins],
          "callee_disasm":[f"{x.address:#x}: {x.mnemonic} {x.op_str}" for x in callee]
        })
    pairs.sort(key=lambda x:(not x["callee_closed_no_nested_calls"],x["score"],x["caller_instructions"]+x["callee_instructions"]))
    return {"original_unwind_intervals_bounded":len(unwinds),
            "decoded_full_ret_intervals":len(decoded),
            "bounded_single_direct_call_to_unwind_callee_pairs":len(pairs),
            "callee_with_closed_control_flow_no_nested_calls":sum(p["callee_closed_no_nested_calls"] for p in pairs),
            "callee_external_branches":sum(bool(p["callee_external_jump_targets"]) for p in pairs),
            "promising_pairs":pairs[:12],
            "all_pair_metadata":[{
                k:v for k,v in pair.items() if k not in ("caller_disasm","callee_disasm")
            } for pair in pairs],
            "caution":"PE unwind boundaries are not sufficient alone to prove callable source-level function boundaries; verify incoming prologues and differential behavior."}

def main():
    if len(sys.argv)!=3:raise SystemExit("usage: python mxbikes_native_call_pairs.py EXE REPORT_DIR")
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    result=scan(Path(sys.argv[1]))
    (out/"original-call-pairs.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# Original MX Bikes small linked-call candidate survey","",
        f"- Bounded unwind intervals: {result['original_unwind_intervals_bounded']}",
        f"- Fully decoded intervals ending in RET: {result['decoded_full_ret_intervals']}",
        f"- One-direct-call caller / independent short callee pairs: {result['bounded_single_direct_call_to_unwind_callee_pairs']}",
        f"- Callees with internally closed CFG and no nested calls: {result['callee_with_closed_control_flow_no_nested_calls']}",
        f"- Callees with branches leaving their unwind interval: {result['callee_external_branches']}",
        ""]
    for case in result["promising_pairs"][:8]:
        lines.extend([
            f"## Caller {case['caller_rva']} ({case['caller_instructions']} instructions) -> callee {case['callee_rva']} ({case['callee_instructions']} instructions)",
            f"- Unsupported mnemonic count: {case['unsupported_mnemonics']}",
            f"- Caller control-flow branches: {case['branch_count']}",
            f"- Callee nested calls and branches: {case['callee_calls']} / {case['callee_branches']}",
            f"- Callee branches outside its unwind interval: {case['callee_external_jump_targets']}",
            "### Caller"
        ])
        lines += ["- "+x for x in case["caller_disasm"]]
        lines += ["### Callee"]
        lines += ["- "+x for x in case["callee_disasm"]]
    lines += ["","This is a static candidate survey; no original interfunction ARM64 execution or native iOS boot is proven.",""]
    summary="\n".join(lines)
    (out/"original-call-pairs.md").write_text(summary)
    print(summary)

if __name__=="__main__":main()
