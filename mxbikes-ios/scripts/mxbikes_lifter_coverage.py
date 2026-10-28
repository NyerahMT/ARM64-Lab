#!/usr/bin/env python3
"""Private strict-lifter compatibility survey of actual MX Bikes unwind intervals.

Only use real unwind ranges, exact disassembly, terminal returns, no branches
or calls. The public SSE lifter is allowed to reject every candidate.
Exports aggregate counts and RVAs but NEVER code bytes or lifted C.
"""
from collections import Counter
import json
from pathlib import Path
import struct
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"arm64-lab"))
from tools.pe_probe import PE
from tools.x64_sse_lift import lift, UnsupportedInstruction
SHA="4ae7de3854b4d0a18271679fb57a1f2fdf0b21804417b85dd82055078ea123b6"


def survey(exe):
    pe=PE(exe)
    if pe.inventory()["sha256"]!=SHA:raise RuntimeError("Unrecognized executable")
    p,size=pe.directory(3)
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    md.detail=True
    candidates=[]
    rejects=Counter()
    processed=set()
    for b,e,u in struct.iter_unpack("<III",pe.read_rva(p,size)):
        if b==0 or e<=b or e-b>256 or (b,e) in processed:
            rejects["range_invalid_or_too_large"]+=1
            continue
        processed.add((b,e))
        try:
            code=pe.read_rva(b,e-b)
            ins=list(md.disasm(code,b))
        except Exception:
            rejects["unreadable"]+=1;continue
        if not ins or sum(i.size for i in ins)!=len(code):
            rejects["undecodable"]+=1;continue
        if not ins[-1].group(CS_GRP_RET) or any(i.group(CS_GRP_JUMP) or i.group(CS_GRP_CALL) for i in ins):
            rejects["has_branch_call_or_no_terminal_ret"]+=1;continue
        try:
            generated,count=lift(code,b)
        except (UnsupportedInstruction,IndexError,ValueError) as exc:
            rejects["lifter_rejected"]+=1
            continue
        candidates.append({"begin_rva":hex(b),"end_rva":hex(e),"bytes":e-b,
                           "instructions":count,"mnemonics":[i.mnemonic for i in ins]})
    candidates.sort(key=lambda x:(-x["instructions"],x["begin_rva"]))
    return {"original_sha256":SHA,"unwind_candidates_evaluated":len(processed),
            "strict_full_function_lifter_accepts":len(candidates),
            "accepted_candidates":candidates[:50],
            "rejections":dict(rejects),
            "interpretation":"Static supported-instruction candidates only, not differential semantic tests or guaranteed whole functions."}


def main():
    if len(sys.argv)!=3:raise SystemExit("usage: python script.py original.exe report_dir")
    result=survey(Path(sys.argv[1]))
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    (out/"lifter-coverage.json").write_text(json.dumps(result,indent=2)+"\n")
    summary=["# Original MX Bikes x64 strict full-function survey","",
             f"- Unwind intervals inspected (bounded): {result['unwind_candidates_evaluated']}",
             f"- Directly accepted by current SSE lifter: **{result['strict_full_function_lifter_accepts']}**",
             "", "## Accepted intervals", ""]
    summary += [f"- {r['begin_rva']} ({r['instructions']} instructions, {r['bytes']} bytes): {','.join(r['mnemonics'])}"
                for r in result["accepted_candidates"][:15]]
    summary += ["", "Only static compatibility; differential x64 vs ARM64 checks are still required.",""]
    content="\n".join(summary)
    (out/"lifter-coverage.md").write_text(content)
    print(content)

if __name__=="__main__":main()
