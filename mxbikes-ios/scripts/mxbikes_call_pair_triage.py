#!/usr/bin/env python3
"""Prioritize original MX Bikes interfunction lifting from cached safe metadata.

No proprietary executable or Ghidra needed: consumes the immutable output
of one private offline scan and emits typed obligations for differential proof.
"""
import json
from pathlib import Path
import sys
from collections import Counter

def triage(records):
    pairs=records.get("all_pair_metadata")
    if not isinstance(pairs,list) or len(pairs)!=records.get("bounded_single_direct_call_to_unwind_callee_pairs"):
        raise ValueError("Expected a complete and internally consistent scan")
    if len(pairs)>10000:raise ValueError("Unexpected candidate count")
    fanin=Counter(p["callee_rva"] for p in pairs)
    shortlisted=[]
    for p in pairs:
        if not p.get("callee_closed_no_nested_calls") or p.get("callee_calls"):
            continue
        if p.get("callee_external_jump_targets") or p["caller_instructions"]>60 or p["callee_instructions"]>100:
            continue
        penalty=p["unsupported_mnemonics"]*1000+p["branch_count"]*12+p["callee_branches"]*10
        score=penalty+p["caller_instructions"]+p["callee_instructions"]-min(4,fanin[p["callee_rva"]])*8
        shortlisted.append({
          "caller_rva":p["caller_rva"],"callee_rva":p["callee_rva"],
          "caller_instructions":p["caller_instructions"],
          "callee_instructions":p["callee_instructions"],
          "unwind_candidate_not_verified":True,
          "callee_fanin_in_scan":fanin[p["callee_rva"]],
          "native_linking_research_score":score,
          "required_obligations":[
            "Validate complete function body and prologue against independent Ghidra FunctionManager",
            "Verify closed intra-function CFG and absence of unresolved jump targets",
            "Classify x64 memory reads and writes and initialize guest memory for both paths",
            "Execute actual x64 caller and callee together without intercepting the direct internal call",
            "Lift both original function bodies and execute a genuine linked native ARM64 caller/callee",
            "Compare all changed guest memory, registers, stack and arithmetic flags across randomized inputs",
            "Keep all commercial bytes and generated native object code private",
          ],
        })
    shortlisted.sort(key=lambda x:(x["native_linking_research_score"],-x["callee_fanin_in_scan"],x["caller_rva"]))
    return {
       "input_pair_count":len(pairs),
       "closed_candidate_pairs":len(shortlisted),
       "unique_callee_count":len(set(x["callee_rva"] for x in shortlisted)),
       "top_candidates":shortlisted[:25],
       "verified_original_linked_calls":0,
       "warning":"A static unwind interval candidate, even with internally closed CFG, is not independent proof of a whole callable function."
    }

def main():
    if len(sys.argv)!=3:raise SystemExit("usage: python scripts/mxbikes_call_pair_triage.py call-pairs.json outdir")
    data=json.loads(Path(sys.argv[1]).read_text())
    result=triage(data)
    out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    (out/"call-pair-priorities.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=[
       "# MX Bikes cached-metadata caller/callee prioritization","",
       "- Original executable analysis and PE extraction: **not repeated**",
       f"- Cached static caller/callee leads reviewed: **{result['input_pair_count']}**",
       f"- Closed-callee leads without nested calls: **{result['closed_candidate_pairs']}**",
       f"- Unique callees for deduplicated work: **{result['unique_callee_count']}**","",
       "## Lowest-cost starting points","",
    ]
    for c in result["top_candidates"][:10]:
        lines.append(f"- {c['caller_rva']} -> {c['callee_rva']}: {c['caller_instructions']}+{c['callee_instructions']} instructions, reuse {c['callee_fanin_in_scan']} callers, priority {c['native_linking_research_score']}")
    lines += ["","## Verification prerequisites", ""]
    for obligation in (result["top_candidates"][0]["required_obligations"] if result["top_candidates"] else []):
        lines.append("- "+obligation)
    lines += ["","**Static research priorities, not verified game-code translations or native iOS execution.**",""]
    report="\n".join(lines)
    (out/"call-pair-priorities.md").write_text(report)
    print(report)

if __name__=="__main__":main()
