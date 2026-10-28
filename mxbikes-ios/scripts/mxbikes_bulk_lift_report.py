#!/usr/bin/env python3
"""Summarize private Remill batch lift outcomes WITHOUT publishing game code."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import sys

def summarize(private_dir,report_dir):
    manifest=json.loads((private_dir/"pilot-private.json").read_text())
    candidates=[]
    for item in manifest["pilot"]:
        key=item["key"]
        lift=(private_dir/(key+".lift-status")).read_text().strip()
        compile_status=(private_dir/(key+".compile-status")).read_text().strip()
        ir=private_dir/(key+".ll")
        basic=private_dir/(key+".basic.ll")
        whole_equals_basic=(hashlib.sha256(ir.read_bytes()).digest()==
                            hashlib.sha256(basic.read_bytes()).digest()
                            if ir.is_file() and basic.is_file() else None)
        missing=("__remill_missing_block" in ir.read_text(errors="replace")
                 if ir.is_file() else None)
        candidates.append({
            "rva":item["rva"],"group":item["group"],
            "source_x64_instructions":item["instructions"],
            "source_bytes":item["bytes"],
            "llvm_ir":lift,"arm64_object":compile_status,
            "full_ir_equal_to_first_block":whole_equals_basic,
            "mentions_missing_block":missing,
            "arm64_executed":False,
            "runtime_linkage_verified":False,
        })
    total=len(candidates)
    ir_count=sum(x["llvm_ir"]=="ok" for x in candidates)
    obj_count=sum(x["arm64_object"]=="pass" for x in candidates)
    suspect=sum(x["full_ir_equal_to_first_block"] is True for x in candidates)
    counts=dict(Counter(x["arm64_object"] for x in candidates))
    report={
        "game_executable_verified":True,
        "original_unwind_intervals":manifest["whole_executable_unwind_count"],
        "decoded_original_unwind_intervals":manifest["whole_executable_decoded_count"],
        "sample_count":total,
        "llvm_ir_success":ir_count,
        "aarch64_objects_compiled":obj_count,
        "full_ir_equals_first_basic_block":suspect,
        "object_status_distribution":counts,
        "pilot_functions":candidates,
        "native_arm64_functions_executed_in_this_job":0,
        "full_game_recompiled":False,
        "complete_cfg_semantics_proven":False,
        "limitations":[
          "Remill lifting of independent bytes can produce IR for a single trace only.",
          "Compilation does not demonstrate working imports, indirect calls, ABI or full CFG.",
          "Original game execution, iOS support, graphics and engine boot are not tested.",
          "No original bytes, IR, object code or source-derived code leave private job."
        ]
    }
    report_dir.mkdir(parents=True,exist_ok=True)
    (report_dir/"bulk-lift-pilot.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=[
      "# MX Bikes automatic whole-map batch lift pilot","",
      f"- Original PE unwind intervals mapped: **{report['original_unwind_intervals']:,}**",
      f"- Original intervals completely decoded: **{report['decoded_original_unwind_intervals']:,}**",
      f"- Distinct sampled functions: **{total}**",
      f"- Remill-produced LLVM IR modules: **{ir_count}/{total}**",
      f"- Compiled ARM64 objects: **{obj_count}/{total}**",
      f"- Full-body IR identical to first-block IR: **{suspect}**",
      "",
      "## Sampled groups",
    ]
    for group,count in sorted(Counter(x["group"] for x in candidates).items()):
        lines.append(f"- {group.replace('_',' ')}: {count}")
    lines += ["","## Object compilation statuses"]
    for label,count in sorted(counts.items()):
        lines.append(f"- {label}: {count}")
    lines += ["","## Full-body and runtime caveat","",
              "**An LLVM module or AArch64 object is only a compiler output. "
              "It is not proof that the full function was recovered, linked, "
              "or executed; a function may lift only the initial basic block.**",
              "No gameplay, iOS, renderer or engine was executed in this pilot.",""]
    md="\n".join(lines)
    (report_dir/"bulk-lift-pilot.md").write_text(md)
    print(md)
    if not ir_count or not obj_count:
        raise RuntimeError("Batch lift produced no usable IR or ARM64 objects")
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py PRIVATE_INPUT_DIR OUTPUT_METADATA_DIR")
    summarize(Path(sys.argv[1]),Path(sys.argv[2]))
