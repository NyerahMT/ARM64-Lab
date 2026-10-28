#!/usr/bin/env python3
"""Recover the original Steam startup imported-CALL site from x64 trace.

The original purchased executable remains on the ephemeral private runner.
Only bounded function/callsite/Win64 import metadata is emitted. This never
simulates a Steam success, crosses the unsupported import or executes engine
code in native ARM64.
"""
from pathlib import Path
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.pe_import_handoff import find_handoff
from mxbikes_first_callee_emu import import_slots, EXE_SHA


def run(executable,trace_path,out):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=EXE_SHA:
        raise RuntimeError("Unexpected original MX Bikes revision")
    trace=json.loads(trace_path.read_text())
    if (trace.get("stop_reason")!="unsupported_external_api" or
        trace.get("unimplemented_import")!="steam_api64.dll::SteamAPI_Init" or
        trace.get("native_arm64_executed") is not False):
        raise RuntimeError("No verified original x64 Steam init boundary")
    text=trace.get("unsupported_import_stack_return_rva")
    if not isinstance(text,str) or not text.startswith("0x"):
        raise RuntimeError("Missing original guest stack continuation RVA")
    return_rva=int(text,16)
    imports={rva:dll.lower()+"::"+name for rva,dll,name in import_slots(pe)}
    record=find_handoff(pe,return_rva,imports)
    if record["import"]["symbol"]!="steam_api64.dll::SteamAPI_Init":
        raise RuntimeError("Original stack return does not follow SteamAPI_Init")
    out.mkdir(parents=True,exist_ok=True)
    (out/"engine-steam-callsite.json").write_text(
        json.dumps(record,indent=2)+"\n")
    summary=[
        "# MX Bikes — static original Steam startup handoff", "",
        "- Original blocked imported CALL RVA: **"+
        record["original_import_call_site_rva"]+"**",
        "- Import: **"+record["import"]["symbol"]+"**",
        "- Guest continuation RVA (NOT executed): **"+
        record["guest_return_rva"]+"**",
        "- Unwind-backed caller function: **"+
        record["unwind_caller_rva"]+"**",
        "- Bounded instructions in that function: **"+
        str(record["bounded_function_instructions"])+"**",
        "- Static imported calls in enclosing function: **"+
        str(sum(x["sites"] for x in record["function_static_import_calls"]))+"**",
        "- Immediate continuation contains a conditional branch: **"+
        str(record["nearby_next_12_has_conditional_branch"])+"**",
        "- Return-value zero/nonzero branch is structurally verified: **"+
        str(record["post_import_accumulator_zero_branch"] is not None)+"**",
        "- Import result zero continuation (NOT executed): **"+
        str((record["post_import_accumulator_zero_branch"] or {}).get(
            "zero_result_continuation_rva", "unclassified"))+"**",
        "- Import result nonzero continuation (NOT executed): **"+
        str((record["post_import_accumulator_zero_branch"] or {}).get(
            "nonzero_result_continuation_rva", "unclassified"))+"**", "",
        "## Other static imported dependencies in the enclosing function", ""
    ]
    for item in record["function_static_import_calls"][:30]:
        summary.append("- "+item["name"]+": "+str(item["sites"])+" static callsites")
    summary.extend([
        "", "**The Steam API was not executed successfully. The continuation",
        "is a static candidate; no subsequent original engine instruction,",
        "graphics frame, native ARM64 gameplay or iOS app has been verified.**",""
    ])
    md="\n".join(summary)
    (out/"engine-steam-callsite.md").write_text(md)
    print(md)


if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: script.py private-game.exe private-crt-frontier.json report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
