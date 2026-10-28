#!/usr/bin/env python3
"""Map the ORIGINAL outer game's initializer return-chain without Steam stubs.

Recover all possible *static* paths through the two nested return sites:
- original 0x133F03 CALL -> 0x130580, would return at 0x133F08
- original 0x13677F CALL -> 0x133E80, would return at 0x136784

The SHA-verified native game stops at SteamAPI_RestartAppIfNecessary in
the innermost function, and these returns have NOT occurred in the native
runtime. A caller CFG and its direct descendants can still be inventoried
without forging Steam results or declaring an engine frame successful.
"""
from __future__ import annotations
import hashlib,json,sys
from pathlib import Path

from mxbikes_main_postinit_dependency_wave import map_main_return
from mxbikes_first_callee_emu import import_slots
from mxbikes_whole_game_map import INPUT_SHA

BASE=0x140000000
PARENT_CALL=0x133f03
PARENT_RETURN=0x133f08
PARENT_TARGET=0x130580
MAIN_CALL=0x13677f
MAIN_RETURN=0x136784
MAIN_TARGET=0x133e80
MAX_STAGE_FUNCTIONS=128

def explore(pe, imports, *, base=BASE, stages=None):
    if stages is None:
        stages=(
            ("original_initializer_parent",PARENT_CALL,PARENT_RETURN,PARENT_TARGET),
            ("original_game_main",MAIN_CALL,MAIN_RETURN,MAIN_TARGET),
        )
    if not isinstance(stages,(list,tuple)) or not 1<=len(stages)<=4:
        raise ValueError("Invalid original nested return stage list")
    stage_reports={}
    candidates={}
    seen_names=set()
    for name,call,ret,target in stages:
        if not isinstance(name,str) or not name or name in seen_names:
            raise ValueError("Duplicate or missing return-stage label")
        seen_names.add(name)
        report=map_main_return(pe,imports,base=base,call_rva=call,
                               return_rva=ret,init_target=target)
        if report["scan_budget_truncated"]:
            raise ValueError("Original caller analysis exceeded a bounded scan limit")
        stage_reports[name]=report
        for item in report["original_callee_dependency_audit"]:
            k=item["target_rva"]
            if k not in candidates:
                candidates[k]={"rva":k,
                               "first_observed_static_from":name,
                               "original_report":item}
                if len(candidates)>MAX_STAGE_FUNCTIONS:
                    raise ValueError("Too many original return-chain callees")
    ranked=[]
    for item in candidates.values():
        inner=item["original_report"]
        status=inner["status"]
        if inner.get("steam_import_thunk",False):
            group="external_Steamworks_import_thunk"
            rank=99
        elif inner.get("import_library") and inner["import_library"].lower()=="msvcr90.dll":
            group="external_CRT_import_thunk"
            rank=90
        elif status=="fully_decoded_original_unwind_not_executed":
            if inner["steam_imports"]:
                group="original_callee_with_Steamworks_dependency"
                rank=70
            elif not inner["unknown_indirect_calls"]:
                group="first_tier_game_native_translation_candidate"
                rank=10
            else:
                group="game_callee_with_indirect_call_blockers"
                rank=25
        elif status=="original_unwindless_bounded_prefix_not_executed":
            group="unwindless_original_candidate_needs_CFG_verification"
            rank=40
        else:
            group="unresolved_original_function_boundary"
            rank=80
        ranked.append({"original_rva":item["rva"],
                       "source_stage":item["first_observed_static_from"],
                       "candidate_group":group,
                       "priority":rank,
                       "verified_original_function_return":False,
                       "native_arm64_translated_by_this_pass":False,
                       "engine_identity_confirmed":False,
                       "first_control_rva":inner.get("first_control_rva"),
                       "status":status,
                       "original_call_count":inner.get("original_callsite_count"),
                       "direct_child_rvas":inner.get("direct_original_callees",[]),
                       "unresolved_indirect_calls":inner.get("unknown_indirect_calls"),
                       "direct_Steamworks_imports":inner.get("steam_imports",[]),
                       "other_direct_imports":inner.get("other_named_imports",[]),
                       "possible_import_library":inner.get("import_library"),
                       "possible_import_symbol":inner.get("import_symbol")})
    ranked.sort(key=lambda x:(x["priority"],int(x["original_rva"],16)))
    return {
        "schema":1,
        "source":"SHA-pinned original x64 nested Win64 return addresses",
        "two_game_return_stages":stage_reports,
        "ranked_unique_original_callees":ranked,
        "unique_direct_original_callee_targets":len(ranked),
        "best_game_candidate_rvas":[x["original_rva"] for x in ranked
                                    if x["priority"]<=25],
        "all_caller_return_paths_are_hypothetical":True,
        "original_native_runtime_currently_stops_at_steam":True,
        "native_steamworks_result_forged":False,
        "original_initializer_returned_in_native_runtime":False,
        "original_engine_started_on_arm64":False,
        "ios_loading_screen_rendered":False,
    }

def run(original_exe, output_dir):
    from tools.pe_probe import PE
    original_exe=Path(original_exe)
    output_dir=Path(output_dir)
    pe=PE(original_exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Owned MX Bikes executable hash changed")
    steam=json.loads((output_dir/"original-post-steam-static-successors.json").read_text())
    outer=json.loads((output_dir/"game-main-postinit-dependency-wave.json").read_text())
    native=json.loads((output_dir/"fused-native-entry-to-steam.json").read_text())
    if (not steam.get("original_exe_sha_verified") or
        not steam.get("prior_native_steam_stop_verified") or
        outer.get("original_initializer_call_rva")!=hex(MAIN_CALL) or
        outer.get("hypothetical_original_main_return_rva")!=hex(MAIN_RETURN) or
        outer.get("original_sha_verified") is not True or
        native.get("original_sha_verified") is not True or
        native.get("native_steam_api_executed") is not False or
        native.get("game_engine_booted") is not False):
        raise ValueError("Prior original-game and actual native boundary evidence invalid")
    report=explore(pe,import_slots(pe))
    report["original_owned_exe_sha_verified"]=True
    report["same_run_original_and_arm64_boundary_verified"]=True
    output_dir.mkdir(parents=True,exist_ok=True)
    (output_dir/"game-nested-return-batch.json").write_text(
        json.dumps(report,indent=2)+"\n")
    lines=[
        "# Original MX Bikes nested caller return-chain dependency batch",
        "",
        "- Original executable SHA-pinned: **PASS**",
        "- Real native ARM64 original startup to Steam import: **PASS**",
        "- Actual original Steam client/auth invoked: **NO**",
        "- Hypothetical original return stages scanned: **"+str(len(report["two_game_return_stages"]))+"**",
        "- Unique original direct callee candidates: **"+str(report["unique_direct_original_callee_targets"])+"**",
        "- First-tier bounded native candidate RVAs: **"+
          (", ".join(report["best_game_candidate_rvas"]) or "none")+"**",
        "- Actual post-Steam original engine code executed: **NO**",
        "",
        "## Caller return-stage static inventory"]
    for name,stage in report["two_game_return_stages"].items():
        lines+=["### "+name,
                "- Original CALL RVA: "+stage["original_initializer_call_rva"],
                "- Original target RVA: "+stage["original_initializer_target_rva"],
                "- Hypothetical RETURN RVA: "+stage["hypothetical_original_main_return_rva"],
                "- Static possible instruction sites: "+str(stage["possible_main_instruction_sites"]),
                "- Possible CALL sites: "+str(stage["possible_main_calls"])]
        for c in stage["original_main_callsite_inventory"]:
            label=c.get("library","")+"!"+c.get("symbol","")
            lines.append("- "+c["site_rva"]+" "+c["kind"]+" "+
                         (c.get("target_rva") or label))
        lines.append("")
    lines.append("## Ranked first-tier non-Steam code targets (NOT native execution)")
    for x in report["ranked_unique_original_callees"][:48]:
        lines.append("- "+x["original_rva"]+" — "+x["candidate_group"]+
                     (" | direct calls "+str(x["original_call_count"])
                      if x["original_call_count"] is not None else "")+
                     (" | first control "+x["first_control_rva"]
                      if x["first_control_rva"] else ""))
    lines+=["","The current native run stops at the *authentic* first Steam import,",
            "and neither nested CALL has returned there. Static code after the",
            "possible return PCs is not proven to execute in the game.",
            "No Steam result, game engine, native rendered screen or IPA is claimed.",""]
    (output_dir/"game-nested-return-batch.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: nested_returns.py original_owned.exe output_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
