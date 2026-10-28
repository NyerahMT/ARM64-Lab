#!/usr/bin/env python3
"""Authentic _initterm callback tail JMP -> wrapper CALL -> translated CRT child.

Requires SHA-pinned original callback pointer table at slot 3, verifies
the original 7-byte LEA RCX and 5-byte JMP rel32 instruction pair, then
executes that original x64 two-instruction tail path into the original
eight-instruction wrapper and 39-instruction child, comparing the entire
guest observable result to generated C and executed AArch64.

MSVCR90 imported services are deliberate deterministic test doubles across
all three architectures; real initializer table traversal, CRT lifecycle
and Steam initialization remain unverified. No original code export.
"""
from pathlib import Path
import hashlib
import json
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_initializer_inventory import inventory
from mxbikes_crt_child_path_reference import ENTRY,END,GLOBALS,THUNKS,cases
from mxbikes_crt_child_aot_differential import fixture,checked
from mxbikes_crt_joined_wrapper_child_aot import (
    SHA,BASE,WRAPPER,TAIL_CALLBACK,TAIL_ARGUMENT,
    verify,verify_tail,reference_original,native_harness,
)

def run(executable,output):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original purchased MX Bikes executable SHA changed")
    original_tables=inventory(executable)
    targets=[e for t in original_tables["tables"]
             if t["symbol"]=="msvcr90.dll::_initterm"
             for e in t["entries"]
             if e["slot_index"]==3 and not e["null"]]
    if (len(targets)!=1 or
        targets[0]["target_rva"]!=hex(TAIL_CALLBACK)):
        raise RuntimeError("Original _initterm callback slot 3 no longer targets tail")
    allowed,wrapper_pcs=verify(pe)
    tail_pcs=verify_tail(pe)
    iat={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunks={rva:pe.read_rva(rva,6) for rva in THUNKS}
    generated,meta=lift_crt_import_cluster(
        pe.read_rva(ENTRY,END-ENTRY),ENTRY,iat,thunks,BASE)
    if meta["decoded_instructions"]!=39 or meta["import_calls"]!=10:
        raise RuntimeError("Entire real CRT child did not compile via public lifter")
    rows=[]
    covered_child=set()
    covered_tail=set()
    for c in cases():
        expected=reference_original(pe,c,allowed,wrapper_pcs,tail=True)
        covered_child.update(expected["visited_child"])
        covered_tail.update(expected["visited_tail"])
        rows.append((fixture(c),expected))
    if (len(rows)!=16 or len(covered_child)!=39 or
        covered_tail!={TAIL_CALLBACK,TAIL_CALLBACK+7} or
        sum(len(ref["trace"])==2 for _,ref in rows)!=8):
        raise RuntimeError("Original three-level x64 execution did not cover both paths")
    native=native_harness(rows,tail=True)
    with tempfile.TemporaryDirectory(prefix="private-mxbikes-crt-table-callback-") as td:
        work=Path(td)
        source=work/"private-generated-crt-child.c"
        harness=work/"private-tail-wrapper-harness.c"
        source.write_text(generated)
        harness.write_text(native)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=work/"host"
        checked(["cc",*flags,"-DHOST",str(source),str(harness),
                 "-o",str(host)])
        checked([str(host)])
        arm=work/"joined-arm64.elf"
        checked([
            "clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",*flags,
            "-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",str(source),str(harness),"-o",str(arm)
        ])
        result=execute_arm64_elf(
            arm,instruction_budget=1400000,timeout_us=11000000)
    output.mkdir(parents=True,exist_ok=True)
    record={
        "authentic_table":"msvcr90.dll::_initterm",
        "authentic_slot_index":3,
        "original_callback_tail_rva":hex(TAIL_CALLBACK),
        "original_callback_instructions":2,
        "original_wrapper_rva":hex(WRAPPER),
        "original_wrapper_instructions":8,
        "original_child_rva":hex(ENTRY),
        "original_child_instructions":39,
        "original_union_source_instructions":49,
        "original_x64_vs_native_C_vs_executed_AArch64_fixtures":len(rows),
        "original_child_source_instructions_covered":len(covered_child),
        "both_registration_branches_exercised":True,
        "native_wrapper_invokes_actual_generated_child":True,
        "native_callback_enters_real_nested_wrapper":True,
        "actual_initterm_table_traversed":False,
        "all_msvcr90_services_deterministic_test_doubles":True,
        "all_remaining_initializer_callbacks_executed":False,
        "steam_engine_render_ios_booted":False,
        "arm64_elf_exit":result["arm64_smoke_exit"],
    }
    (output/"crt-joined-tail-callback-arm64.json").write_text(
        json.dumps(record,indent=2)+"\n")
    summary="\n".join([
        "# MX Bikes _initterm callback → wrapper → CRT child joined AArch64","",
        "- Actual _initterm callback slot 3 RVA: **"+hex(TAIL_CALLBACK)+"**",
        "- Original 2-instruction LEA/JMP + 8-instruction wrapper +",
        "  39-instruction child: **49 original instructions**",
        "- Original x64 vs compiled native C vs executed AArch64:",
        "  **"+str(len(rows))+"/"+str(len(rows))+" matched**",
        "- Both registration paths: **8 short / 8 long**",
        "- All 39 original child instructions collectively covered",
        "- Actual original callback tail-jump target and table-slot identity verified",
        "- Guest stack, registers, CRT globals, imported services and status matched","",
        "**One authentic _initterm callback PATH was tested in isolation;",
        "the complete callback array, real MSVCR90 services and native",
        "engine/Steam/iPhone startup have NOT been executed.**",""
    ])
    (output/"crt-joined-tail-callback-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py private-original-exe metadata-report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
