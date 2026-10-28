#!/usr/bin/env python3
"""Fully bounded authentic CRT child: original x64 vs generated C/AArch64.

Uses the PUBLIC, tested generic import-cluster lifter with exactly the SHA-
pinned original 176-byte/39-instruction Win64 unwind span. Generated C, input
bytes and the original executable stay in ephemeral PRIVATE CI only.

MSVCR90 calls are deterministic injection callbacks in all three machines,
not actual DLL services. Passing proves those original child semantics and
import ABI effects under tested fixtures, not a completed CRT or game boot.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"arm64-lab"))
sys.path.insert(0,str(ROOT/"arm64-lab"/"tests"))

from tools.pe_probe import PE
from tools.crt_import_cluster_lift import lift_crt_import_cluster
from tools.import_aot_smoke import execute_arm64_elf
from test_crt_import_cluster_lift import HARNESS, encode
from mxbikes_first_callee_emu import import_slots
from mxbikes_crt_exception_callback_differential import SHA, BASE, SP, STOP
from mxbikes_crt_child_path_reference import (
    ENTRY, END, GLOBALS, THUNKS, prepare, original, cases,
)

def fixture(c):
    return {
        "rax":0xbbbb0000, "rbx":0xaaaa0000,
        "rcx":c["rcx"], "rdx":0, "r8":0,
        "rdi":0, "rsi":0, "r11":0, "zf":0,
        "g0":c["global0"], "g1":c["global1"],
        "decode":list(c["decode"]), "encode":list(c["encode"]),
        "onexit":c["onexit"], "dll":c["dll"],
        "update":int(c["update"]),
        "updated0":c["start"], "updated1":c["end"],
    }

def checked(command):
    result=subprocess.run(command,capture_output=True,text=True)
    if result.returncode:
        raise RuntimeError("CRT child native differential command failed ("+
                           str(result.returncode)+"): "+
                           (result.stderr or result.stdout)[-4000:])

def run(executable,report):
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=SHA:
        raise RuntimeError("Original MX Bikes image hash mismatch")
    allowed=prepare(pe)
    imports={rva:(dll,name) for rva,dll,name in import_slots(pe)}
    thunks={rva:pe.read_rva(rva,6) for rva in THUNKS}
    generated,meta=lift_crt_import_cluster(
        pe.read_rva(ENTRY,END-ENTRY), ENTRY,imports,thunks,BASE)
    if (meta["decoded_instructions"]!=39 or
        meta["import_calls"]!=10 or
        meta["unique_import_services"]!=[
            "__dllonexit","_decode_pointer","_encode_pointer",
            "_lock","_onexit","_unlock"]):
        raise RuntimeError("Generated CRT cluster differs from original coverage")
    rows=[]
    visited=set()
    for c in cases():
        ref=original(pe,allowed,c)
        visited.update(ref["instructions_visited"])
        ref["trace"]=ref["calls"]  # Same verified imported service sequence.
        rows.append((fixture(c),ref))
    if len(rows)!=16 or len(visited)!=39:
        raise RuntimeError("Original CRT case matrix does not cover 39 instructions")
    if [ref["path"] for _,ref in rows].count("onexit-early")!=8:
        raise RuntimeError("Original early-registration paths not fully covered")

    # The public synthetic native harness uses ascending contiguous globals.
    # This original PE's two globals are adjacent but in reverse order.
    # Update only generic address macros, NOT guest instruction semantics.
    program=HARNESS.replace("REPLACE_SP",str(SP))
    program=program.replace("REPLACE_WIN",str(SP-128))
    program=program.replace("REPLACE_G0",str(BASE+GLOBALS[0]))
    program=program.replace("REPLACE_ENTRY",str(BASE+ENTRY))
    program=program.replace("REPLACE_STOP",str(STOP))
    program=program.replace(
        "#define ENTRY UINT64_C(",
        "#define BASE_G1 UINT64_C("+str(BASE+GLOBALS[1])+")\n#define ENTRY UINT64_C(")
    program=program.replace("{BASE_G,global_bytes,16}",
                            "{BASE_G1,global_bytes,16}")
    program=program.replace("BASE_G+8U","BASE_G1")
    program=program.replace("REPLACE_CASES",encode(rows))
    if "REPLACE_" in program:
        raise RuntimeError("Native fixture generator retains missing placeholder")

    with tempfile.TemporaryDirectory(prefix="private-crt-child-aot-") as td:
        temporary=Path(td)
        lift_file=temporary/"transient-original-child.c"
        smoke_file=temporary/"transient-original-child-smoke.c"
        lift_file.write_text(generated)
        smoke_file.write_text(program)
        flags=["-O2","-std=c11","-Wall","-Wextra","-Werror",
               "-I"+str(ROOT/"arm64-lab"/"runtime")]
        host=temporary/"host-crt-check"
        checked(["cc",*flags,"-DHOST",str(lift_file),str(smoke_file),
                 "-o",str(host)])
        checked([str(host)])
        arm=temporary/"child.elf"
        checked([
            "clang","--target=aarch64-unknown-linux-gnu",
            "-fuse-ld=lld","-nostdlib","-static","-ffreestanding",
            "-fno-builtin","-fno-stack-protector",
            *flags,"-Wl,-e,smoke","-Wl,-z,max-page-size=4096",
            "-Wl,--build-id=none",
            str(lift_file),str(smoke_file),"-o",str(arm),
        ])
        result=execute_arm64_elf(
            arm,instruction_budget=950000,timeout_us=9000000)
    report.mkdir(parents=True,exist_ok=True)
    metadata={
        "original_child_rva":hex(ENTRY),
        "original_instructions_statically_decoded":39,
        "original_instruction_coverage_with_synthetic_imports":len(visited),
        "original_x64_vs_generated_native_C_vs_executed_AArch64":len(rows),
        "tested_early_paths":8,
        "tested_registration_paths":8,
        "service_symbols":meta["unique_import_services"],
        "service_import_calls_in_original_function":meta["import_calls"],
        "generic_auto_translator_generated_and_compiled":True,
        "imported_msvcr90_calls_are_test_doubles":True,
        "real_msvcr90_dll_executed":False,
        "initializer_callback_table_executed_natively":False,
        "complete_startup_or_engine_booted":False,
        "arm64_smoke_return":result["arm64_smoke_exit"],
    }
    (report/"crt-child-aot-arm64.json").write_text(
        json.dumps(metadata,indent=2)+"\n")
    summary="\n".join([
        "# Real MX Bikes CRT child — full generic AOT ARM64 differential","",
        "- Original source function: **39/39 actual x64 instructions**",
        "- x64 reference vs generated C vs executed ARM64: **16/16 matched**",
        "- Original short/long paths exercised: **8 / 8**",
        "- Real original imported callsites: **10** across six MSVCR90 services",
        "- Register state, all 256 stack bytes, two CRT globals,",
        "  deterministic import order and Win64 call stack ABI compared",
        "- ARM64 ELF returned: **"+str(result["arm64_smoke_exit"])+"**","",
        "**All imported CRT functions are synthetic callbacks on BOTH sides.",
        "This does not implement Windows CRT process lifecycle, Steam, native",
        "engine startup, rendering or iPhone gameplay. Original derived native",
        "C/ELF exists only in the transient PRIVATE Actions runner.**",""
    ])
    (report/"crt-child-aot-arm64.md").write_text(summary)
    print(summary)

if __name__=="__main__":
    if len(sys.argv)!=3:
        raise SystemExit("usage: script.py private-owned-mxbikes.exe report-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
