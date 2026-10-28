#!/usr/bin/env python3
"""Run original MX Bikes code ACROSS many CALLs via one bounded service dispatcher.

A reusable dynamic-reference driver, not an iOS executable or ARM64 translator.
Begin at the verified original post-fopen success path (after the independently
verified original parser -> initializer -> cookie CALL/RET and x64 import thunk).
Patch original Win64 IAT slots to explicit controlled return trampolines.
Implement only genuine read-only CRT stream operations backed by real bytes
of the privately owned steam_api64.dll from its SHA-verified Game.zip.
Every other import fails closed and is reported automatically. The original
x64 game instructions themselves execute without per-function stop hooks.

This automation discovers the NEXT blocking service across many instructions
and functions. It never runs a Windows Steam DLL or fakes Steam/auth status.
Only aggregate metadata is archived; no game assets, PE bytes, input names
or guest-memory bytes are saved.
"""
from __future__ import annotations
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from unicorn import UC_HOOK_CODE, UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RAX,UC_X86_REG_RCX,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
import mxbikes_main_joined_callee_native as joined
import mxbikes_steam_fopen_result_probe as bootstrap
from mxbikes_first_callee_emu import import_slots
from mxbikes_owned_file_crt import (
    GuestServiceBlocked, OwnedReadOnlyFile, ReadOnlyCRT,FILE_HANDLE
)
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
STUBS=0x730060000
STUB_BYTES=0x40000
STUB_STRIDE=16
INSTRUCTION_LIMIT=1500000
GUEST_TIMEOUT_US=15_000_000
TRACE_PREVIEW=48
MAX_IMPORTS=4096
SEED_BUDGETS=((0,100000),(1,20000),(0x80000000,20000))


def unwind_index(pe):
    import struct
    start,length=pe.directory(3)
    if (not start or not length or length%12 or length>8*1024*1024):
        raise ValueError("Invalid original PE unwind table")
    ranges=sorted((a,b) for a,b,_ in struct.iter_unpack("<III",pe.read_rva(start,length))
                  if a and b>a)
    return [r[0] for r in ranges], [r[1] for r in ranges]


def owner_rva(starts,ends,rva):
    i=bisect_right(starts,rva)-1
    return starts[i] if i>=0 and rva<ends[i] else None


def symbol_is_supported(library,symbol):
    return (library.lower() in ("msvcr90.dll","msvcr90d.dll")
            and symbol.lower() in ReadOnlyCRT.SUPPORTED)


def install_import_dispatch(uc,pe):
    slots=import_slots(pe)
    if not 0<len(slots)<=MAX_IMPORTS:
        raise ValueError("Original Win64 IAT slot count outside budget")
    if STUB_STRIDE*len(slots)>STUB_BYTES:
        raise ValueError("Original Win64 IAT trampoline budget exceeded")
    uc.mem_map(STUBS,STUB_BYTES)
    by_pc={}
    for i,(iat_rva,lib,symbol) in enumerate(slots):
        pc=STUBS+STUB_STRIDE*i
        # RET executes only after the supported host-side syscall handler
        # has written the guest x64 RAX return value; unsupported calls stop.
        uc.mem_write(pc,b"\xc3")
        uc.mem_write(BASE+iat_rva,pc.to_bytes(8,"little"))
        by_pc[pc]=(lib,symbol)
    if not any(lib.lower()=="msvcr90.dll" and name.lower()=="fseek"
               for lib,name in by_pc.values()):
        raise ValueError("Original game has no requested CRT fseek IAT entry")
    return by_pc


def run_case(pe,dll_bytes,dword,*,instruction_limit=INSTRUCTION_LIMIT,
             graphics_handler=None):
    if not 100<=instruction_limit<=INSTRUCTION_LIMIT:
        raise ValueError("Instruction budget out of range")
    # The first fopen and its real original x64 conditional are independently
    # validated in bootstrap. The returned FILE* is ONLY a guest handle to
    # bytes from the owned archive; it is never a successful Steam init.
    _,uc=bootstrap.original_case(
        pe,dword,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    stream=OwnedReadOnlyFile(dll_bytes)
    crt=ReadOnlyCRT(stream)
    imports=install_import_dispatch(uc,pe)
    starts,ends=unwind_index(pe)
    visited=set()
    visited_pcs=set()
    hot_pcs=Counter()
    first_rvas=[]
    first_imports=[]
    total=0
    original_count=0
    external_count=0
    stop={"status":None,"import":None,"rva":None,"reason":None}
    image_hi=BASE+max(rva+max(vsz,raw) for _,vsz,rva,raw,_,_ in pe.sections)

    def hook(u,pc,size,ctx):
        nonlocal total,original_count,external_count
        if stop["status"] is not None:
            u.emu_stop()
            return
        total+=1
        if total>instruction_limit:
            stop["status"]="instruction_budget"
            u.emu_stop()
            return
        if pc in imports:
            external_count+=1
            lib,symbol=imports[pc]
            if len(first_imports)<TRACE_PREVIEW:
                first_imports.append(lib+"!"+symbol)
            if lib.lower()=="opengl32.dll" and graphics_handler is not None:
                # Only call for a REAL guest IAT trampoline reached while
                # executing SHA-pinned original x64 executable bytes.
                # The handler must independently prove the guest return PC.
                try:
                    if graphics_handler(u,lib,symbol):
                        return  # original imported void call executes stub RET
                except Exception as exc:
                    stop.update(status="original_graphics_handoff_rejected",
                        **{"import":lib+"!"+symbol,
                           "reason":type(exc).__name__})
                    u.emu_stop()
                    return
            if not symbol_is_supported(lib,symbol):
                stop.update(status="unsupported_import",
                    **{"import":lib+"!"+symbol,"reason":"service_not_implemented"})
                u.emu_stop()
                return
            try:
                result=crt.dispatch(u,symbol,
                   u.reg_read(UC_X86_REG_RCX),
                   u.reg_read(UC_X86_REG_RDX),
                   u.reg_read(UC_X86_REG_R8),
                   u.reg_read(UC_X86_REG_R9))
            except GuestServiceBlocked as exc:
                stop.update(status="blocked_guest_service",
                    **{"import":lib+"!"+symbol,"reason":str(exc)})
                u.emu_stop()
                return
            u.reg_write(UC_X86_REG_RAX,result&0xffffffffffffffff)
            return
        if BASE<=pc<image_hi:
            original_count+=1
            rva=pc-BASE
            visited_pcs.add(rva)
            hot_pcs[rva]+=1
            owner=owner_rva(starts,ends,rva)
            if owner is not None:visited.add(owner)
            if len(first_rvas)<TRACE_PREVIEW:
                first_rvas.append(hex(rva))
            return
        stop.update(status="outside_verified_game_or_services",
                    rva=None,reason="unexpected_execution_address")
        u.emu_stop()

    uc.hook_add(UC_HOOK_CODE,hook)
    starting_pc=uc.reg_read(UC_X86_REG_RIP)
    if starting_pc!=BASE+0x1305c0:
        raise ValueError("Original x64 fopen success bootstrap did not reach target")
    try:
        uc.emu_start(starting_pc,0,timeout=GUEST_TIMEOUT_US,count=instruction_limit)
    except UcError as exc:
        stop["status"]=stop["status"] or "original_guest_emulation_fault"
        stop["reason"]=stop["reason"] or type(exc).__name__
    if stop["status"] is None:
        stop["status"]="instruction_budget_or_guest_stop"
    current=uc.reg_read(UC_X86_REG_RIP)
    stop["rva"]=hex(current-BASE) if BASE<=current<image_hi else None
    return {
      "original_parser_dword":dword,
      "starts_after_real_original_x64_fopen_jne":True,
      "original_x64_instructions_executed":original_count,
      "synthetic_return_stub_instructions":external_count,
      "guest_instruction_total":total,
      "distinct_original_unwind_functions_reached":len(visited),
      "unique_original_instruction_addresses":len(visited_pcs),
      "repeat_execution_ratio":round(original_count/max(1,len(visited_pcs)),2),
      "hot_instruction_rvas":[{"rva":hex(pc),"hits":hits} for pc,hits
                               in hot_pcs.most_common(12)],
      "first_original_rvas":first_rvas,
      "original_import_calls":dict(sorted(crt.calls.items())),
      "first_imports":first_imports,
      "owned_file_read_bytes":crt.bytes_returned,
      "owned_file_cursor":stream.cursor,
      "owned_file_size":len(stream.content),
      "file_handle_open":stream.open,
      "stop":stop,
      "actual_steam_client_initialized":False,
      "native_arm64_original_engine_executed":False,
    }


def run(executable,dll,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned executable SHA changed")
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if (manifest.get("steam_api64_dll_present") is not True or
        manifest.get("matching_owned_dll_count")!=1):
        raise ValueError("No unique authentic Steam DLL in original owned archive")
    stream=OwnedReadOnlyFile.from_private_path(
        dll,manifest.get("owned_dll_size_bytes"))
    result=[run_case(pe,stream.content,dword,instruction_limit=budget)
            for dword,budget in SEED_BUDGETS]
    if len(result)!=len(SEED_BUDGETS):
        raise ValueError("Batch probe did not cover all original guest seed cases")
    out.mkdir(parents=True,exist_ok=True)
    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
    decoder=Cs(CS_ARCH_X86,CS_MODE_64)
    hot_forms=[]
    for rva in [int(x["rva"],16) for x in result[0]["hot_instruction_rvas"]]:
        instruction=list(decoder.disasm(pe.read_rva(rva,15),rva,count=1))
        if instruction and instruction[0].address==rva:
            hot_forms.append({"rva":hex(rva),"mnemonic":instruction[0].mnemonic,
                              "operands":instruction[0].op_str})
    report={
      "sha_pinned_original_verified":True,
      "original_steam_file_size":len(stream.content),
      "representative_hot_instruction_forms":hot_forms,
      "guest_import_service_policy":"allowlisted_read_only_crt; unsupported_fail_closed",
      "total_original_x64_instructions_executed":sum(
          x["original_x64_instructions_executed"] for x in result),
      "max_original_x64_instructions_in_single_path":max(
          x["original_x64_instructions_executed"] for x in result),
      "max_distinct_unwind_functions_in_single_path":max(
          x["distinct_original_unwind_functions_reached"] for x in result),
      "max_unique_original_instruction_addresses":max(
          x["unique_original_instruction_addresses"] for x in result),
      "cases":result,
      "original_game_full_engine_boot":False,
      "ios_original_frame_rendered":False,
      "native_arm64_new_code_executed_by_this_probe":False,
    }
    (out/"startup-batch-runtime.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes — bounded multi-function original startup runner","",
      "- Automatically executes original x64 through multiple functions and known CRT read services",
      "- Guest original instruction total: **"+
         str(report["total_original_x64_instructions_executed"])+"**",
      "- Longest original x64 single path: **"+
         str(report["max_original_x64_instructions_in_single_path"])+" instructions**",
      "- Most original function unwind intervals in one path: **"+
         str(report["max_distinct_unwind_functions_in_single_path"])+"**",
      "- Max UNIQUE original x64 instruction addresses in a path: **"+
         str(report["max_unique_original_instruction_addresses"])+"**",
      "- Read-only authentic steam_api64.dll bytes in private runner: **"+
         str(len(stream.content))+"**",
      "","## All automatic executions"]
    for row in result:
        stop=row["stop"]
        lines.append("- Parser DWORD "+hex(row["original_parser_dword"])+
            ": **"+str(row["original_x64_instructions_executed"])+" executed original instructions**, "+
            str(row["unique_original_instruction_addresses"])+" distinct instruction PCs, "+
            str(row["distinct_original_unwind_functions_reached"])+" unwind functions, "+
            str(row["owned_file_read_bytes"])+" bytes read, stop **"+
            stop["status"]+"**"+
            (", unsupported: "+str(stop["import"]) if stop.get("import") else "")+
            (", cause: "+str(stop["reason"]) if stop.get("reason") else "")+
            "; dominant PCs: "+
            ", ".join(q["rva"]+" x"+str(q["hits"]) for q in row["hot_instruction_rvas"][:5])+
            "; CRT calls: "+str(row["original_import_calls"]))
    lines.extend(["","## Representative original x64 hot loop"])
    lines.extend("- "+item["rva"]+": "+item["mnemonic"]+" "+item["operands"]
                 for item in hot_forms)
    lines.extend(["",
       "This is a reusable original x64 dependency and service runner, not native ARM64 execution.",
       "No Steam DLL instructions/auth, graphics engine, loading screen, or iOS build run.",""])
    summary="\n".join(lines)
    (out/"startup-batch-runtime.md").write_text(summary)
    print(summary)
    return report


if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: startup_batch_runner.py SHA-verified-exe owned-steam-dll metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
