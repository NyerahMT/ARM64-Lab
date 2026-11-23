#!/usr/bin/env python3
"""High-throughput bounded ORIGINAL x64 game execution with real owned file bytes.

Uses Unicorn translated-BLOCK hooks instead of per-instruction Python tracing;
service interception is CODE-hooked ONLY inside verified IAT trampolines.
Runs ordinary original game code without manual CALLEE-by-CALLEE stops.
All external DLL calls unimplemented by the read-only CRT adapter fail closed.

The resulting block-count instruction estimate is NOT a native ARM64 port,
not a Steam client, not an authenticated game launch, and not a true CPU
instruction counter if the run ends part-way through the final block.
"""
import hashlib,json,struct
from collections import Counter
from pathlib import Path
from unicorn import UC_HOOK_BLOCK,UC_HOOK_CODE,UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RSP,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
)
from capstone import Cs,CS_ARCH_X86,CS_MODE_64

import mxbikes_main_joined_callee_native as joined
import mxbikes_steam_fopen_result_probe as bootstrap
from mxbikes_owned_file_crt import (
    GuestServiceBlocked,OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE
)
from mxbikes_startup_batch_runner import (
    install_import_dispatch,unwind_index,owner_rva,symbol_is_supported,
    STUBS,STUB_BYTES
)
from mxbikes_whole_game_map import INPUT_SHA
from mxbikes_first_callee_emu import import_slots

BASE=joined.BASE
MAX_BLOCKS=1500000
MAX_INSTRUCTIONS=15000000
MAX_USEC=25000000


def verified_import_return(pe, return_va, library, symbol, original_slots):
    """Prove imported Win64 CALL from exact original source; never infer from a stub.

    Returns original CALLsite RVA or None. Only the original 6-byte
    RIP-relative IAT CALL form is certified; other call forms stay unknown.
    """
    if not isinstance(return_va, int) or return_va < BASE + 6:
        return None
    call_rva = return_va - BASE - 6
    try:
        code = bytes(pe.read_rva(call_rva, 6))
    except (ValueError, struct.error, OverflowError):
        return None
    if len(code) != 6 or code[:2] != bytes((0xff,0x15)):
        return None
    slot = call_rva + 6 + struct.unpack_from("<i", code, 2)[0]
    if original_slots.get(slot) != (library.lower(), symbol):
        return None
    return hex(call_rva)


def execute(executable,dll,out,*,graphics_handler=None,steam_failure_probe=False,
            steam_init_success_probe=False):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original privately owned game binary SHA mismatch")
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if (manifest.get("steam_api64_dll_present") is not True or
        manifest.get("matching_owned_dll_count")!=1):
        raise ValueError("Private source has no uniquely named owned Steam DLL")
    file=OwnedReadOnlyFile.from_private_path(dll,manifest.get("owned_dll_size_bytes"))
    # Real game code through startup and authenticated original import thunk
    # to its genuine fopen success branch (no Steam execution).
    _,uc=bootstrap.original_case(
        pe,0,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    imports=install_import_dispatch(uc,pe)
    original_slots={rva:(lib.lower(),name) for rva,lib,name in import_slots(pe)}
    if steam_failure_probe and steam_init_success_probe:
        raise ValueError("Choose exactly one Steam diagnostic scenario")
    steam_failure = None
    if steam_failure_probe or steam_init_success_probe:
        from mxbikes_steam_failure_path import SteamFailureProbe
        steam_failure = SteamFailureProbe(pe,
            init_success_branch_probe=steam_init_success_probe)
    starts,ends=unwind_index(pe)
    crt=ReadOnlyCRT(file)
    decoded={}
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    counters=Counter()
    functions=set()
    seen=set()
    first=[]
    post_failure_blocks=[]
    original_blocks=0
    emulated_instructions=0
    import_call_count=0
    actual_original_gl_import_events=0
    blocker={"status":None,"import":None,"reason":None}
    image_hi=BASE+max(rva+max(vsz,raw) for _,vsz,rva,raw,_,_ in pe.sections)
    def stop(u,status_name,**extra):
        if blocker["status"] is None:
            blocker.update(status=status_name,**extra)
        u.emu_stop()

    def on_block(u,pc,size,ctx):
        nonlocal original_blocks,emulated_instructions
        if blocker["status"] is not None:return
        if pc in imports:
            return
        if not BASE<=pc<image_hi:
            stop(u,"guest_executed_outside_original_image")
            return
        rva=pc-BASE
        if size<=0 or size>4096 or pc+size>image_hi:
            stop(u,"invalid_translated_block_size")
            return
        original_blocks+=1
        counters[rva]+=1
        seen.add(rva)
        if steam_failure is not None and steam_failure.events and len(post_failure_blocks)<64:
            post_failure_blocks.append(hex(rva))
        owner=owner_rva(starts,ends,rva)
        if owner is not None:functions.add(owner)
        if len(first)<64:first.append(hex(rva))
        key=(rva,size)
        count=decoded.get(key)
        if count is None:
            from capstone import Cs
            try:
                guest_bytes=pe.read_rva(rva,size)
                instructions=list(md.disasm(guest_bytes,rva))
                count=len(instructions) if sum(ins.size for ins in instructions)==size else 0
            except Exception:
                count=0
            if not count:
                stop(u,"unverifiable_original_x64_block")
                return
            decoded[key]=count
        emulated_instructions+=count
        if original_blocks>=MAX_BLOCKS:
            stop(u,"original_basic_block_budget")

    def on_import(u,pc,size,ctx):
        nonlocal import_call_count,actual_original_gl_import_events
        if blocker["status"] is not None:return
        reference=imports.get(pc)
        if reference is None:
            stop(u,"non_import_executable_trampoline")
            return
        import_call_count+=1
        lib,symbol=reference
        if steam_failure is not None and lib.lower()=="steam_api64.dll":
            from mxbikes_steam_failure_path import SteamFailureProbeRejected
            try:
                if steam_failure.handle(u,lib,symbol):
                    return
            except SteamFailureProbeRejected as exc:
                stop(u,"steam_failure_probe_rejected",**{"import":lib+"!"+symbol,
                                                     "reason":str(exc)})
                return
        if lib.lower()=="opengl32.dll":
            actual_original_gl_import_events+=1
            if graphics_handler is not None:
                try:
                    if graphics_handler(u,lib,symbol):
                        return
                except Exception as exc:
                    stop(u,"real_original_GL_handoff_rejected",
                         **{"import":lib+"!"+symbol,
                            "reason":type(exc).__name__})
                    return
        if not symbol_is_supported(lib,symbol):
            try:
                return_va=struct.unpack("<Q",bytes(u.mem_read(u.reg_read(UC_X86_REG_RSP),8)))[0]
            except Exception:
                return_va=None
            exact_site=verified_import_return(pe,return_va,lib,symbol,original_slots)
            stop(u,"unsupported_import",**{"import":lib+"!"+symbol,
                      "reason":"unsupported_service",
                      "verified_original_iat_call_rva":exact_site,
                      "guest_stack_return_rva": (hex(return_va-BASE)
                             if return_va is not None and BASE<=return_va<image_hi else None)})
            return
        try:
            result=crt.dispatch(u,symbol,
                u.reg_read(UC_X86_REG_RCX),u.reg_read(UC_X86_REG_RDX),
                u.reg_read(UC_X86_REG_R8),u.reg_read(UC_X86_REG_R9))
        except GuestServiceBlocked as exc:
            stop(u,"blocked_guest_crt_call",**{"import":lib+"!"+symbol,
                                           "reason":str(exc)})
            return
        u.reg_write(UC_X86_REG_RAX,result&0xffffffffffffffff)

    uc.hook_add(UC_HOOK_BLOCK,on_block)
    uc.hook_add(UC_HOOK_CODE,on_import,begin=STUBS,end=STUBS+STUB_BYTES-1)
    start=uc.reg_read(UC_X86_REG_RIP)
    if start!=BASE+0x1305c0:
        raise ValueError("Authenticated original x64 fopen path moved")
    try:
        uc.emu_start(start,0,timeout=MAX_USEC,count=MAX_INSTRUCTIONS)
    except UcError as exc:
        if blocker["status"] is None:
            blocker.update(status="x64_guest_execution_fault",reason=type(exc).__name__)
    if blocker["status"] is None:
        blocker["status"]="bounded_unstopped_guest_run"
        blocker["reason"]="instruction_count_or_timeout_limit"
    current_pc=uc.reg_read(UC_X86_REG_RIP)
    stop_rva=hex(current_pc-BASE) if BASE<=current_pc<image_hi else None
    top=[]
    for rva,hits in counters.most_common(12):
        best=[(key,cnt) for key,cnt in decoded.items() if key[0]==rva]
        representative_size=best[0][0][1] if best else 0
        top.append({"rva":hex(rva),"executed_block_hits":hits,
                    "decoded_instructions_in_block":decoded.get((rva,representative_size),0)})
    result={
        "original_pe_sha_verified":True,
        "actual_owned_file_bytes":len(file.content),
        "read_only_guest_bytes_returned":crt.bytes_returned,
        "original_guest_basic_block_executions":original_blocks,
        "distinct_original_guest_basic_block_entries":len(seen),
        "distinct_original_unwind_functions":len(functions),
        "estimated_original_instructions_in_completed_blocks":emulated_instructions,
        "count_estimate_not_proof_of_unique_code":True,
        "total_guest_import_calls":import_call_count,
        "actual_original_gl_import_events":actual_original_gl_import_events,
        "original_GL_calls_from_synthetic_fixture":0,
        "supported_crt_calls":dict(crt.calls),
        "guest_file_final_cursor":file.cursor,
        "guest_file_closed":not file.open,
        "first_original_block_rvas":first,
        "hot_original_basic_blocks":top,
        "last_original_rva":stop_rva,
        "stop":blocker,
        "actual_native_arm64_executed_by_this_runner":False,
        "actual_ios_steam_client_initialized":False,
        "original_game_engine_booted":False,
        "steam_failure_probe_enabled":bool(steam_failure_probe),
        "steam_init_success_probe_enabled":bool(steam_init_success_probe),
        "original_post_failure_block_rvas":post_failure_blocks,
        "authentic_post_failure_original_blocks_observed":len(post_failure_blocks)>0,
        "steam_failure_probe":steam_failure.summary() if steam_failure else None,
    }
    out.mkdir(parents=True,exist_ok=True)
    report_name = ("startup-steam-failure-blocks" if steam_failure_probe else
                   "startup-steam-init-success-probe" if steam_init_success_probe else
                   "startup-fast-blocks")
    (out/(report_name+".json")).write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — fast multi-block original game execution","",
       "- Original guest translated BASIC BLOCK executions: **"+str(original_blocks)+"**",
       "- Distinct original guest block entry RVAs: **"+str(len(seen))+"**",
       "- Distinct original unwind functions: **"+str(len(functions))+"**",
       "- Estimated original x64 instructions in completed blocks: **"+
          str(emulated_instructions)+"**",
       "- Actual privately owned steam_api64.dll bytes read: **"+
          str(crt.bytes_returned)+" of "+str(len(file.content))+"**",
       "- Real original x64 import calls handled: **"+str(import_call_count)+"**",
       "- Actual game-produced GL imported calls: **"+str(actual_original_gl_import_events)+"**",
       "- Supported service calls: **"+str(dict(crt.calls))+"**",
       "- Experimental Steam response calls: **"+str(len(steam_failure.events))+"**" if steam_failure is not None else "- Steam response probe: disabled",
       "- Original blocks after probe call observed: **"+str(len(post_failure_blocks))+"**",
       "- Stop: **"+str(blocker["status"])+"**"+
          (", import "+str(blocker["import"]) if blocker.get("import") else "")+
          (", reason "+str(blocker["reason"]) if blocker.get("reason") else ""),
       "","## Hot blocks (not unique code progress)"]
    lines.extend("- "+x["rva"]+": "+str(x["executed_block_hits"])+
                 " runs, "+str(x["decoded_instructions_in_block"])+" original instructions/block"
                 for x in top)
    lines.extend(["",
       "This is batched original x64 guest execution for dependency discovery, not ARM64 translation.",
       "No Windows Steam DLL executed, authentication granted, original game renderer, or iOS IPA.",""])
    summary="\n".join(lines)
    (out/(report_name+".md")).write_text(summary)
    print(summary)
    return result


if __name__=="__main__":
    import sys
    if len(sys.argv)!=4:
        raise SystemExit("usage: startup_fast_blocks.py original.exe owned-steam-dll metadata-dir")
    execute(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
