#!/usr/bin/env python3
"""Trace authentic original code after fclose to first unsupported Steam import.

This is a fail-closed Win64 x64 discovery test: the owned game is emulated
against read-only CRT file services. No original Windows DLL is executed.
The first Steam dependency is observed at the actual imported entry point,
with original Win64 stack return and argument register metadata.
"""
import hashlib,json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from unicorn import UC_HOOK_CODE,UcError
from unicorn.x86_const import (
 UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX,
 UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)
import mxbikes_main_joined_callee_native as joined
import mxbikes_original_postseek_native as original_state
import mxbikes_steam_fopen_result_probe as bootstrap
from mxbikes_startup_batch_runner import (
   install_import_dispatch,symbol_is_supported,STUBS,STUB_BYTES
)
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE
from mxbikes_whole_game_map import INPUT_SHA

BASE=joined.BASE
POST_CLOSE=0x1306b8
STATIC_STOP=0x130748
MAX_STEPS=15000000

def run(exe,dll,out):
    from tools.pe_probe import PE
    pe=PE(exe)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned executable identity changed")
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if manifest.get("matching_owned_dll_count")!=1:
        raise ValueError("Missing unique privately-owned original Steam DLL")
    blob=OwnedReadOnlyFile.from_private_path(dll,manifest["owned_dll_size_bytes"]).content
    _,uc=bootstrap.original_case(pe,0,FILE_HANDLE,0x1305c0,0x1305b6,return_cpu=True)
    imports=install_import_dispatch(uc,pe)
    file=OwnedReadOnlyFile(blob)
    crt=ReadOnlyCRT(file)
    close_reached=[]
    at_steam=[]
    static=Cs(CS_ARCH_X86,CS_MODE_64)
    orig_ins=list(static.disasm(pe.read_rva(POST_CLOSE,STATIC_STOP-POST_CLOSE),POST_CLOSE))
    program=[{"rva":hex(i.address),"mnemonic":i.mnemonic,"operands":i.op_str}
            for i in orig_ins]
    post_trace=[]
    stop={"status":None,"import":None,"rva":None,"return_va":None,
          "rcx":None,"rdx":None,"r8":None,"r9":None}
    def on_service(u,pc,size,ctx):
        lib,symbol=imports[pc]
        if not symbol_is_supported(lib,symbol):
            stack=u.reg_read(UC_X86_REG_RSP)
            try:return_pc=int.from_bytes(u.mem_read(stack,8),"little")
            except Exception:return_pc=None
            stop.update(status="first_unsupported_external_import",
                        **{"import":lib+"!"+symbol,
                           "rva":hex(pc),"return_va":hex(return_pc) if return_pc else None,
                           "rcx":hex(u.reg_read(UC_X86_REG_RCX)),
                           "rdx":hex(u.reg_read(UC_X86_REG_RDX)),
                           "r8":hex(u.reg_read(UC_X86_REG_R8)),
                           "r9":hex(u.reg_read(UC_X86_REG_R9))})
            u.emu_stop();return
        retval=crt.dispatch(u,symbol,u.reg_read(UC_X86_REG_RCX),
                 u.reg_read(UC_X86_REG_RDX),
                 u.reg_read(UC_X86_REG_R8),
                 u.reg_read(UC_X86_REG_R9))
        u.reg_write(UC_X86_REG_RAX,retval&0xffffffffffffffff)
    def after_close(u,pc,size,ctx):
        if pc==BASE+POST_CLOSE:close_reached.append(pc)
        if pc==BASE+0x1306ed:at_steam.append(original_state.register_snapshot(u))
        if close_reached and len(post_trace)<200:
            post_trace.append(hex(pc-BASE))
    uc.hook_add(UC_HOOK_CODE,on_service,
                begin=STUBS,end=STUBS+STUB_BYTES-1)
    uc.hook_add(UC_HOOK_CODE,after_close,
                begin=BASE+POST_CLOSE,end=BASE+STATIC_STOP-1)
    try:
        uc.emu_start(BASE+0x1305c0,0,timeout=15000000,count=MAX_STEPS)
    except UcError as exc:
        raise RuntimeError("Original Win64 after-close trace fault: "+str(exc)) from exc
    if (not close_reached or len(at_steam)!=1 or
        stop["status"]!="first_unsupported_external_import" or
        stop["import"]!="steam_api64.dll!SteamAPI_RestartAppIfNecessary"):
        raise ValueError("Original first Steam boundary moved "+str(stop))
    if (crt.calls!={"fseek":2,"ftell":1,"fread":251,"fclose":1} or
        file.open or crt.bytes_returned!=len(blob)):
        raise ValueError("Original read-only file services incomplete")
    result={
      "original_sha_verified":True,
      "original_postclose_frontier_rva":hex(POST_CLOSE),
      "original_postclose_instruction_forms":program,
      "original_executed_postclose_prefix_rvas":post_trace,
      "original_crt_calls":crt.calls,
      "authentic_original_before_steam_call_guest_registers":at_steam[0],
      "actual_owned_bytes_read":crt.bytes_returned,
      "original_first_unsupported_external_call":stop,
      "post_close_reached_before_steam_call":True,
      "steam_client_initialized":False,
      "native_steam_module_available":False,
      "native_arm64_postclose_translation_complete":False
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"original-postclose-steam-boundary.json").write_text(json.dumps(result,indent=2)+"\n")
    lines=["# MX Bikes — original game after DLL-close dependency map","",
      "- Original x64 file close returned at **0x1306B8**",
      "- Entire original owned file was processed and closed: **YES**",
      "- First unsupported imported service: **"+str(stop["import"])+"**",
      "- Original import caller return: **"+str(stop["return_va"])+"**",
      "- Explicit fail-closed behavior; no Steam result invented","",
      "## Original x64 postclose disassembly"]
    lines.extend("- "+i["rva"]+": "+i["mnemonic"]+" "+i["operands"] for i in program)
    lines.extend(["","## Observed postclose branch PCs"])
    lines.extend("- "+x for x in post_trace)
    lines.extend(["","This maps the next real dependency, not native ARM64 execution.",""])
    (out/"original-postclose-steam-boundary.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return result
if __name__=="__main__":
    if len(sys.argv)!=4:raise SystemExit("usage: map_steam.py exe dll reports")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
