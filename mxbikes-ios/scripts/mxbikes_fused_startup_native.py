#!/usr/bin/env python3
"""FUSE the original Win64 startup prefix and entire checksum startup on AArch64.

Extend the existing validated native game entry / parser / initializer / cookie
/ fopen / fseek-prep C program IN PLACE; do not recreate or seed new guest
CPU state at the join. The same mx_crt_cluster_state and the same 128k guest
stack continue through 251 original Win64 fread/CRC branches, fclose, CRC
comparison and STOP at the real SteamAPI_RestartAppIfNecessary CALL.

The SHA-verified original x64 executable (with allowlisted bounded CRT)
independently supplies exact final CPU/guest stack oracle for the SAME
parser fixture. No Steam API result, license, engine or iOS result is faked.
"""
import hashlib,json,sys
from pathlib import Path
from unicorn import UC_HOOK_CODE,UcError
from unicorn.x86_const import (UC_X86_REG_RAX,UC_X86_REG_RCX,
                                UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,
                                UC_X86_REG_RIP,UC_X86_REG_RSP)
import mxbikes_steam_fopen_status_native as steam
import mxbikes_steam_fopen_result_probe as fopen
import mxbikes_original_postseek_native as checkpoint
import mxbikes_original_postseek_full_native as full
import mxbikes_crc_native as crc
from mxbikes_startup_batch_runner import (install_import_dispatch,
                                          symbol_is_supported,STUBS,STUB_BYTES)
from mxbikes_owned_file_crt import OwnedReadOnlyFile,ReadOnlyCRT,FILE_HANDLE
from mxbikes_whole_game_map import INPUT_SHA

BASE=steam.BASE
ROOT=Path(__file__).resolve().parents[1]
STEAM_CALL=0x1306ed
NATIVE_SELECTED=1

def original_end_to_end(pe,blob,parser_dword,rbx,rsi,rdi):
    """Independent real original Win64 parser -> Steam CALL entry oracle."""
    _,u=fopen.original_case(pe,parser_dword,FILE_HANDLE,steam.OPEN,
               steam.MISSING,return_cpu=True,rbx=rbx,rsi=rsi,rdi=rdi)
    slots=install_import_dispatch(u,pe)
    crt=ReadOnlyCRT(OwnedReadOnlyFile(blob))
    arrived=[]
    def on_crt(cpu,pc,size,ctx):
        lib,name=slots[pc]
        if not symbol_is_supported(lib,name):
            raise ValueError("Original unexpectedly requested unsupported import")
        retval=crt.dispatch(cpu,name,
                    cpu.reg_read(UC_X86_REG_RCX),cpu.reg_read(UC_X86_REG_RDX),
                    cpu.reg_read(UC_X86_REG_R8),cpu.reg_read(UC_X86_REG_R9))
        cpu.reg_write(UC_X86_REG_RAX,retval&0xffffffffffffffff)
    def at_boundary(cpu,pc,size,ctx):
        arrived.append(pc)
        cpu.emu_stop()
    u.hook_add(UC_HOOK_CODE,on_crt,begin=STUBS,end=STUBS+STUB_BYTES-1)
    u.hook_add(UC_HOOK_CODE,at_boundary,
               begin=BASE+STEAM_CALL,end=BASE+STEAM_CALL)
    try:
        u.emu_start(BASE+steam.OPEN,0,timeout=15000000,count=15000000)
    except UcError as exc:
        raise ValueError("Authentic original x64 parser/CRC path fault") from exc
    if arrived!=[BASE+STEAM_CALL]:
        raise ValueError("Original game did not reach Steam first CALL")
    if crt.calls!={"fseek":2,"ftell":1,"fread":251,"fclose":1}:
        raise ValueError("Genuine x64 service sequence changed: "+str(crt.calls))
    if crt.bytes_returned!=len(blob) or crt.file.open:
        raise ValueError("Original file processing incomplete")
    final=checkpoint.register_snapshot(u)
    rsp=final["rsp"]
    final["stack_return_slot"]=int.from_bytes(u.mem_read(rsp-8,8),"little")
    final["stack_saved_rbx"]=int.from_bytes(u.mem_read(rsp+0x440,8),"little")
    final["stack_saved_rsi"]=int.from_bytes(u.mem_read(rsp+0x450,8),"little")
    if final["rcx"]!=0xa008c:
        raise ValueError("Original Steam app ID not as expected")
    return final

def c_number(value):
    return "UINT64_C("+str(int(value))+")"

def inject_native_bridge(pe,source,cases,owned):
    # Original source already includes C code for all earlier game stages.
    source=steam.extend(pe,source,cases)
    indices=[i for i,(_,row,_,kind) in enumerate(cases)
             if kind=="returned" and row["rip"]==BASE+steam.joined.AFTER_CALL]
    if len(indices)!=12:
        raise ValueError("Expected 12 original startup cases that reach fopen")
    # The original x64 reference helper currently covers the TAKEN early
    # child JLE (signed dword <= 1). Other original branches must be
    # separately translated/oracled, not silently inferred as successes.
    eligible=[i for i in indices if
              cases[i][1]["callee_global1"]<=1 or
              cases[i][1]["callee_global1"]>=0x80000000]
    selected_cases=[]
    seen_parser_dwords=set()
    for index in eligible:
        dword=cases[index][1]["callee_global1"]
        if dword not in seen_parser_dwords:
            selected_cases.append(index)
            seen_parser_dwords.add(dword)
        if len(selected_cases)>=3:
            break
    for index in eligible:
        if len(selected_cases)>=3:
            break
        if index not in selected_cases:
            selected_cases.append(index)
    if not selected_cases:
        raise ValueError("No original cases available for supported x64 early JLE oracle")
    targets=[]
    for selected in selected_cases:
        _,row,_,_=cases[selected]
        oracle=original_end_to_end(pe,owned,row["callee_global1"],
                 row["rbx"],row["rsi"],row["rdi"])
        targets.append((selected,oracle))
    inject_native_bridge.last_oracle={
        "case_indices":selected_cases,
        "source_parser_dwords":[cases[n][1]["callee_global1"] for n in selected_cases],
        "original_final_rva":hex(targets[0][1]["rip"]-BASE),
        "original_appid_rcx":hex(targets[0][1]["rcx"]),
        "original_owned_bytes_per_case":len(owned),
        "original_full_crt_calls_per_case":255,
        "original_file_checksums_per_case":251
    }
    header="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(header)!=1:
        raise ValueError("Base C native game guest functions moved")
    static_data=("static const uint8_t original_owned_game_dll["+
       str(len(owned))+"]={"+",".join(str(x) for x in owned)+"};\n")
    source=source.replace(header,static_data+header)
    source='#include "mxbikes_steam_platform_boundary.h"\n#include "mxbikes_original_postseek_native.h"\n'+source
    anchor="         actual_open_status_frontiers++;"
    if source.count(anchor)!=1:
        raise ValueError("Native original fseek prefix join moved")
    blocks=[]
    for selected,oracle in targets:
        regcheck=[
            " if(s."+name+"!="+c_number(oracle[name])+")return 100;"
            for name in ("rip","rsp","rax","rbx","rcx","rdx",
                         "r8","r9","rsi","rdi","r11","zf","sf","cf")
        ]
        regcheck.extend([
            " if(extra."+name+"!="+c_number(oracle[name])+")return 101;"
            for name in ("rbp","r12","r13","r14")
        ])
        regcheck.extend([
           " if(read_guest(&mem,s.rsp-8U,8U)!="+
                 c_number(oracle["stack_return_slot"])+")return 102;",
           " if(read_guest(&mem,s.rsp+0x440U,8U)!="+
                 c_number(oracle["stack_saved_rbx"])+")return 103;",
           " if(read_guest(&mem,s.rsp+0x450U,8U)!="+
                 c_number(oracle["stack_saved_rsi"])+")return 104;",
        ])
        block="""
             /* Original game native first CLI/parser/initializer/fopen case
              * continues WITHOUT a seeded state or second guest stack.
              * Narrow view references region[0] of the same already live stack.
              */
             if(i==__INDEX__U){
                if(s.rip!=MXB_POSTSEEK_CALL)return 80;
                if(s.rax!=MXB_POSTSEEK_HANDLE ||
                   extra.r12!=MXB_POSTSEEK_HANDLE)return 81;
                mx_cfg_region live_stack=regions[0];
                mx_cfg_memory stack_mem={&live_stack,1U};
                mxb_postseek_extra post={0};
                post.rbp=extra.rbp;post.r12=extra.r12;
                post.r13=extra.r13;post.r14=extra.r14;
                mxb_readonly_file owned_file={0};
                if(!mxb_file_init(&owned_file,original_owned_game_dll,
                       sizeof(original_owned_game_dll),0U))return 82;
                if(mxb_postseek_native_first_read(&s,&stack_mem,
                       &owned_file,&post)!=1)return 83;
                if(!mxb_postseek_native_finish_reads(&s,&stack_mem,
                       &owned_file,&post))return 84;
                if(mxb_postseek_native_until_steam(&s,&stack_mem,&post)!=1)
                       return 85;
                extra.rbp=post.rbp;extra.r12=post.r12;
                extra.r13=post.r13;extra.r14=post.r14;
                if(owned_file.total_bytes_read!=
                        sizeof(original_owned_game_dll)||
                   owned_file.read_calls!=251U||owned_file.seek_calls!=2U||
                   owned_file.tell_calls!=1U||owned_file.close_calls!=1U||
                   owned_file.is_open)return 86;
                if(post.original_crt_calls!=255U)return 87;
                if(s.rip!=MXB_POSTSEEK_STEAM_BOUNDARY)return 88;
                const uint64_t steam_pc_before=s.rip;
                const uint64_t steam_rax_before=s.rax;
                const uint64_t steam_arg_before=s.rcx;
                const unsigned steam_imports_before=s.imports;
                /* Preflight the exact original Win64 CALL [IAT] frame
                 * in the existing guest memory, without invoking Steam.
                 */
                mxb_steam_call_contract contract={0};
                if(mxb_steam_capture_call_contract(&s,&stack_mem,
                     MXB_HOST_DESKTOP,&contract)!=
                     MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED)return 95;
                if(contract.guest_call_pc!=MXB_ORIGINAL_STEAM_PC||
                   contract.import_iat_slot!=MXB_ORIGINAL_STEAM_IAT_SLOT||
                   contract.original_return_pc!=MXB_ORIGINAL_STEAM_RETURN_PC||
                   contract.guest_app_id!=MXB_ORIGINAL_STEAM_APP_ID||
                   contract.caller_rsp!=s.rsp||
                   contract.callee_rsp_if_invoked!=s.rsp-8U||
                   read_guest(&mem,contract.callee_rsp_if_invoked,8U)!=
                       contract.prior_callee_stack_bytes)return 96;
                mxb_steam_call_contract ios_contract={0};
                if(mxb_steam_capture_call_contract(&s,&stack_mem,
                     MXB_HOST_IOS,&ios_contract)!=
                     MXB_STEAM_UNSUPPORTED_IOS||
                   ios_contract.callee_rsp_if_invoked!=
                     contract.callee_rsp_if_invoked)return 97;
                if(mxb_steam_platform_boundary(&s,MXB_HOST_IOS)!=
                   MXB_STEAM_UNSUPPORTED_IOS)return 91;
                if(mxb_steam_platform_boundary(&s,MXB_HOST_DESKTOP)!=
                   MXB_STEAM_DESKTOP_CLIENT_NOT_CONNECTED)return 92;
                if(s.rip!=steam_pc_before||s.rax!=steam_rax_before||
                   s.rcx!=steam_arg_before||s.imports!=steam_imports_before)
                    return 93;
                s.rcx^=UINT64_C(1);
                if(mxb_steam_platform_boundary(&s,MXB_HOST_IOS)!=
                     MXB_STEAM_INVALID_GUEST_STATE)return 94;
                s.rcx^=UINT64_C(1);
    __CHECKS__
                fused_entry_to_steam++;
             }
    """.replace("__INDEX__",str(selected)).replace(
        "__CHECKS__","\n".join("            "+line for line in regcheck))
        blocks.append(block)
    source=source.replace(
        " unsigned actual_open_status_frontiers=0U;",
        " unsigned actual_open_status_frontiers=0U;\n unsigned fused_entry_to_steam=0U;")
    source=source.replace(anchor,anchor+"\n"+"\n".join(blocks))
    gate=" if(next_initializer_frontiers!=12U)return 220;"
    # Some generation changes the exact gate constant; use installed
    # actual-open-status assertion to bind strict full-path count.
    import re
    match=re.search(r" if\(actual_open_status_frontiers!=[0-9]+U\)return 175;",source)
    if not match:
        raise ValueError("Base native fopen case-count gate moved")
    marker=match.group(0)
    source=source.replace(marker,marker+
              "\n if(fused_entry_to_steam!="+str(len(selected_cases))+"U)return 89;",1)
    return source

def run(executable,dll,out):
    from tools.pe_probe import PE
    pe=PE(executable)
    if hashlib.sha256(pe.b).hexdigest()!=INPUT_SHA:
        raise ValueError("Original owned exe SHA changed")
    steam.validate(pe)
    crc.original_form(pe)
    manifest=json.loads((out/"owned-steam-file-manifest.json").read_text())
    if (manifest.get("steam_api64_dll_present") is not True or
        manifest.get("matching_owned_dll_count")!=1):
        raise ValueError("No uniquely owned Steam DLL to read")
    owned=OwnedReadOnlyFile.from_private_path(
        dll,manifest.get("owned_dll_size_bytes")).content
    if len(owned)!=0x3d320:
        raise ValueError("Authentic game DLL size gate mismatched")
    steam.OWNED_DLL_PRESENT=True
    def extend(pe,source,cases):
        return inject_native_bridge(pe,source,cases,owned)
    import mxbikes_main_callee_tail_native as compiler
    from mxbikes_large_native_executor import execute_arm64_elf as continued_native_execution
    old_executor=compiler.execute_arm64_elf
    compiler.execute_arm64_elf=continued_native_execution
    old_budget=compiler.ARM64_INSTRUCTION_BUDGET
    old_timeout=compiler.ARM64_TIMEOUT_US
    compiler.ARM64_INSTRUCTION_BUDGET=22000000
    compiler.ARM64_TIMEOUT_US=60000000
    try:
        prev=steam.previous.run(executable,out,native_extension=extend)
    finally:
        compiler.execute_arm64_elf=old_executor
        compiler.ARM64_INSTRUCTION_BUDGET=old_budget
        compiler.ARM64_TIMEOUT_US=old_timeout
    details=inject_native_bridge.last_oracle
    report={
      "original_sha_verified":True,
      "cumulative_previous_native_prefix":"main -> parser -> initializer -> cookie -> fopen -> fseek args",
      "native_same_guest_cpu_and_stack_carried_across_join":True,
      "native_original_full_file_control_until_steam":True,
      "one_native_aarch64_elf_run_from_game_prefix_to_steam_boundary":True,
      "native_steam_api_original_call_rva":hex(STEAM_CALL),
      "native_steam_api_executed":False,
      "native_original_file_bytes":len(owned),
      "fused_parser_cases":len(details["case_indices"]),
      "previous_fixture_count":16,
      "original_guest_final_cpu_and_stack_differential":True,
      "game_engine_booted":False,
      "ios_frame_rendered":False,
      "details":details
    }
    out.mkdir(parents=True,exist_ok=True)
    (out/"fused-native-entry-to-steam.json").write_text(json.dumps(report,indent=2)+"\n")
    summary="\n".join([
       "# MX Bikes — ONE native original game startup-to-Steam execution","",
       "- Earlier authentic parser -> initializer -> FILE* prefix: **native executed**",
       "- The SAME live guest CPU/stack continues through all 251 fread/CRC",
       "  iterations, original fclose, and checksum comparison: **native executed**",
       "- Original x64 vs native ARM64 final registers and stack: **PASS**",
       "- Authentic owned Steam DLL bytes processed: **"+str(len(owned))+"**",
       "- Complete main-prefix original x64 fixtures carried through: **"+str(len(details["case_indices"]))+"**",
       "- Native game execution stops at genuine SteamAPI_RestartAppIfNecessary",
       "  original CALL RVA **"+hex(STEAM_CALL)+"**: **REACHED**",
       "","NO Steam API invocation, faked authorization, engine startup or",
       "rendered iOS frame. Later runtime still blocked at Steam integration.",""])
    (out/"fused-native-entry-to-steam.md").write_text(summary)
    print(summary)
    return report

if __name__=="__main__":
    if len(sys.argv)!=4:
        raise SystemExit("usage: fused_native.py private_game.exe owned_dll metadata_dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]))
