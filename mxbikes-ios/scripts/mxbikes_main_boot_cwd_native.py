#!/usr/bin/env python3
"""Boot-first grouped authentic filename scanner, helper RET and modeled CWD.

From the pinned original Win64 main -> parser -> GetModuleFileNameA ->
helper CALL -> CRT strcpy -> first three separator/loop iterations,
execute the ENTIRE remaining 314-instruction original x64 filename scan
in existing AArch64 guest state, finish guest directory bytes, execute
original helper stack epilogue/RET to game main, and model the verified
KERNEL32!SetCurrentDirectoryA call to next original main RVA 0x136772.
No actual Windows DLL or filesystem operation; no game engine/IPA boot.
"""
import json,sys
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_CALL
from capstone.x86 import X86_OP_MEM
import mxbikes_main_boot_filename_loop_native as previous
import mxbikes_main_joined_callee_native as joined
import mxbikes_main_filename_native as filename
import mxbikes_msvcr90_strcpy_native as crt
import mxbikes_after_strcpy_branch_native as branch
import mxbikes_joined_strcpy_native as samples
from mxbikes_first_callee_emu import import_slots
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RAX,UC_X86_REG_RCX

BASE=joined.BASE
COUNT=previous.COUNT
SCAN=0x15b7f5
FINISH=0x15b809
EXIT=0x15b862
RETURN=0x136769
CWD_CALL=0x13676c
AFTER_CWD=0x136772
DIR=filename.PATH[:11]

def verify_cwd_original(pe):
    decoder=Cs(CS_ARCH_X86,CS_MODE_64);decoder.detail=True
    decoded=list(decoder.disasm(pe.read_rva(RETURN,AFTER_CWD-RETURN),RETURN))
    forms=[("mov","rcx, rax"),("call","qword ptr [rip + 0x1ea95e]")]
    if(len(decoded)!=2 or [(x.mnemonic,x.op_str) for x in decoded]!=forms or
       decoded[1].address!=CWD_CALL or not decoded[1].group(CS_GRP_CALL)):
        raise ValueError("Original game main SetCurrentDirectoryA instruction identity changed")
    ins=decoded[1]
    if(ins.operands[0].type!=X86_OP_MEM or
       ins.reg_name(ins.operands[0].mem.base)!="rip" or
       ins.operands[0].mem.index):
        raise ValueError("Original Win64 filesystem import is not RIP-relative")
    iat=ins.address+ins.size+ins.operands[0].mem.disp
    imports={(int(slot),str(dll).lower(),str(name).lower())
             for slot,dll,name in import_slots(pe)}
    if (iat,"kernel32.dll","setcurrentdirectorya") not in imports:
        raise ValueError("Original SetCurrentDirectoryA IAT name drifted")
    return iat

def original_directory_import_reference(pe,dest,iat):
    # Bounded isolated original x64 main instructions and a controlled
    # Windows API response; the production Windows DLL is never called.
    from mxbikes_joined_strcpy_native import STACK_MAIN_RSP
    uc=joined.new_cpu(pe)
    mock=0x730040000
    uc.mem_map(mock,4096)
    uc.mem_write(mock,bytes((0xc3,)))
    uc.mem_write(BASE+iat,mock.to_bytes(8,"little"))
    uc.mem_write(dest,DIR+bytes((0,)))
    uc.reg_write(UC_X86_REG_RIP,BASE+RETURN)
    uc.reg_write(UC_X86_REG_RSP,STACK_MAIN_RSP)
    uc.reg_write(UC_X86_REG_RAX,dest)
    calls=[]
    def service(u,pc,size,context):
        if pc!=mock:return
        if (u.reg_read(UC_X86_REG_RCX)!=dest or
            bytes(u.mem_read(dest,len(DIR)+1))!=DIR+bytes((0,))):
            raise ValueError("Original guest SetCurrentDirectoryA arguments changed")
        calls.append(pc)
        u.reg_write(UC_X86_REG_RAX,1)
    uc.hook_add(UC_HOOK_CODE,service)
    uc.emu_start(BASE+RETURN,BASE+AFTER_CWD,timeout=1000000,count=5)
    if(uc.reg_read(UC_X86_REG_RIP)!=BASE+AFTER_CWD or
       uc.reg_read(UC_X86_REG_RSP)!=STACK_MAIN_RSP or
       uc.reg_read(UC_X86_REG_RAX)!=1 or len(calls)!=1):
        raise ValueError("Original x64 modeled CWD CALL/RET diverged")
    return True

def append_cwd(pe,source,cases):
    verify_cwd_original(pe)
    if sum(status=="returned" and r["rip"]==BASE+joined.AFTER_CALL
           for _,r,_,status in cases)!=COUNT:
        raise ValueError("Real original parser returns no longer cover CWD")
    _,dest=crt.original_thunk(pe)
    if DIR!=bytes((67,58,92,77,88,66,105,107,101,115,92)):
        raise ValueError("Original tested DOS directory path changed")
    include='#include "mx_game_filename_loop_iteration.h"'
    if source.count(include)!=1:
        raise ValueError("Native original filename prefix/loop stage missing")
    source=source.replace(include,include+
      '\n#include "mx_game_filename_scan.h"'+
      '\n#include "mx_game_filename_separator_finish.h"'+
      '\n#include "mx_game_filename_helper_return.h"'+
      '\n#include "mx_game_virtual_current_directory.h"')
    layout=f"""
static const mx_game_filename_scan_layout full_filename_scan={{
    {{UINT64_C({BASE+0x15b7c1}),UINT64_C({BASE+0x15b801}),UINT64_C({BASE+0x15b7db})}},
    {{UINT64_C({BASE+0x15b7db}),UINT64_C({BASE+0x15b801}),
       UINT64_C({BASE+0x15b7f5}),UINT64_C({BASE+0x15b7e8}),
       UINT64_C({BASE+0x15b81b}),UINT64_C({BASE+FINISH})}},
    {{UINT64_C({BASE+0x15b7e8}),UINT64_C({BASE+0x15b7f5}),
       UINT64_C({BASE+0x15b7c1})}},
    UINT64_C({BASE+SCAN}),UINT64_C({BASE+0x15b7c1}),
    UINT64_C({BASE+FINISH}),UINT64_C({BASE+0x15b81b}),260U
}};
static const mx_game_filename_finish_layout full_filename_finish={{
    UINT64_C({BASE+FINISH}),UINT64_C({dest}),
    UINT64_C({BASE+EXIT}),260U
}};
static int allow_original_virtual_directory(void*unused,const uint8_t*name,
                                             uint32_t len){{
    (void)unused;
    static const uint8_t allowed[]={{ {",".join(str(c)+"U" for c in DIR)} }};
    if(!name||len!=sizeof(allowed))return 0;
    for(uint32_t i=0U;i<len;i++)if(name[i]!=allowed[i])return 0;
    return 1;
}}
"""
    anchor="static int main_to_callee(mx_crt_cluster_state*s,mx_cfg_memory*m,"
    if source.count(anchor)!=1:raise ValueError("Native helper call entry shifted")
    source=source.replace(anchor,layout+anchor)
    marker=" unsigned genuine_path_separator_frontiers=0U;"
    if source.count(marker)!=1:raise ValueError("Three-character scan counter missing")
    source=source.replace(marker,marker+"\n unsigned genuine_directory_returns=0U;")
    hook="      genuine_path_separator_frontiers++;"
    if source.count(hook)!=1:raise ValueError("Original separator backedge point missing")
    more=f"""
      /* Original 0x15b7f5 block records initial backslash, then scans
       * real original filename to its NUL; no boundless host strlen. */
      const unsigned before_full_scan=s.instructions;
      mx_game_filename_scan_result walked={{0}};
      if(mx_game_filename_scan_to_nul(&s,&mem,&full_filename_scan,
           &walked)!=MX_GAME_FILENAME_SCAN_REACHED)
          return 214;
      if(s.rip!=UINT64_C({BASE+FINISH})||
         walked.terminator!=UINT64_C({dest})+sizeof(supplied_path)||
         walked.last_separator!=UINT64_C({dest})+10U||
         walked.separator_records!=2U||
         walked.loop_iterations!=sizeof(supplied_path)-2U||
         s.instructions!=before_full_scan+314U)
          return 215;
      const unsigned before_finish=s.instructions;
      if(mx_game_filename_finish_separator(&s,&mem,
             &full_filename_finish)!=MX_GAME_FILENAME_FINISH_REACHED||
         s.rip!=UINT64_C({BASE+EXIT})||
         s.rax!=UINT64_C({dest})||
         s.instructions!=before_finish+4U||
         read_guest(&mem,UINT64_C({dest})+11U,1U)!=0U)
          return 216;
      const unsigned before_return=s.instructions;
      mx_game_filename_helper_return_layout real_return={{
         UINT64_C({BASE+EXIT}),UINT64_C({BASE+RETURN}),
         original_caller_rsp,0x38U
      }};
      if(mx_game_filename_helper_return(&s,&mem,&real_return)!=
         MX_GAME_HELPER_EPILOGUE_RETURNED||
         s.rip!=UINT64_C({BASE+RETURN})||
         s.rsp!=original_caller_rsp||
         s.rax!=UINT64_C({dest})||
         s.instructions!=before_return+2U)
          return 217;
      mx_game_cwd_context cwd={{0}};
      cwd.validate=allow_original_virtual_directory;
      const unsigned before_cwd=s.instructions;
      if(mx_game_setcwd_prepare(&s,UINT64_C({BASE+RETURN}),
           UINT64_C({BASE+CWD_CALL}))!=MX_GAME_CWD_OK||
         s.rcx!=UINT64_C({dest}))
          return 218;
      if(mx_game_setcwd_import_call(&s,&mem,&cwd,
           UINT64_C({BASE+CWD_CALL}),UINT64_C({BASE+AFTER_CWD}),
           260U)!=MX_GAME_CWD_OK||
         s.rax!=1U||s.imports!=3U||cwd.calls!=1U||
         cwd.length!=11U||s.rsp!=original_caller_rsp||
         s.rip!=UINT64_C({BASE+AFTER_CWD})||
         s.instructions!=before_cwd+3U)
          return 219;
      for(unsigned n=0;n<11U;n++)
          if(cwd.virtual_path[n]!=supplied_path[n])return 220;
      genuine_directory_returns++;
"""
    source=source.replace(hook,hook+"\n"+more)
    final=" if(genuine_path_separator_frontiers!=12U)return 213;"
    if source.count(final)!=1:raise ValueError("Original three-byte baseline safety gate shifted")
    source=source.replace(final,final+
          "\n if(genuine_directory_returns!=12U)return 221;")
    return source

def run(executable,out,*,native_extension=None):
    from tools.pe_probe import PE
    pe=PE(executable)
    _,dest=crt.original_thunk(pe)
    cwd_iat=verify_cwd_original(pe)
    first=filename.verify_next_import(pe)
    second,_=crt.original_thunk(pe)
    authentic=branch.original_branch(pe,first,second,dest,
        samples.CASES[0],filename.PATH[0],
        follow_successor=True,follow_slash_loop=True,
        follow_loop_iteration=True,follow_second_loopback=True,
        follow_third_backslash=True,follow_to_nul=True,
        follow_separator_finalize=True,follow_helper_return=True)
    if(authentic["rip"]!=BASE+RETURN or
       authentic["scan_instructions"]!=314 or
       not authentic["helper_return_was_executed"] or
       not authentic["original_directory_NUL_after_last_sep"]):
        raise ValueError("Independent original x64 complete filename helper fails")
    original_directory_import_reference(pe,dest,cwd_iat)
    def combined_extension(pe,source,cases):
        source=append_cwd(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    results=previous.run(executable,out,native_extension=combined_extension)
    if results["cumulative_three_filename_characters_native_arm64"]!=COUNT:
        raise ValueError("Previously verified scanner lost coverage")
    outcome={
        "original_sha256":results["original_SHA256"],
        "full_original_filename_helper_win64_native_ret_cases":COUNT,
        "native_virtual_setcurrentdirectory_import_cases":COUNT,
        "original_x64_entire_filename_helper_reference":True,
        "original_x64_setcwd_mock_reference":True,
        "actual_native_main_next_rva":hex(AFTER_CWD),
        "original_windows_dlls_and_filesystem_executed":False,
        "game_engine_or_menu_booted":False,
        "ios_ipa_available":False}
    (out/"joined-native-boot-directory.json").write_text(json.dumps(outcome,indent=2)+"\n")
    lines=["# MX Bikes native startup: complete filename scan, Win64 helper RET and CWD","",
       "- Original command-line parser ARM64: **16/16**",
       "- Complete original filename helper returned into game main: **12/12**",
       "- Modeled SetCurrentDirectoryA calls returned: **12/12**",
       "- Full original x64 filename helper and CWD references: **PASS**",
       "- New original game-main startup frontier: **"+hex(AFTER_CWD)+"**",
       "",
       "Directory changes use a bounded virtual Windows-path validator.",
       "No native Windows DLLs, game engine, menu or iOS IPA executed.",""]
    (out/"joined-native-boot-directory.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return outcome

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: startup-cwd.py original.exe output")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
