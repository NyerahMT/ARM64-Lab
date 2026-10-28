#!/usr/bin/env python3
"""First grouped native game-main POST-parser progression: Win32 import boundary.

Extends the entire verified command-line scanner, including the 12 actually
returning cases, through original main RVA 0x136746->0x136756
and the explicitly host-modeled GetModuleFileNameA import -> RVA 0x13675C.
This is a native AArch64 executable guest-state proof, not Windows itself:
the executable path is a deterministic supplied test value, not a real
Windows API call, game engine, graphics initialization or an iOS IPA.
"""
from pathlib import Path
import json,sys
import mxbikes_main_callee_tail_native as tail
import mxbikes_main_filename_native as filename
import mxbikes_main_joined_callee_native as joined

ROOT=Path(__file__).resolve().parents[1]
EXPECTED_RETURNED_CASES=12
PATH=filename.PATH

def append_postreturn(pe,source,cases):
    filename.verify_next_import(pe)
    returned=sum(1 for _,record,_,status in cases
                 if status=="returned" and record["rip"]==joined.BASE+joined.AFTER_CALL)
    if returned!=EXPECTED_RETURNED_CASES:
        raise ValueError("Original parser genuine returns changed; refusing to fake post-CALL coverage")
    include='#include "mx_native_guest_linker.h"'
    if source.count(include)!=1:
        raise ValueError("Original guest native linker includes moved")
    source=source.replace(include,include+'\n#include "mx_game_module_filename.h"')
    anchor=" unsigned taken=0,fallthrough=0;"
    if source.count(anchor)!=1:
        raise ValueError("Original test loop entry moved")
    source=source.replace(anchor,anchor+'\n unsigned genuine_module_filename_calls=0U;')
    inject="   if(current_branch.branch_taken)taken++;else fallthrough++;"
    if source.count(inject)!=1:
        raise ValueError("Original native main/callee smoke insertion point missing")
    # Original x64 instructions and IAT identity are verified against the
    # original executable by filename.verify_next_import. The WinAPI response
    # is explicitly modeled using a known safe path supplied by the test.
    path_nums=", ".join(str(n)+"U" for n in PATH)
    next_stage=f"""
   if(result==MX_NATIVE_LINK_OK && s.rip==AFTER_CALL){{
      static const uint8_t supplied_path[]={{ {path_nums} }};
      mx_game_module_context supplied={{supplied_path,
          (uint32_t)sizeof(supplied_path)}};
      const uint64_t expected_rsp=s.rsp;
      const uint64_t expected_rbx=s.rbx;
      const uint64_t expected_rsi=s.rsi;
      const uint64_t expected_rdi=s.rdi;
      const uint64_t expected_guest_ret=UINT64_C({joined.BASE+filename.AFTER_IMPORT});
      if(mx_game_main_filename_prepare(&s,AFTER_CALL,
          UINT64_C({joined.BASE+filename.CALL_IMPORT}))!=MX_GAME_FILENAME_OK)
         return 180;
      if(s.rip!=UINT64_C({joined.BASE+filename.CALL_IMPORT})||
         s.rcx!=0U||s.r8!=0x104U||s.rdx!=s.rsp+0x140U)
         return 181;
      if(mx_game_main_filename_import_call(&s,&mem,&supplied,
          UINT64_C({joined.BASE+filename.CALL_IMPORT}),
          expected_guest_ret)!=MX_GAME_FILENAME_OK)
         return 182;
      if(s.rip!=expected_guest_ret||s.rsp!=expected_rsp||
         s.rax!=sizeof(supplied_path)||s.imports!=1U||
         s.rbx!=expected_rbx||s.rsi!=expected_rsi||s.rdi!=expected_rdi)
         return 183;
      for(unsigned path_byte=0U;path_byte<sizeof(supplied_path);path_byte++){{
         uint8_t actual_path_byte=0U;
         if(!mx_cfg_transfer(&mem,s.rdx+path_byte,&actual_path_byte,1U,0)||
            actual_path_byte!=supplied_path[path_byte])
            return 184;
      }}
      uint8_t terminator=255U;
      if(!mx_cfg_transfer(&mem,
          s.rdx+sizeof(supplied_path),&terminator,1U,0)||
          terminator!=0U)return 185;
      const uint64_t native_ret=read_guest(&mem,expected_rsp-8U,8U);
      if(native_ret!=expected_guest_ret)return 186;
      genuine_module_filename_calls++;
   }}
"""
    source=source.replace(inject,next_stage+inject)
    gate=" /* Unknown functions cannot fabricate a successful frontier. */"
    if source.count(gate)!=1:
        raise ValueError("Original native unknown-call safety gate missing")
    source=source.replace(gate,
        " if(genuine_module_filename_calls!="+str(EXPECTED_RETURNED_CASES)+"U)return 187;\n"+gate)
    return source

def run(executable,out,*,native_extension=None):
    # Verify independent original x64 executed GetModuleFileNameA call
    # (deterministically modeled) before extending cumulative ARM64 scenario.
    from mxbikes_main_filename_native import original_main_with_module_name
    from mxbikes_main_callee_native_branch import INPUT
    from tools.pe_probe import PE
    from mxbikes_main_joined_callee_native import inspect_original
    pe=PE(executable)
    slot=filename.verify_next_import(pe)
    layout,_,_=inspect_original(pe)
    originals=[i for i,v in enumerate(INPUT) if v==0]
    if not originals:
        raise ValueError("Original zero-byte import test fixture missing")
    for i in originals:
        observed=original_main_with_module_name(pe,layout,slot,i)
        if(observed["rip"]!=joined.BASE+filename.AFTER_IMPORT or
           observed["buffer"]!=list(PATH+bytes((0,)))):
            raise ValueError("Independent original x64 modeled WinAPI differential changed")
    def combined_extension(pe,source,cases):
        source=append_postreturn(pe,source,cases)
        return native_extension(pe,source,cases) if native_extension is not None else source
    outcome=tail.run(executable,out,native_extension=combined_extension)
    if outcome["original_parser_returned_to_main"]!=EXPECTED_RETURNED_CASES:
        raise ValueError("No longer exactly 12 original callee returns")
    report={
       "source_sha256":outcome["original_sha256"],
       "native_aarch64_parser_and_post_main_service_join_verified":True,
       "verified_original_x64_main_import_opcode_and_slot":True,
       "original_x64_executed_modeled_import_zero_byte_cases":len(originals),
       "native_aarch64_postreturn_modeled_import_cases":EXPECTED_RETURNED_CASES,
       "native_guest_after_import_original_rva":hex(filename.AFTER_IMPORT),
       "win32_getmodulefilenamea_modeled_not_real":True,
       "native_engine_initialized":False,
       "actual_win32_runtime_or_ios_game_boot":False
    }
    (out/"joined-main-postimport-native.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# MX Bikes native joined game-main: first Windows import boundary","",
      "- Cumulative game-main/callee original x64 vs native ARM64: **16/16**",
      "- Native AArch64 joined post-CALL GetModuleFileNameA modeled calls: **12**",
      "- Original source x64 import identity and IAT verified: **YES**",
      "- Original x64 isolated modeled WinAPI responses: **"+str(len(originals))+"**",
      "- Verified bounded guest continuation: **RVA "+hex(filename.AFTER_IMPORT)+"**",
      "",
      "This is a deterministic supplied import response. It is NOT an",
      "actual Win32 kernel call, renderer, game menu, or iOS launch.",""]
    (out/"joined-main-postimport-native.md").write_text("\n".join(lines))
    print("\n".join(lines))
    return report

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: main_postreturn_native.py owned.exe metadata-dir")
    run(Path(sys.argv[1]),Path(sys.argv[2]))
